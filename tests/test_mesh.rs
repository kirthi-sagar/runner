//! Mesh tests: invitation token mint/verify and WireGuard config gen.

use runner::mesh::invite::{
    parse_size_mb, parse_ttl_secs, InviteAuthority, InviteCaps, InviteRole, InviteToken,
};
use runner::mesh::peer::{
    apply_donor_caps, generate_keypair, render_config, DEFAULT_KEEPALIVE_SECS,
};

fn authority() -> InviteAuthority {
    InviteAuthority::new(vec![42u8; 32]).unwrap()
}

#[test]
fn invite_generation_and_parsing() {
    let token = InviteToken {
        role: "donor".parse::<InviteRole>().unwrap(),
        caps: InviteCaps {
            max_cores: 4,
            max_ram_mb: parse_size_mb("8G").unwrap(),
        },
        ttl_secs: parse_ttl_secs("7d").unwrap(),
        name: "alice-desktop".to_string(),
    };
    let minted = authority().mint(&token).unwrap();
    assert!(minted.starts_with("runner1."));
    assert_eq!(minted.split('.').count(), 3);

    let payload = authority().verify(&minted).unwrap();
    assert_eq!(payload.role, InviteRole::Donor);
    assert_eq!(payload.max_cores, 4);
    assert_eq!(payload.max_ram_mb, 8192);
    assert_eq!(payload.name, "alice-desktop");
    assert!(payload.expires_at > payload.issued_at);

    // Offline structural decode (join side) sees the same payload.
    let offline = InviteAuthority::decode_unverified(&minted).unwrap();
    assert_eq!(offline, payload);
}

#[test]
fn invite_rejects_tampering_and_expiry() {
    let token = InviteToken {
        role: InviteRole::Worker,
        caps: InviteCaps {
            max_cores: 2,
            max_ram_mb: 4096,
        },
        ttl_secs: 3600,
        name: "bob".to_string(),
    };
    let minted = authority().mint(&token).unwrap();
    // Tamper with the signature segment.
    let mut parts: Vec<String> = minted.split('.').map(str::to_string).collect();
    parts[2] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    assert!(authority().verify(&parts.join(".")).is_err());
    assert!(InviteAuthority::decode_unverified("runner1.bogus").is_err());
}

#[test]
fn wireguard_config_generation() {
    let local = generate_keypair();
    let peer = generate_keypair();
    let config = render_config(
        &local.private_b64,
        &peer.public_b64,
        &["10.9.0.2/32"],
        Some("203.0.113.7:51820"),
        DEFAULT_KEEPALIVE_SECS,
    );
    assert!(config.contains("[Interface]"));
    assert!(config.contains("[Peer]"));
    assert!(config.contains(&format!("PrivateKey = {}", local.private_b64)));
    assert!(config.contains(&format!("PublicKey = {}", peer.public_b64)));
    assert!(config.contains("AllowedIPs = 10.9.0.2/32"));
    assert!(config.contains("PersistentKeepalive = 25"));
    assert!(config.contains("Endpoint = 203.0.113.7:51820"));
}

#[test]
fn donor_caps_bound_fleet_slots() {
    // 4 donated cores / 8GB RAM cannot serve a 4-slot plan.
    assert_eq!(apply_donor_caps(4, 4, 8192), 2);
    // Generous caps leave the plan untouched.
    assert_eq!(apply_donor_caps(2, 16, 32768), 2);
}
