//! Minimal RFC 5389 STUN client: Binding Request / response only.
//!
//! The mesh needs exactly one STUN feature: reflexive self-discovery
//! (the public `(IP, port)` a NAT maps this socket to). No MESSAGE-
//! INTEGRITY, no authentication, no error handling beyond fail-closed
//! parse errors — Binding responses from a well-behaved server need
//! none of it. Zero new dependencies: the codec is hand-rolled over
//! byte slices, randomness comes from the workspace `rand`.
//!
//! Role in NAT traversal: with one UDP socket per node and
//! joiner-speaks-first, the coordinator's return path is the observed
//! announce source (valid through every NAT type, symmetric
//! included). The reflexive address is secondary — diagnostics,
//! candidate exchange, and the symmetric heuristic — never the
//! primary route. "Hole-punching" is the WireGuard handshake itself:
//! initiation datagrams to the selected candidate open the stateful
//! NAT binding, and boringtun's timers retransmit until the peer
//! answers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rand::RngCore;
use tokio::net::UdpSocket;

use super::proto::JoinAnnounce;
use super::transport::PeerTransport;

/// STUN Binding Request message type (RFC 5389 §6).
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
/// STUN Binding Success Response message type.
pub const STUN_BINDING_RESPONSE: u16 = 0x0101;
/// Fixed magic cookie every STUN message carries (bytes 4-7).
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
/// `XOR-MAPPED-ADDRESS` attribute type (RFC 5389 §15.2).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// STUN header length: type + length + cookie + transaction id.
pub const STUN_HEADER_LEN: usize = 20;
/// Transaction id length (96 bits).
pub const STUN_TXID_LEN: usize = 12;

/// Default STUN servers, tried in order. Overridable via
/// `[mesh] stun_servers`; an explicit empty list disables STUN.
pub const DEFAULT_STUN_SERVERS: &[&str] = &["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

/// Binding attempts per discovery call (RFC retransmission spirit:
/// same transaction id, spaced resends).
pub const STUN_ATTEMPTS: u32 = 3;
/// Per-attempt wait for a response.
pub const STUN_TIMEOUT: Duration = Duration::from_secs(1);

/// NAT mapping behavior inferred from two reflexive samples taken
/// through the same socket against different servers. A heuristic,
/// logged only — routing never depends on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatClass {
    /// Same mapping for both servers: full-cone NAT or open internet.
    Cone,
    /// Different mappings: symmetric (or port-restricted) NAT.
    Symmetric,
}

/// Generate a random 96-bit transaction id.
pub fn random_txid() -> [u8; STUN_TXID_LEN] {
    let mut txid = [0u8; STUN_TXID_LEN];
    rand::thread_rng().fill_bytes(&mut txid);
    txid
}

/// Build a bare 20-byte Binding Request header (no attributes).
pub fn build_binding_request(txid: &[u8; STUN_TXID_LEN]) -> [u8; STUN_HEADER_LEN] {
    let mut header = [0u8; STUN_HEADER_LEN];
    header[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    // Length stays zero: no attributes follow.
    header[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    header[8..20].copy_from_slice(txid);
    header
}

/// Build a Binding Success Response carrying one `XOR-MAPPED-ADDRESS`
/// attribute. Production code never sends these (servers do); the
/// mock STUN server in tests does.
pub fn build_binding_response(txid: &[u8; STUN_TXID_LEN], reflexive: SocketAddr) -> Vec<u8> {
    let (family, xaddr): (u8, Vec<u8>) = match reflexive.ip() {
        IpAddr::V4(v4) => {
            let xored = u32::from_be_bytes(v4.octets()) ^ STUN_MAGIC_COOKIE;
            (0x01, xored.to_be_bytes().to_vec())
        }
        IpAddr::V6(v6) => {
            let mask: Vec<u8> = STUN_MAGIC_COOKIE
                .to_be_bytes()
                .into_iter()
                .chain(txid.iter().copied())
                .collect();
            let xored: Vec<u8> = v6
                .octets()
                .iter()
                .zip(mask.iter())
                .map(|(b, m)| b ^ m)
                .collect();
            (0x02, xored)
        }
    };
    let xport = reflexive.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    // Attribute: type + length + family + x-port + x-address.
    let attr_len = 4 + xaddr.len();
    let mut response = vec![0u8; STUN_HEADER_LEN + 4 + attr_len];
    response[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
    response[2..4].copy_from_slice(&((4 + attr_len) as u16).to_be_bytes());
    response[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    response[8..20].copy_from_slice(txid);
    response[20..22].copy_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    response[22..24].copy_from_slice(&(attr_len as u16).to_be_bytes());
    // response[24] is the reserved zero byte.
    response[25] = family;
    response[26..28].copy_from_slice(&xport.to_be_bytes());
    response[28..28 + xaddr.len()].copy_from_slice(&xaddr);
    response
}

/// Cheap shape check so the transport pump can intercept STUN
/// responses before WireGuard trial routing. A response starts with
/// `0x01 0x01`, which naive first-byte dispatch would mistake for a
/// handshake initiation — the magic cookie + length consistency
/// disambiguate (initiations carry zeros where the cookie sits).
pub fn looks_like_stun_response(bytes: &[u8]) -> bool {
    if bytes.len() < STUN_HEADER_LEN {
        return false;
    }
    if u16::from_be_bytes([bytes[0], bytes[1]]) != STUN_BINDING_RESPONSE {
        return false;
    }
    if u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) != STUN_MAGIC_COOKIE {
        return false;
    }
    let declared = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    declared + STUN_HEADER_LEN == bytes.len()
}

/// Parse a Binding Success Response, verifying the transaction id and
/// extracting the first well-formed `XOR-MAPPED-ADDRESS`. Unknown
/// attributes are skipped (comprehension-optional); malformed ones
/// fail the parse.
pub fn parse_binding_response(
    bytes: &[u8],
    expected_txid: &[u8; STUN_TXID_LEN],
) -> Result<SocketAddr, String> {
    if !looks_like_stun_response(bytes) {
        return Err("not a STUN binding response".to_string());
    }
    if bytes[8..20] != expected_txid[..] {
        return Err("STUN transaction id mismatch".to_string());
    }
    let mut offset = STUN_HEADER_LEN;
    while offset + 4 <= bytes.len() {
        let attr_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let attr_len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        let value_start = offset + 4;
        let value_end = value_start + attr_len;
        if value_end > bytes.len() {
            return Err("STUN attribute overruns message".to_string());
        }
        if attr_type == ATTR_XOR_MAPPED_ADDRESS {
            return decode_xor_mapped(&bytes[value_start..value_end], expected_txid);
        }
        // Attributes pad to a 4-byte boundary.
        offset = value_end + (4 - attr_len % 4) % 4;
    }
    Err("STUN response lacks XOR-MAPPED-ADDRESS".to_string())
}

/// Decode one `XOR-MAPPED-ADDRESS` value (family + x-port + x-address).
fn decode_xor_mapped(value: &[u8], txid: &[u8; STUN_TXID_LEN]) -> Result<SocketAddr, String> {
    if value.len() < 4 {
        return Err("XOR-MAPPED-ADDRESS too short".to_string());
    }
    let family = value[1];
    let xport = u16::from_be_bytes([value[2], value[3]]);
    let port = xport ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let ip = match family {
        0x01 => {
            if value.len() < 8 {
                return Err("IPv4 XOR-MAPPED-ADDRESS too short".to_string());
            }
            let xored = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            IpAddr::V4(Ipv4Addr::from(xored ^ STUN_MAGIC_COOKIE))
        }
        0x02 => {
            if value.len() < 20 {
                return Err("IPv6 XOR-MAPPED-ADDRESS too short".to_string());
            }
            let mask: Vec<u8> = STUN_MAGIC_COOKIE
                .to_be_bytes()
                .into_iter()
                .chain(txid.iter().copied())
                .collect();
            let mut octets = [0u8; 16];
            for (i, octet) in octets.iter_mut().enumerate() {
                *octet = value[4 + i] ^ mask[i];
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        other => return Err(format!("unknown XOR-MAPPED family {other}")),
    };
    Ok(SocketAddr::new(ip, port))
}

/// True when a recv error means "nobody is listening" (ICMP
/// port-unreachable surfaced as refused/reset) rather than a broken
/// socket: the server counts as silent, not fatal.
fn is_silence(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
    )
}

/// Discover this socket's reflexive address against one STUN server:
/// send a Binding Request, await the matching response, resend up to
/// [`STUN_ATTEMPTS`] times. The socket must be dedicated to this call
/// (the transport pump routes its own socket's STUN traffic through
/// [`super::transport::PeerTransport::discover_stun`] instead, since
/// two concurrent readers would race datagrams).
pub async fn discover_reflexive_addr(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr, String> {
    let txid = random_txid();
    let request = build_binding_request(&txid);
    let mut buf = vec![0u8; 512];
    for attempt in 0..STUN_ATTEMPTS {
        socket
            .send_to(&request, server)
            .await
            .map_err(|e| format!("STUN request send failed: {e}"))?;
        match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => match parse_binding_response(&buf[..n], &txid) {
                Ok(addr) => return Ok(addr),
                Err(e) => {
                    // A mismatched transaction id means a stray reply
                    // (ours is still in flight); anything else is a
                    // broken server response — both just cost a retry.
                    if attempt + 1 == STUN_ATTEMPTS {
                        return Err(e);
                    }
                }
            },
            Ok(Err(e)) if is_silence(&e) => {
                // ICMP port-unreachable (nothing listening): Windows
                // surfaces it as a recv error where Unix times out.
                // Same meaning — the server is silent — so pay a
                // retry like a timeout instead of failing fast.
                if attempt + 1 == STUN_ATTEMPTS {
                    return Err(format!(
                        "STUN server {server} silent after {STUN_ATTEMPTS} attempts"
                    ));
                }
            }
            Ok(Err(e)) => return Err(format!("STUN receive failed: {e}")),
            Err(_) => {
                if attempt + 1 == STUN_ATTEMPTS {
                    return Err(format!(
                        "STUN server {server} silent after {STUN_ATTEMPTS} attempts"
                    ));
                }
            }
        }
    }
    Err(format!("STUN server {server} unreachable"))
}

/// Reflexive discovery outcome: the mapping plus a NAT
/// classification when two servers answered.
pub struct StunDiscovery {
    pub reflexive: SocketAddr,
    pub nat: Option<NatClass>,
}

/// Discover through the shared transport socket: try each server in
/// order (each attempt is a fresh transaction, retried once on
/// timeout), return the first reflexive mapping plus a NAT
/// classification when a second server answers. Fails closed when no
/// server answers; callers fall back to observed-source routing.
pub async fn discover_via_transport(
    tx: &PeerTransport,
    servers: &[SocketAddr],
) -> Result<StunDiscovery, String> {
    let mut first: Option<SocketAddr> = None;
    let mut nat = None;
    let mut errors = Vec::new();
    for server in servers {
        let mut got = None;
        for _ in 0..2 {
            match tokio::time::timeout(STUN_TIMEOUT, tx.discover_stun(*server)).await {
                Ok(Ok(addr)) => {
                    got = Some(addr);
                    break;
                }
                Ok(Err(e)) => {
                    errors.push(e);
                    break;
                }
                Err(_) => continue,
            }
        }
        match (first, got) {
            (None, Some(addr)) => first = Some(addr),
            (Some(prev), Some(addr)) => {
                nat = Some(classify_nat(prev, addr));
                break;
            }
            (_, None) => {}
        }
    }
    match first {
        Some(reflexive) => Ok(StunDiscovery { reflexive, nat }),
        None => Err(errors.into_iter().next().unwrap_or_else(|| {
            if servers.is_empty() {
                "no STUN servers configured".to_string()
            } else {
                "all STUN servers silent".to_string()
            }
        })),
    }
}

/// Classify NAT mapping behavior from two reflexive samples taken
/// through one socket against different servers.
pub fn classify_nat(first: SocketAddr, second: SocketAddr) -> NatClass {
    if first == second {
        NatClass::Cone
    } else {
        NatClass::Symmetric
    }
}

/// Effective STUN server list: the configured override when present
/// (possibly empty, which disables STUN), else the built-in defaults.
pub fn stun_servers(config: &crate::config::MeshConfig) -> Vec<String> {
    match &config.stun_servers {
        Some(list) => list.clone(),
        None => DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
    }
}

/// Resolve configured `host:port` strings to socket addresses, skipping
/// (loudly) entries that neither parse nor resolve.
pub async fn resolve_stun_servers(servers: &[String]) -> Vec<SocketAddr> {
    let mut resolved = Vec::new();
    for server in servers {
        if let Ok(addr) = server.parse::<SocketAddr>() {
            resolved.push(addr);
            continue;
        }
        match tokio::net::lookup_host(server.as_str()).await {
            Ok(addrs) => {
                if let Some(addr) = addrs.into_iter().next() {
                    resolved.push(addr);
                } else {
                    eprintln!("runner: STUN server {server} resolved to nothing; skipped");
                }
            }
            Err(e) => eprintln!("runner: STUN server {server} unresolvable ({e}); skipped"),
        }
    }
    resolved
}

/// Local interface address that would source traffic to `target` (the
/// connect-without-sending trick; no packets leave the host).
pub fn local_addr_for(target: SocketAddr) -> Option<IpAddr> {
    let probe = std::net::UdpSocket::bind(match target {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    })
    .ok()?;
    probe.connect(target).ok()?;
    probe.local_addr().ok().map(|addr| addr.ip())
}

/// Same-subnet test for the LAN-direct fast path: /24 for IPv4, /64
/// for IPv6. Conservative on purpose — a miss just routes via the
/// observed source, which also works on LANs.
pub fn same_subnet(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a4), IpAddr::V4(b4)) => a4.octets()[..3] == b4.octets()[..3],
        (IpAddr::V6(a6), IpAddr::V6(b6)) => a6.octets()[..8] == b6.octets()[..8],
        _ => false,
    }
}

/// Pick the handshake endpoint for an announce: the advertised LAN
/// address when it shares our subnet, else the observed source (the
/// NAT binding the announce itself opened). The second return value
/// names the decision for logging.
pub fn select_endpoint(
    src: SocketAddr,
    announce: &JoinAnnounce,
    local_ip: IpAddr,
) -> (SocketAddr, &'static str) {
    if let Some(lan) = &announce.lan {
        if let Ok(addr) = lan.parse::<SocketAddr>() {
            if same_subnet(addr.ip(), local_ip) {
                return (addr, "lan");
            }
        }
    }
    (src, "observed")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed transaction id so vectors are reproducible.
    fn fixed_txid() -> [u8; STUN_TXID_LEN] {
        [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        ]
    }

    #[test]
    fn binding_request_has_rfc_shape() {
        let txid = fixed_txid();
        let request = build_binding_request(&txid);
        assert_eq!(u16::from_be_bytes([request[0], request[1]]), 0x0001);
        assert_eq!(u16::from_be_bytes([request[2], request[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([request[4], request[5], request[6], request[7]]),
            0x2112_A442
        );
        assert_eq!(request[8..20], txid);
        // A request is not a response (pump must not intercept it).
        assert!(!looks_like_stun_response(&request));
    }

    #[test]
    fn xor_mapped_ipv4_vector_round_trips() {
        // Hand-computed: 192.0.2.1:32853 with the fixed txid above.
        // x-port = 0x8055 ^ 0x2112 = 0xA147; x-addr = c0000201 ^
        // 2112a442 = e112a643.
        let txid = fixed_txid();
        let reflexive: SocketAddr = "192.0.2.1:32853".parse().unwrap();
        let response = build_binding_response(&txid, reflexive);
        assert!(looks_like_stun_response(&response));
        assert_eq!(&response[26..28], &0xA147u16.to_be_bytes());
        assert_eq!(&response[28..32], &[0xe1, 0x12, 0xa6, 0x43]);
        assert_eq!(parse_binding_response(&response, &txid).unwrap(), reflexive);
    }

    #[test]
    fn xor_mapped_ipv6_vector_round_trips() {
        let txid = fixed_txid();
        let reflexive: SocketAddr = "[2001:db8::1]:3478".parse().unwrap();
        let response = build_binding_response(&txid, reflexive);
        assert!(looks_like_stun_response(&response));
        assert_eq!(response[25], 0x02);
        assert_eq!(parse_binding_response(&response, &txid).unwrap(), reflexive);
    }

    #[test]
    fn malformed_responses_fail_closed() {
        let txid = fixed_txid();
        let good = build_binding_response(&txid, "192.0.2.1:32853".parse().unwrap());

        // Truncated header.
        assert!(!looks_like_stun_response(&good[..10]));
        // Length lie.
        let mut bad_len = good.clone();
        bad_len[2..4].copy_from_slice(&99u16.to_be_bytes());
        assert!(parse_binding_response(&bad_len, &txid).is_err());
        // Wrong transaction id.
        let mut other_txid = txid;
        other_txid[0] ^= 0xff;
        assert!(parse_binding_response(&good, &other_txid).is_err());
        // WireGuard initiation bytes are never STUN (zeros at the cookie).
        assert!(!looks_like_stun_response(&[1u8; 148]));
        // Missing attribute.
        let mut bare = vec![0u8; STUN_HEADER_LEN];
        bare[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        bare[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        bare[8..20].copy_from_slice(&txid);
        assert!(parse_binding_response(&bare, &txid).is_err());
    }

    #[test]
    fn nat_classification_compares_mappings() {
        let a: SocketAddr = "198.51.100.7:45001".parse().unwrap();
        assert_eq!(classify_nat(a, a), NatClass::Cone);
        let b: SocketAddr = "198.51.100.7:45002".parse().unwrap();
        assert_eq!(classify_nat(a, b), NatClass::Symmetric);
    }

    #[test]
    fn subnet_test_covers_both_families() {
        let a: IpAddr = "192.168.1.10".parse().unwrap();
        let b: IpAddr = "192.168.1.200".parse().unwrap();
        let c: IpAddr = "192.168.2.10".parse().unwrap();
        assert!(same_subnet(a, b));
        assert!(!same_subnet(a, c));
        let v6a: IpAddr = "fd00::1".parse().unwrap();
        let v6b: IpAddr = "fd00::2".parse().unwrap();
        let v6c: IpAddr = "fd01::1".parse().unwrap();
        assert!(same_subnet(v6a, v6b));
        assert!(!same_subnet(v6a, v6c));
        assert!(!same_subnet(a, v6a));
    }

    #[test]
    fn silence_covers_refused_and_reset_only() {
        use std::io::{Error, ErrorKind::*};
        for kind in [ConnectionRefused, ConnectionReset] {
            assert!(is_silence(&Error::new(kind, "x")), "{kind:?} is silence");
        }
        for kind in [TimedOut, Interrupted, UnexpectedEof, BrokenPipe] {
            assert!(!is_silence(&Error::new(kind, "x")), "{kind:?} is fatal");
        }
    }
}
