# WAN Peer Execution Transport (`docs/wan-federation.md`)

Trusted peers (friends & family) execute coordinator-dispatched jobs
over Noise-encrypted UDP — no TUN device, no privileges, no kernel
WireGuard. The daemon stays fully unprivileged on both ends.

## How it works

1. **Invite** (coordinator): `runner mesh invite` mints a signed token
   (role + donor caps + TTL) and prints the coordinator's WireGuard
   public key. Send both to the peer operator out of band.
2. **Join** (peer): `runner join <token> --coordinator <host:port>
   --coordinator-pubkey <key>` persists donor caps, mesh identity, and
   coordinator coordinates (0600 config).
3. **Announce**: the peer dials the coordinator with its token + pubkey
   + caps + listen port (plaintext; no session exists yet). The
   coordinator verifies signature + TTL + single-use nonce, learns the
   endpoint from the UDP source, and starts the Noise handshake.
   Re-announces every 60s heal restarts and NAT rebinding; known
   node+pubkey pairs skip the nonce check.
4. **Dispatch**: the coordinator mints a single-use JIT config, offers
   it to an `active` peer, awaits accept (5s), and records the
   in-flight entry + lease. The peer validates donor caps + slots,
   runs the official worker, and reports exit status back.
5. **Completion**: results finish the job record; expired leases
   (job timeout) release for re-dispatch. Any failure fails back to
   cloud burst / wait in the same tick — never wedged.

## Wire protocol

Messages ride inside boringtun sessions wrapped in a framing-only
IPv4 header (boringtun rejects non-IP inner bytes), 20 bytes:
version/IHL `0x45`, exact total length, protocol 253 (experimental),
`10.9.0.1` → `10.9.0.2`. Single datagram per message (16 KiB cap);
larger offers fail closed rather than fragmenting.

- `JoinAnnounce` (plaintext): token + identity + caps + listen port.
- `JobOffer` (encrypted): provider, job/run ids, name, labels,
  JIT blob, worker version, timeout.
- `JobAccept` (encrypted): accept flag + reason.
- `JobResult` (encrypted): exit code + killed flag. Logs stay with
  GitHub (the worker reports directly), so only status crosses.

## Config

```toml
[mesh]
peer_port = 48717  # UDP listen port; unset disables the transport
```

Joiners also persist `coordinator`, `coordinator_pubkey`, `node_key`,
and `join_token` (all set by `runner join`; never hand-edit secrets).

## Donor safety

- Coordinator side: peers route only while `active`, non-drained,
  under cap-derived max load, and meeting the job's `cpu-N` /
  `ram-Ngb` label minimums.
- Peer side: offers are declined without donor caps, below minimums,
  when slots are full, or when already running; execution reserves a
  real governor slot and runs inside the donor cgroup slice.
- Peers never receive the coordinator's LAN cache endpoint or bearer.

## Limits (v1.4.0)

- Direct/LAN endpoints only: no STUN/ICE/DERP hole-punching, so peers
  behind symmetric NAT cannot federate.
- GitHub coordinator loop only; GitLab/Bitbucket loops unchanged.
- At-least-once delivery: a lost accept/result after the peer started
  executing can duplicate work (same tradeoff as the cloud-burst
  path, which likewise gets no completion signal).
- Invitation TTLs bound federation: re-join after expiry; tokens are
  single-use per unknown node.
- Small trusted meshes: unknown-address trial routing is O(sessions),
  backstopped by boringtun's internal rate limiter.

## Test posture

- `tests/test_wan_dispatch.rs` — two live transports on ephemeral
  loopback ports: join→offer→accept→result, token/nonce rejection,
  donor/slot/capacity declines, oversize refusal, and a full
  coordinator-loop run against a stub GitHub API.
- Unit: IPv4 framing, Noise session flows, routing matrix, label
  minimums, lease expiry. No multi-machine network needed anywhere.
