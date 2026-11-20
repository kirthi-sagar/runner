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
   + caps + listen port + NAT candidates (plaintext; no session exists
   yet). The coordinator verifies signature + TTL + single-use nonce,
   picks the endpoint (LAN candidate when same-subnet, else the
   observed UDP source — the NAT binding the announce itself opened),
   and starts the Noise handshake; on establishment it replies with an
   encrypted `JoinAccept`. Re-announces every 60s heal restarts and NAT
   rebinding; known node+pubkey pairs skip the nonce check.
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

- `JoinAnnounce` (plaintext): token + identity + caps + listen port
  + optional `reflexive` (STUN public mapping) and `lan` (LAN
  address) candidates.
- `JoinAccept` (encrypted): acceptance + the coordinator's reflexive
  address, sent once per session establishment.
- `JobOffer` (encrypted): provider, job/run ids, name, labels,
  JIT blob, worker version, timeout.
- `JobAccept` (encrypted): accept flag + reason.
- `JobResult` (encrypted): exit code + killed flag. Logs stay with
  GitHub (the worker reports directly), so only status crosses.

Wire compat is one-directional across the v1.6.0 boundary: new
coordinators serve older peers (missing candidates default to absent),
but older coordinators reject v1.6.0 announces with candidates
(`deny_unknown_fields`). Upgrade coordinators first.

## Config

```toml
[mesh]
peer_port = 48717  # UDP listen port; unset disables the transport
# STUN servers for reflexive discovery (default: Google + Cloudflare).
# An explicit empty list disables STUN; routing still works.
# stun_servers = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"]
```

Joiners also persist `coordinator`, `coordinator_pubkey`, `node_key`,
and `join_token` (all set by `runner join`; never hand-edit secrets).

## NAT traversal (v1.6.0)

One UDP socket per node, joiner-speaks-first: the coordinator's
return path is the **observed announce source**, valid through every
NAT type (cone, restricted, symmetric) because the announce itself
opened that binding. "Hole-punching" is the WireGuard handshake —
initiation datagrams to the selected endpoint keep the binding alive,
and boringtun's timers retransmit until the peer answers. No TURN
relay, no router configuration, no public IPs.

STUN (minimal RFC 5389 Binding client, zero new dependencies) plays
three supporting roles: reflexive self-discovery advertised in each
announce, a same-subnet LAN-direct fast path, and a log-only
symmetric-NAT heuristic (two servers, mappings compared). STUN
responses share the transport socket, so the pump intercepts them by
shape + transaction id before WireGuard routing. `runner join`
prints a one-shot NAT diagnostic; the daemon re-discovers before
every announce and publishes its own reflexive in `JoinAccept`.

Privacy note: each STUN query reveals this node's existence and IP
to the STUN operator. Defaults are Google + Cloudflare; point
`stun_servers` at your own server, or set it to `[]` to disable.

Troubleshooting symmetric NAT: if a peer behind symmetric NAT never
reaches `active`, check that (1) the coordinator is reachable on its
`peer_port` (the announce must arrive for a binding to open), (2) no
egress firewall blocks the peer's UDP replies, and (3) the daemon
log's `route via observed` line names a public endpoint. The
reflexive address is never dialed, so a reflexive/observed mismatch
in the log is expected behind symmetric NAT — not an error.

## Donor safety

- Coordinator side: peers route only while `active`, non-drained,
  under cap-derived max load, and meeting the job's `cpu-N` /
  `ram-Ngb` label minimums.
- Peer side: offers are declined without donor caps, below minimums,
  when slots are full, or when already running; execution reserves a
  real governor slot and runs inside the donor cgroup slice.
- Peers never receive the coordinator's LAN cache endpoint or bearer.

## Limits (v1.6.0)

- No TURN relaying: both ends must allow the UDP handshake (a firewall
  that blocks all inbound UDP still blocks federation).
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
- `tests/test_mesh_stun.rs` — mock STUN servers + a simulated NAT
  proxy (cone and symmetric modes): reflexive discovery, endpoint
  selection, JoinAccept delivery, malformed-candidate rejection, and
  full join→dispatch→result flows through both NAT types.
- Unit: IPv4 framing, Noise session flows, routing matrix, label
  minimums, lease expiry, STUN vectors. No multi-machine network
  needed anywhere.
