# Per-Repo Cache Isolation (`docs/cache-isolation.md`)

The transparent `ACTIONS_CACHE_URL` proxy namespaces every entry by
repository scope (`owner/repo`), so multi-tenant meshes never share
or collide dependency caches across repositories. Same key, same
version, different repo: a miss, always.

## How it works

1. **Scoped endpoint**: workers receive
   `ACTIONS_CACHE_URL=http://{host}:{port}/repos/{owner}/{repo}/`
   (local dispatch takes the slug from the polled repo coordinates;
   WAN peers take it from the job offer and point at their *own*
   loopback proxy — the coordinator's bearer never crosses the mesh).
2. **Scoped routes**: the proxy serves
   `/repos/:owner/:repo/_apis/artifactcache/*` alongside the legacy
   unscoped routes, which fall back to the `global` namespace (old
   clients and pre-v1.7.0 index rows keep working, no wipe).
3. **Scoped store**: entries index by `(scope, version, key)` —
   lookups, reserves, restore-key prefix fallback, and filename
   hashes all carry the scope. LRU eviction and the 7-day TTL sweep
   stay store-wide and scope-blind over the shared 10 GB budget, so
   no repo can starve another and idle scopes age out fairly.
4. **Scoped federation**: a local miss queries LAN peers on the same
   scoped path and imports only that scope's bytes. Pre-v1.7.0 peers
   404 scoped paths, which degrades to a miss. Downloads stay
   id-addressed: the HMAC capability minted at scoped lookup time is
   the gate, so a signed URL can only ever serve the entry its own
   lookup authorized.

## Threat model

- Cross-repo *reads* are impossible by construction: every read path
  filters on scope first, including prefix fallback and federation.
- Cross-repo *writes* cannot clobber: reserves are per-scope, so a
  hostile or buggy worker in repo A cannot poison repo B's entries —
  at worst it fills shared budget, which LRU reclaims by recency.
- Scope segments are validated (`[A-Za-z0-9._-]`, no `.`/`..`,
  ≤128 chars); anything else is a 400. Scopes are index keys and
  hash inputs only, never filesystem paths.

## Limits

- Isolation is per repository, not per branch or identity: any job
  for `owner/repo` reads and writes that repo's namespace. Per-trust
  write auth and archive signing remain future work.
- Stats (`cache stats`, IPC, MCP) aggregate store-wide; there are no
  per-scope counters yet.
