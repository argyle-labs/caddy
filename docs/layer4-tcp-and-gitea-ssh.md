# Caddy plugin — reverse-proxy + Layer4 TCP capability (impl notes)

> **Status:** design notes seeded 2026-08-10 from a MANUAL implementation on the
> live homelab. The orca `caddy` plugin is currently `unreleased`/not-installed,
> so this was done by hand on the Docker Caddy host (`baldur`, 10.10.10.6). These
> notes exist so the plugin can later own this declaratively over the orca API.
> Design intent: **orca sets all of this over the API; plugins define how.**

## The problem this capability must solve

`gitea.scottkey.me` (public + internal DNS → `baldur` 10.10.10.6) is fronted by a
Docker Caddy that terminates TLS and reverse-proxies **HTTP only** to the Gitea
LXC (`CT117@frigg`, `10.10.10.20:3000`). Gitea's **SSH** listens on
`10.10.10.20:2222`, but Caddy published only `:80`/`:443`, so `gitea.scottkey.me:2222`
did not route anywhere — git-over-SSH was unreachable via the hostname. TLS is
terminated ONLY at Caddy (the Gitea host serves plain HTTP on :3000, no cert), so
a blanket DNS repoint of the name to the LXC would break HTTPS. The correct fix is
to make Caddy **also pass raw TCP :2222 through to the Gitea host** — an L4
(transport-layer) route alongside the existing L7 reverse_proxy.

## Ground truth captured from the manual host (baldur `/opt/stacks/caddy/`)

- Caddy **v2.11.2**, Docker, `container_name: caddy`, `restart: unless-stopped`.
- Image is a **custom xcaddy build** (`build: .`):
  ```dockerfile
  FROM caddy:builder AS builder
  RUN xcaddy build \
      --with github.com/caddy-dns/cloudflare
  FROM caddy:latest
  COPY --from=builder /usr/bin/caddy /usr/bin/caddy
  ```
  → **`caddy-l4` is NOT present** (`caddy list-modules | grep layer4` is empty).
- ACME: **Cloudflare DNS-01** (`acme_dns cloudflare {env.CF_API_TOKEN}`), email
  scottdkey@gmail.com. `CF_API_TOKEN` injected via compose env.
- Ports published: `80:80`, `443:443`, `443:443/udp` (HTTP/3). Admin on 2019 (internal).
- Config: `/opt/stacks/caddy/Caddyfile` → `/etc/caddy/Caddyfile:ro`. Data/config in
  named volumes `caddy_data` / `caddy_config`.
- **Blast radius: 37 vhosts** (`*.scottkey.me`: opn, adguard, loki/thor/frigg PVE,
  pbs, unifi, willow/maple unraid, ollama, dockge, ha, zwave/zigbee, ntfy, status,
  the full *arr + media stack, immich, jellyfin, gitea, …). Recreating this
  container is a brief outage for ALL of them — treat as shared infra.
- Gitea vhost block today:
  ```
  gitea.scottkey.me {
      reverse_proxy 10.10.10.20:3000
  }
  ```

## The manual change (what the plugin must reproduce)

1. **Compose the L4 module into the build** — add to the xcaddy line:
   ```dockerfile
   RUN xcaddy build \
       --with github.com/caddy-dns/cloudflare \
       --with github.com/mholt/caddy-l4
   ```
2. **Declare the L4 route** in the Caddyfile global-options block (caddy-l4 exposes
   the `layer4` app in globals):
   ```
   {
       acme_dns cloudflare {env.CF_API_TOKEN}
       email scottdkey@gmail.com

       layer4 {
           :2222 {
               route {
                   proxy tcp/10.10.10.20:2222
               }
           }
       }
   }
   ```
   (L7 `gitea.scottkey.me { reverse_proxy 10.10.10.20:3000 }` stays unchanged.)
3. **Publish the port** in compose:
   ```yaml
   ports:
     - "80:80"
     - "443:443"
     - "443:443/udp"
     - "2222:2222"
   ```
4. **Build-first, validate, then swap** (never blind-recreate a 37-vhost proxy):
   - `docker compose build` → new image tagged; keep the old image ID for rollback.
   - Assert `caddy list-modules | grep layer4` is now non-empty in the built image.
   - `caddy validate --config /etc/caddy/Caddyfile` against the new image.
   - `docker compose up -d` (recreate — the brief all-services blip).
   - Verify: a couple L7 vhosts still 200 over HTTPS **and**
     `ssh -p 2222 git@gitea.scottkey.me` authenticates (tokenless).
   - Rollback: restore the 3 files (git/backup them first) + `up -d` with the prior image.

DNS needs NO change — the name already points at Caddy; we only added a port.

## Plugin capability shape (for later orca implementation)

The `caddy` plugin should own, declaratively over the orca API:

- **Module set / image composition** — the xcaddy module list (dns providers +
  `caddy-l4` + others). Rebuild + swap is a managed operation with health-gated
  cutover and automatic rollback on validate/health failure (the 37-vhost blast
  radius makes gated cutover mandatory, not optional).
- **L7 routes** — `site → upstream` (the existing `reverse_proxy` blocks), incl.
  `import tls_backend` (self-signed upstreams: proxmox/unifi/unraid) and header
  rewrites (see the `opn.scottkey.me` block).
- **L4 routes** — `listen_port → tcp/udp upstream[:port]` passthrough (this Gitea
  SSH case is the first). Maps to a typed route object, NOT opaque Caddyfile text.
- **ACME/cert config** — DNS-01 provider + credential **by secret reference**
  ([[secrets-opaque-reference-sync-model]]), never inline the CF token.
- **Model note:** Caddy here runs in Docker → the caddy plugin composes with the
  `docker`/`dockge` plugin for image build + container lifecycle, OR (alt design)
  is itself an **api-client plugin** driving Caddy's admin API on :2019
  (`POST /load` with JSON config) so no rebuild/recreate is needed for route
  changes — only module additions require an image rebuild. Prefer the admin-API
  path for route CRUD (zero-downtime `/load`), reserve rebuild for module changes.

## Cross-refs
- DNS side (Unbound host overrides, split-horizon) → `opnsense` plugin notes:
  `docs/unbound-host-overrides.md`.
- Gitea SSH topology: CT117@frigg, LAN `10.10.10.20`, tailnet `100.84.159.99`,
  SSH `:2222`, web `:3000`. Tokenless git auth uses an SSH key registered on the
  orca Gitea account (Gitea 1.27 gates token mint/revoke behind basic auth — an
  admin token cannot rotate tokens, so SSH key auth is the durable path).
