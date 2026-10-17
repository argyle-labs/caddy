<p align="center">
  <img src="assets/icon-256.png" width="120" alt="caddy" />
</p>

# caddy

Caddy is a fast, automatic-HTTPS web server and reverse proxy.

A first-party [orca](https://github.com/argyle-labs/orca) plugin: first-class CRUD over an already-running Caddy instance's reverse-proxy routes (plus config read / reload / status) over its **admin API** — so you stop hand-editing the `Caddyfile`.

This repo is **self-contained** — the steps below run caddy **by hand, without orca**. orca then drives the running instance's routes through the tools below (and automates deploy/backup via the generic `service.*` surface).

---

## Run it without orca

### Docker Compose

```yaml
# compose.yml
services:
  caddy:
    image: caddy:latest
    container_name: caddy
    restart: unless-stopped
    ports:
      - "80:80/tcp"
      - "443:443/tcp"
      - "443:443/udp"   # HTTP/3
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - ./data:/data
      - ./config:/config
```

```sh
docker compose up -d
```

### Other runtimes

**Podman** — the compose above works with `podman compose up -d`, or run it directly:

```sh
podman run -d --name caddy --restart unless-stopped \
    -p 80:80/tcp \
    -p 443:443/tcp \
    -p 443:443/udp \
    -v ./Caddyfile:/etc/caddy/Caddyfile \
    -v ./data:/data \
    -v ./config:/config \
    caddy:latest
```

**LXC** — on a container-capable LXC (e.g. a Proxmox LXC with nesting enabled) run the same image via Docker/Podman as above, or install caddy from upstream directly on the guest: <https://caddyserver.com/>.

**VM** — install caddy from upstream (<https://caddyserver.com/>) or run the same container image inside the VM; expose port `80`.

**Unraid** — add via *Community Applications*, or *Docker → Add Container* with image `caddy:latest`, port `80`, and the volume paths above.

### Ports & data

| | |
|---|---|
| Default port | `80` |
| Upstream | <https://caddyserver.com/> |
| Operator notes | [caddy.md](docs/caddy.md) |


### Backup & restore

Back up the config/data volume(s) above — that's the whole service state (stop the container first for a clean copy). Restore by putting them back and starting it.

> With orca this is **`service.backup` / `service.restore`** — location-agnostic (docker / podman / lxc / vm), one command regardless of where caddy runs. No per-service backup script.

## With orca

A translation layer over Caddy's official [admin API](https://caddyserver.com/docs/api). Register a running instance as an endpoint whose `routes` point at the admin API (default `localhost:2019`; see [Reaching the admin API](#reaching-the-admin-api)), then drive it:

```sh
orca caddy.create --name edge --route lan=http://10.0.0.5:2019 --enabled true
orca caddy.status        --name edge
orca caddy.route.list    --name edge
orca caddy.route.set     --name edge --host orca.example.com --upstream 10.0.0.6:12000
orca caddy.route.set     --name edge --host app.example.com --upstream 10.0.0.9:8080,10.0.0.10:8080
orca caddy.route.delete  --name edge --host app.example.com
orca caddy.tls.ensure    --name edge --host app.example.com
orca caddy.config.get    --name edge                 # secret-shaped fields redacted
orca caddy.config.export --name edge > caddy.json    # lossless
orca caddy.config.persist --name edge
orca caddy.reload        --name edge
```

Writes run by default; pass `dryRun=true` to preview. Reads need `read`, writes and `config.export` need `admin`. Every write reads `GET /config/` first and sends its `Etag` back as `If-Match`, so a concurrent change fails with HTTP 412 instead of being overwritten ([concurrent config changes](https://caddyserver.com/docs/api#concurrent-config-changes)).

| Tool | Role | Admin API |
|---|---|---|
| `caddy.status` | read | `GET /config/`, `GET /reverse_proxy/upstreams` |
| `caddy.config.get` | read | `GET /config/`, secret-shaped keys redacted |
| `caddy.config.export` | admin | `GET /config/`, unredacted |
| `caddy.route.list` | read | `GET /config/` |
| `caddy.route.set` | admin | `caddy.tls.ensure`, then `PATCH /config/apps/http/servers/<server>/routes` (`PUT` when the server has no `routes` yet) |
| `caddy.route.delete` | admin | `PATCH /config/apps/http/servers/<server>/routes` |
| `caddy.tls.ensure` | admin | `PATCH /config/apps/tls/automation/policies/<i>/subjects` |
| `caddy.config.persist` | admin | `PATCH /config/admin/config/persist` |
| `caddy.reload` | admin | `POST /load` with `Cache-Control: must-revalidate` |

API references: [`GET/PUT/PATCH /config/[path]`](https://caddyserver.com/docs/api#get-configpath), [`POST /load`](https://caddyserver.com/docs/api#post-load), [`GET /reverse_proxy/upstreams`](https://caddyserver.com/docs/api#get-reverse-proxyupstreams), [TLS automation policies](https://caddyserver.com/docs/json/apps/tls/automation/policies/), [`admin.config.persist`](https://caddyserver.com/docs/json/admin/config/persist/).

`api_key` is optional and stored as the orca secret `caddy.<endpoint>.api_key`. Caddy's admin API has no bearer auth of its own; the key is sent as `Authorization: Bearer` for an authenticating proxy in front of it.

### Routes

`caddy.route.set` is idempotent and writes nothing when the route is already right.

- An existing reverse-proxy route for the host has its upstreams replaced, including Caddyfile-style routes whose `reverse_proxy` sits inside a `subroute`.
- It refuses a route that also serves other hosts, or one with more than one `reverse_proxy` handler, rather than changing them all.
- A new host gets `{"match":[{"host":[host]}],"handle":[{"handler":"reverse_proxy",...}],"terminal":true}`, inserted ahead of the first route that would otherwise match it (a wildcard host such as `*.example.com`, or a route without a host matcher).

`caddy.route.delete` removes a route that serves only that host. From a route shared with other hosts it removes just the host, never leaving a matcher broader than before.

### TLS

Caddy picks the first [automation policy](https://caddyserver.com/docs/json/apps/tls/automation/policies/) whose `subjects` match a name; a policy without `subjects` matches every name. `caddy.tls.ensure`, and `caddy.route.set` before it writes the route:

1. Leaves the host alone if a catch-all policy or a matching subject covers it. A subject `*.example.com` matches exactly one label.
2. Otherwise adds the host to the `subjects` of the DNS-01 policy (an issuer with `challenges.dns`) sharing the longest domain suffix with it. Other policies are untouched.
3. Writes nothing when there is no DNS-01 policy. Caddy's default issuers (HTTP-01 / TLS-ALPN-01) then apply, which need the host to be publicly reachable.

Certificates loaded through `apps.tls.certificates` are not considered.

### Running from JSON so admin-API changes survive restarts

Admin-API changes apply live and Caddy autosaves the active config to `autosave.json` in its [config directory](https://caddyserver.com/docs/conventions#configuration-directory) (`admin.config.persist`, default `true`). A Caddy started with `--config Caddyfile` ignores that file and reloads the Caddyfile on every restart or `caddy reload`, discarding everything orca wrote. Convert once, on the Caddy host:

```sh
# 1. Render the Caddyfile to JSON and check it.
caddy adapt --config /etc/caddy/Caddyfile --pretty > /etc/caddy/caddy.json
caddy validate --config /etc/caddy/caddy.json

# 2. Load it through the admin API (this also writes autosave.json).
curl -fsS -X POST -H 'Content-Type: application/json' \
  --data-binary @/etc/caddy/caddy.json http://localhost:2019/load

# 3. Start from the autosave from now on. The packaged caddy-api unit runs
#    `caddy run --environ --resume`.
systemctl disable --now caddy
systemctl enable --now caddy-api
```

- [`caddy adapt`](https://caddyserver.com/docs/command-line#caddy-adapt) and [`caddy validate`](https://caddyserver.com/docs/command-line#caddy-validate) do not touch the running server.
- [`caddy run --resume`](https://caddyserver.com/docs/command-line#caddy-run) starts from the last autosaved config. The `caddy-api` unit is described in [Linux service](https://caddyserver.com/docs/running#linux-service).
- Placeholders such as `{env.CF_API_TOKEN}` survive `adapt`, so give `caddy-api` the same environment file as `caddy` (`systemctl edit caddy-api`, `EnvironmentFile=`).
- In Docker, run `caddy run --resume` and keep `/config` on a volume. That is where `autosave.json` lives.
- After the switch, do not run `caddy reload --config Caddyfile`. Change routes through orca, and keep `orca caddy.config.export` output as the off-box copy. `caddy.config.persist` sets `admin.config.persist` back to `true` if it was turned off.

### Reaching the admin API

The admin endpoint listens on `localhost:2019` by default. Anyone who can reach it can rewrite the server, so it must not be opened to the network without access control ([admin](https://caddyserver.com/docs/json/admin/)). The options:

1. **An orca member on the Caddy host (recommended).** Run orca on the Caddy host and register the endpoint with `--route lan=http://localhost:2019`, so the plugin's HTTP goes from that member to its own loopback. The admin API stays loopback-only and needs no new listener or credential, and access goes through orca's roles.
2. **Loopback admin behind an authenticating site.** Keep `admin localhost:2019`, and add a LAN-bound Caddy site that requires the Hydra forward-auth or a bearer token and `reverse_proxy`s to `localhost:2019` with `header_up Host localhost:2019`. Without that header, the admin endpoint's Host/Origin check rejects the request. Store the token as `caddy.<endpoint>.api_key`. This site lives in the same config orca edits, so a bad write can cut off orca's own access.
3. **`admin.listen` on a LAN address with `origins`.** Avoid. [`origins` / `enforce_origin`](https://caddyserver.com/docs/json/admin/origins/) protect against DNS rebinding and are not authentication: every host on the LAN gets full control.
4. **Remote admin (`admin.remote`).** Authenticates clients by mTLS public key with per-path permissions ([remote](https://caddyserver.com/docs/json/admin/remote/)). It needs a client certificate on every request, and the plugin's delegated HTTP sends none.

## Layout

- `src/lib.rs` — the `ServiceBackend` and the `#[endpoint_resource]` registry.
- `src/api.rs` — the admin-API client.
- `src/routes.rs` — route list/upsert/delete over the config JSON.
- `src/tls.rs` — automation-policy coverage and the subject to add.
- `src/tools.rs` — the `caddy.*` tools.
- `src/main.rs` — the `Plugin` builder entrypoint (dual facet: service + tools).
- `docs/` — standalone operator notes.
- [CAPABILITIES.md](CAPABILITIES.md) — the plugin contract checklist.
- `assets/` — plugin icon.
