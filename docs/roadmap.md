# caddy plugin — roadmap

The operational route-management surface is implemented (see below). This file
tracks what's shipped vs. still intended.

## Control & configure Caddy — via the admin API on `:2019`

Shipped (operational surface, driving the JSON config over the admin API):

- **Reverse-proxy routes as first-class objects** — a `route` = hostname →
  upstream(s) (`host:port`). `caddy.route.{list,set,delete}`; `set` is an
  idempotent upsert. Adding a service is one orca call, not a hand-edited
  Caddyfile. Edits are surgical (`PATCH .../routes`).
- **Read config** — `caddy.config.get` (`GET /config/`).
- **Reload** — `caddy.reload` re-applies the running config (`POST /config/` with `If-Match` and `Cache-Control: must-revalidate`).
- **Status** — `caddy.status` (server/route/upstream counts).
- **TLS coverage** — `caddy.tls.ensure`, run by `caddy.route.set`.
- **Export / persist** — `caddy.config.export`, `caddy.config.persist`.

Not yet implemented — captured so the intent isn't lost:

- **TLS-backend per route** (self-signed skip-verify), **header rewrites**, and
  other per-route handler knobs beyond the plain reverse_proxy upstream.
- **DNS-01 / wildcard certs** — create a DNS-01 policy and surface cert status.
  Building Caddy *with* a DNS-provider plugin is a deploy-time concern (needs
  in-guest exec), out of scope for this operational surface.
- **Validate / adapt** — `POST /adapt` to render+validate a Caddyfile before
  applying.
- Service-backend `workload_spec` / `configure` / `status`.
