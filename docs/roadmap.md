# caddy plugin — roadmap

Intended functionality for the orca caddy plugin, beyond today's deploy config.
Not yet implemented — captured so the intent isn't lost.

## Control & configure Caddy

The plugin should let orca **control and configure** a running Caddy instance,
not just deploy it:

- **Read/write the Caddyfile** (or Caddy's JSON config via the admin API on
  `:2019`) — add/remove reverse-proxy routes, TLS/ACME settings, snippets.
- **Reload** config without downtime (Caddy admin API `POST /load`).
- **Manage routes as first-class objects** — a `route` = hostname → upstream
  (host:port), optional TLS-backend (self-signed skip-verify), header rewrites.
  Adding a service should be one orca call, not a hand-edited Caddyfile.
- **DNS-01 / wildcard certs** — surface the Cloudflare DNS provider config
  (`CF_API_TOKEN`) and cert status.
- **Validate** (`caddy validate`) before applying.

A route is the concrete shape this plugin should be able to generate and manage:
a hostname mapped to an upstream `host:port`, with optional TLS-backend
(self-signed skip-verify) and header rewrites. See
[`examples/Caddyfile.example`](../examples/Caddyfile.example) for the pattern.
