# Caddy

Reverse proxy with automatic TLS. Caddy can issue certificates via an ACME
DNS-01 challenge (e.g. Cloudflare) so it manages HTTPS for `*.<your-domain>`
without exposing ports for cert issuance. Proxy rules live in the `Caddyfile` —
all routing is config.

---

## Ports

| Field | Value |
|---|---|
| HTTP | `80` |
| HTTPS | `443` (TCP + UDP for HTTP/3) |
| Admin API | `http://localhost:2019` (container-local only) |

---

## DNS

Point a wildcard record `*.<your-domain>` at the host running Caddy (internal
resolver and/or public DNS). With an ACME DNS-01 challenge (e.g. Cloudflare),
TLS certificates are issued without any open inbound ports for validation.

---

## Config

All proxy rules live in the `Caddyfile` mounted into the container at
`/etc/caddy/Caddyfile` (see the README for the compose/run volume mounts). To
add a service:

1. Add a block to the `Caddyfile`.
2. Validate it: `docker exec caddy caddy validate --config /etc/caddy/Caddyfile`.
3. Reload live (no restart): `docker exec caddy caddy reload --config /etc/caddy/Caddyfile`.

`caddy reload` applies changes without dropping connections.

---

## Proxy hosts

Each reverse-proxy block maps a hostname to an upstream `host:port`. A typical
route looks like:

```caddyfile
app.<your-domain> {
    reverse_proxy 10.0.0.10:8080
}

dashboard.<your-domain> {
    reverse_proxy https://10.0.0.11:443
}
```

For upstreams that present self-signed certificates, add a TLS-backend snippet
that skips verification (see the TLS section).

---

## Secrets

When using an ACME DNS provider, the API token (e.g. `CF_API_TOKEN` for
Cloudflare) is read from the container environment. Provide it via an `.env`
file next to your compose file (keep it out of version control) or your secrets
manager of choice.

---

## TLS

Caddy manages certificates automatically. With an ACME DNS-01 provider it can
issue wildcard certs. Certs are persisted in the `caddy_data` volume (mounted at
`/data`). A `(tls_backend)` snippet can disable TLS verification for upstreams
that use self-signed certs:

```caddyfile
(tls_backend) {
    transport http {
        tls_insecure_skip_verify
    }
}
```

---

## Troubleshooting

```bash
# View logs
docker logs caddy

# Validate config without reloading
docker exec caddy caddy validate --config /etc/caddy/Caddyfile

# Reload config (no restart)
docker exec caddy caddy reload --config /etc/caddy/Caddyfile

# Inspect the running environment
docker exec caddy caddy environ
```
