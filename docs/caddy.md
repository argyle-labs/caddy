# Caddy

Reverse proxy with automatic TLS via Cloudflare DNS-01 challenge. Manages all `*.<your-domain>` HTTPS access. Config lives in the repo — all proxy rules are code.

> Replaced <host> (LXC 104 on <host>) — decommission after Caddy is validated.

---

## Instance

| Field | Value |
|---|---|
| Host | <host> (<ip>) |
| Docker stack | `/opt/stacks/caddy` |
| Ports | 80, 443 |
| Admin API | http://localhost:2019 (container-local only) |

---

## DNS

AdGuard wildcard: `*.<your-domain>` → `<ip>`

External DNS (Cloudflare): `*.<your-domain>` → WAN IP. TLS certificates issued via Cloudflare DNS-01 — no open ports required for cert issuance.

---

## Config

All proxy rules live in `compose/caddy/Caddyfile` in the <repo> repo. To add a service:

1. Add a block to `Caddyfile`
2. Push to GitHub
3. Pull on <host>: `cd /opt/<repo> && git pull`
4. Reload Caddy: `docker exec caddy caddy reload --config /etc/caddy/Caddyfile`

No restart needed for config changes — `caddy reload` applies changes live.

---

## Proxy Hosts

### Infrastructure

| Domain | Backend |
|---|---|
| opn.<your-domain> | <ip>:80 |
| adguard.<your-domain> | <ip>:80 |
| <host>.<your-domain> | https://<ip>:8006 |
| <host>.<your-domain> | https://<ip>:8006 |
| <host>.<your-domain> | https://<ip>:8006 |
| pbs.<your-domain> | https://<ip>:8007 |
| unifi.<your-domain> | https://<ip>:8443 |
| <host>.<your-domain> | https://<ip>:443 |
| ollama.<your-domain> | <ip>:11434 |
| <host>.<your-domain> | https://<ip>:443 |
| dockge.<your-domain> | <ip>:5001 |

### Home Automation

| Domain | Backend |
|---|---|
| ha.<your-domain> | <ip>:8123 |
| zwave.<your-domain> | <ip>:8091 |
| zigbee.<your-domain> | <ip>:8080 |

### Monitoring / Notifications

| Domain | Backend |
|---|---|
| ntfy.<your-domain> | <ip>:8080 |
| status.<your-domain> | <ip>:3001 |

### Media Stack (<host> — <ip>)

| Domain | Port |
|---|---|
| sonarr.<your-domain> | 8989 |
| radarr.<your-domain> | 7878 |
| radarr4k.<your-domain> | 7879 |
| prowlarr.<your-domain> | 9696 |
| bazarr.<your-domain> | 6767 |
| sabnzbd.<your-domain> | 8080 |
| qbittorrent.<your-domain> | 8070 |
| lidarr.<your-domain> | 8686 |
| lazylibrarian.<your-domain> | 5299 |
| kapowarr.<your-domain> | 5656 |
| mylar3.<your-domain> | 8090 |

### Media / Libraries (<host> — <ip>)

| Domain | Port |
|---|---|
| immich.<your-domain> | 2283 |
| audiobookshelf.<your-domain> | 13378 |
| calibre.<your-domain> | 8083 |
| kavita.<your-domain> | 5000 |
| komga.<your-domain> | 25600 |
| navidrome.<your-domain> | 4533 |

### Media (LXCs)

| Domain | Backend |
|---|---|
| jellyfin.<your-domain> | <ip>:8096 |

---

## Secrets

`CF_API_TOKEN` is stored in <secrets-manager>. On <host>, it lives in `/opt/stacks/caddy/.env` (gitignored).

---

## Deployment

### First deploy on <host>

```bash
ssh <user>@<host>
mkdir -p /opt/stacks/caddy
ln -s /opt/<repo>/compose/caddy /opt/stacks/caddy  # if not already symlinked
echo "CF_API_TOKEN=<token>" > /opt/stacks/caddy/.env
cd /opt/stacks/caddy && docker compose up -d --build
```

### DNS cutover

Update AdGuard DNS: `*.<your-domain>` → `<ip>` (was `<ip>`).

### Decommission <host>

Once all subdomains validate:
```bash
# On <host>
pct stop 104
# Remove from autostart if desired, or destroy:
# pct destroy 104
```

---

## TLS

Caddy manages certs automatically via Cloudflare DNS-01. Certs are stored in the `caddy_data` Docker volume. The `(tls_backend)` snippet in the Caddyfile disables TLS verification for backends with self-signed certs (Proxmox nodes, Unifi, Unraid).

---

## Troubleshooting

```bash
# View logs
docker logs caddy

# Validate config without reloading
docker exec caddy caddy validate --config /etc/caddy/Caddyfile

# Reload config (no restart)
docker exec caddy caddy reload --config /etc/caddy/Caddyfile

# Check cert status
docker exec caddy caddy environ
```
