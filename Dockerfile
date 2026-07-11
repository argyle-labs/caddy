# Caddy with the Cloudflare DNS module built in (for DNS-01 ACME / wildcard certs).
# This is why the plugin ships its own image rather than using upstream caddy:latest.
FROM caddy:builder AS builder
RUN xcaddy build \
    --with github.com/caddy-dns/cloudflare

FROM caddy:latest
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
