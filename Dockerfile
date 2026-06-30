# TODO: base image + build for caddy. Mirror jellyfin/Dockerfile conventions.
FROM debian:12-slim
LABEL org.opencontainers.image.source="https://github.com/argyle-labs/caddy"
EXPOSE 80
