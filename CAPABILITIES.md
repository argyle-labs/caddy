# caddy — service backend + tool surface

Pure-Rust plugin (**no bash/compose/provision scripts**) that drives an
already-running Caddy instance over its **admin API** (default `:2019`). The
HTTP client rides orca's `http.request` capability (`delegated-http`), so the
plugin links no reqwest/rustls. Optional bearer token for an authenticating proxy in
front of the admin API.

One binary registers **two facets** on the `Plugin` builder: a `ServiceBackend`
(the generic `service.*` lifecycle) and the `caddy.*` `#[orca_tool]` surface.

## Tools
- [x] `caddy.{create,update,delete}` (admin) — endpoint-registry CRUD generated
      by `#[endpoint_resource]`; `routes` fallback list + optional `#[secret]`
      `api_key` resolved via `secrets::resolve_scoped`
- [x] `caddy.{list,detail}` (read) — hand-written so they can require `read`
- [x] `caddy.status` (read) — servers, route count, upstream count or the reason it failed, warnings
- [x] `caddy.config.get` (read) — current config, redacted
- [x] `caddy.config.export` (read) — current config, redacted, plus the redacted pointers
- [x] `caddy.config.persist` (admin) — `admin.config.persist` back to `true`
- [x] `caddy.route.list` (read) — reverse-proxy routes, including hosts nested in subroutes
- [x] `caddy.route.set` (admin) — route + TLS coverage in one `If-Match` write
- [x] `caddy.route.delete` (admin) — remove a host's route; shared routes only lose the host
- [x] `caddy.tls.ensure` (admin) — TLS coverage plus `certificates.automate` for a host with no route
- [x] `caddy.reload` (admin) — `POST /load` of the running config

Writes run by default and are dry-run aware: `dryRun=true` reads the live config
and returns the computed plan without writing. 412 conflicts are retried up to
3 times from a fresh snapshot. No tool returns secrets.

## Service backend (`service.*`)
- [x] declares runtimes (docker/podman/lxc/vm), capabilities
      (deploy/backup/restore/configure/status), default port, and `data_paths`
      (`/config`, `/data`) for the generic pluggable backup
- [ ] `workload_spec` / `configure` / `status` — planned (currently
      `ServiceError::unimplemented`)

## Provided generically by orca (NO code here)
- endpoint reachability resolution (`route::resolve_reachable` over the `routes` list)
- secret storage/resolution (`caddy.<endpoint>.api_key`)
- the CLI / REST / MCP surfaces over every `caddy.*` tool
