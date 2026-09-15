//! caddy service backend + read-only admin-API client.
//!
//! Implements `ServiceBackend` so the generic `service.*` tools
//! (deploy/backup/restore/configure/status/connect/sync) drive caddy. ALONGSIDE
//! it, a read-only `#[orca_tool]` surface ([`tools`]) inspects a running Caddy
//! over its admin API (default `:2019`): `caddy.status` and `caddy.route.list`.
//! Modeled on the adguard/nfs backends. See orca/docs/PLUGIN-PROGRAM.md.
//!
//! The wire surface is the toolkit's cap-backed HTTP client (`delegated-http`),
//! so every request rides orca's `http.request` capability and this plugin links
//! no reqwest/rustls. Hand-written call sites join their admin route onto
//! [`Config::base_url`]. This slice is READ-ONLY — no config-write / route-CRUD.
#![allow(clippy::disallowed_types)]

pub mod tools;

use plugin_toolkit::reqwest;
use plugin_toolkit::serde_json;
use plugin_toolkit::service::{
    BoxFuture, Endpoint, Runtime, ServiceBackend, ServiceCapability, ServiceError, ServiceStatus,
    WorkloadSpec,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// caddy backend. Holds only the provider name; per-instance endpoint/creds
/// come from the `Endpoint` the generic `service.*` tools hand each op.
#[derive(Debug, Clone)]
pub struct CaddyBackend {
    provider: &'static str,
}

impl CaddyBackend {
    pub fn new(provider: &'static str) -> Self {
        Self { provider }
    }
}

impl ServiceBackend for CaddyBackend {
    fn provider(&self) -> &str {
        self.provider
    }

    /// Runtimes caddy can be placed on. `service.deploy` hands the
    /// `workload_spec` below to a matching deploy target — this backend never
    /// drives pct/docker itself (that mechanic lives in the deploy-target domain).
    fn runtimes(&self) -> Vec<Runtime> {
        vec![Runtime::Docker, Runtime::Podman, Runtime::Lxc, Runtime::Vm]
    }

    fn capabilities(&self) -> Vec<ServiceCapability> {
        vec![
            ServiceCapability::Deploy,
            ServiceCapability::Backup,
            ServiceCapability::Restore,
            ServiceCapability::Configure,
            ServiceCapability::Status,
        ]
    }

    fn default_port(&self) -> u16 {
        80
    }

    /// In-workload paths holding config/data. This is ALL caddy declares for
    /// backup — the generic pluggable backup (tar for containers/LXC, PBS for
    /// Proxmox guests when available) snapshots these. No backup/restore code
    /// here; those are inherited from ServiceBackend's defaults.
    fn data_paths(&self) -> Vec<String> {
        vec!["/config".to_string()]
    }

    fn workload_spec<'a>(
        &'a self,
        _runtime: Runtime,
        _ep: &'a Endpoint,
    ) -> BoxFuture<'a, Result<WorkloadSpec, ServiceError>> {
        // TODO: describe the caddy workload (image/template, ports, mounts,
        // env) for the chosen runtime. The deploy target turns this into a
        // compose service / LXC config / VM. See deploy-target::WorkloadSpec.
        Box::pin(async move { Err(ServiceError::unimplemented("caddy.workload_spec")) })
    }

    fn configure<'a>(
        &'a self,
        _ep: &'a Endpoint,
        _config: &'a str,
    ) -> BoxFuture<'a, Result<(), ServiceError>> {
        // TODO: apply caddy-specific config idempotently.
        Box::pin(async move { Err(ServiceError::unimplemented("caddy.configure")) })
    }

    fn status<'a>(
        &'a self,
        _ep: &'a Endpoint,
    ) -> BoxFuture<'a, Result<ServiceStatus, ServiceError>> {
        // TODO: real health/diagnostics.
        Box::pin(async move { Err(ServiceError::unimplemented("caddy.status")) })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Read-only admin-API client
// ═══════════════════════════════════════════════════════════════════════════

/// A small liveness/shape summary derived from Caddy's admin config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Status {
    /// `true` if the admin API answered `GET /config/` with 2xx.
    pub reachable: bool,
    /// Number of HTTP servers under `apps.http.servers`.
    pub servers: usize,
    /// Total number of routes across all servers.
    pub routes: usize,
}

/// One reverse-proxy route resolved out of a server's `routes[]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CaddyRoute {
    /// The `apps.http.servers.<name>` this route belongs to.
    pub server: String,
    /// Host matchers (`match[].host`), flattened. May be empty.
    pub host: Vec<String>,
    /// Reverse-proxy upstreams (`reverse_proxy` handler's `upstreams[].dial`).
    pub upstreams: Vec<String>,
    /// The route's `@id`, if it declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Error)]
pub enum CaddyError {
    #[error("caddy transport: {0}")]
    Transport(String),
    #[error("caddy admin api error (status {status}): {body}")]
    Api { status: u16, body: String },
    #[error("malformed caddy response: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of the Caddy admin API (e.g. `http://host:2019`). The admin API
    /// path is joined onto this.
    pub base_url: String,
    /// Skip TLS verification (self-signed homelab certs on an https front-end).
    pub insecure: bool,
}

impl Config {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            insecure: false,
        }
    }

    pub fn insecure(mut self, on: bool) -> Self {
        self.insecure = on;
        self
    }

    /// Build the cap-backed HTTP client with TLS verification toggled per
    /// `insecure`. Caddy's admin API is unauthenticated by default, so no auth
    /// header is attached in this slice.
    pub fn build_client(&self) -> Result<reqwest::Client, CaddyError> {
        plugin_toolkit::api_client::ApiClientBuilder::new()
            .insecure(self.insecure)
            .build()
            .map_err(|e| CaddyError::Transport(format!("client build: {e}")))
    }

    /// Join an admin-API `<path>` onto the base URL.
    fn admin_url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }
}

fn transport(e: impl std::fmt::Display) -> CaddyError {
    CaddyError::Transport(e.to_string())
}

/// `GET /config/apps/http/servers` — the HTTP servers config object, keyed by
/// server name. A missing `apps.http` returns `null`; callers treat that as an
/// empty server set. A 2xx here also proves the admin API is reachable.
async fn get_servers(
    client: &reqwest::Client,
    cfg: &Config,
) -> Result<serde_json::Value, CaddyError> {
    let resp = client
        .get(cfg.admin_url("config/apps/http/servers"))
        .send()
        .await
        .map_err(transport)?;
    let status = resp.status();
    let body = resp.text().await.map_err(transport)?;
    if !status.is_success() {
        return Err(CaddyError::Api {
            status: status.as_u16(),
            body,
        });
    }
    plugin_toolkit::serde_json::from_str(&body).map_err(|e| CaddyError::Malformed(e.to_string()))
}

/// Read a running Caddy's liveness + server/route counts. A transport failure
/// (admin API down/unreachable) maps to `reachable: false` rather than a hard
/// error; a non-2xx HTTP response is still surfaced as an error.
pub async fn status(client: &reqwest::Client, cfg: &Config) -> Result<Status, CaddyError> {
    let servers = match get_servers(client, cfg).await {
        Ok(v) => v,
        Err(CaddyError::Transport(_)) => {
            return Ok(Status {
                reachable: false,
                servers: 0,
                routes: 0,
            })
        }
        Err(e) => return Err(e),
    };
    Ok(count_status(&servers))
}

/// List every reverse-proxy route across all servers.
pub async fn list_routes(
    client: &reqwest::Client,
    cfg: &Config,
) -> Result<Vec<CaddyRoute>, CaddyError> {
    let servers = get_servers(client, cfg).await?;
    Ok(parse_routes(&servers))
}

/// Derive a [`Status`] from a `servers` config object (the value of
/// `apps.http.servers`). Counts servers and sums each server's `routes[]` len.
pub fn count_status(servers: &serde_json::Value) -> Status {
    let Some(map) = servers.as_object() else {
        return Status {
            reachable: true,
            servers: 0,
            routes: 0,
        };
    };
    let routes = map
        .values()
        .filter_map(|s| s.get("routes").and_then(|r| r.as_array()))
        .map(|r| r.len())
        .sum();
    Status {
        reachable: true,
        servers: map.len(),
        routes,
    }
}

/// Walk a `servers` config object and extract every reverse-proxy route.
///
/// For each `apps.http.servers.<name>.routes[]` entry we collect the host
/// matchers (`match[].host`) and any reverse-proxy upstreams. Handlers nest —
/// a `subroute` handler wraps its own `routes[]` — so [`collect_upstreams`]
/// walks `handle[]` recursively, descending into `subroute`/`route` inner
/// routes and collecting the `upstreams[].dial` of every `reverse_proxy`
/// handler it finds. A route that resolves to no reverse-proxy handler is
/// skipped; a route with no host matcher is kept with an empty `host`.
pub fn parse_routes(servers: &serde_json::Value) -> Vec<CaddyRoute> {
    let mut out = Vec::new();
    let Some(map) = servers.as_object() else {
        return out;
    };
    for (server, server_cfg) in map {
        let Some(routes) = server_cfg.get("routes").and_then(|r| r.as_array()) else {
            continue;
        };
        for route in routes {
            let mut upstreams = Vec::new();
            if let Some(handle) = route.get("handle").and_then(|h| h.as_array()) {
                collect_upstreams(handle, &mut upstreams);
            }
            // Skip non-proxy routes: nothing to report for this read-only view.
            if upstreams.is_empty() {
                continue;
            }
            let host = route
                .get("match")
                .and_then(|m| m.as_array())
                .map(|matchers| {
                    matchers
                        .iter()
                        .filter_map(|m| m.get("host").and_then(|h| h.as_array()))
                        .flatten()
                        .filter_map(|h| h.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let id = route
                .get("@id")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            out.push(CaddyRoute {
                server: server.clone(),
                host,
                upstreams,
                id,
            });
        }
    }
    out
}

/// Recursively walk a `handle[]` array, appending the `upstreams[].dial` of
/// every `reverse_proxy` handler. Descends into `subroute`/`route` handlers,
/// which nest their own `routes[]` (each with its own `handle[]`).
fn collect_upstreams(handle: &[serde_json::Value], out: &mut Vec<String>) {
    for h in handle {
        match h.get("handler").and_then(|v| v.as_str()) {
            Some("reverse_proxy") => {
                if let Some(ups) = h.get("upstreams").and_then(|u| u.as_array()) {
                    for u in ups {
                        if let Some(dial) = u.get("dial").and_then(|d| d.as_str()) {
                            out.push(dial.to_string());
                        }
                    }
                }
            }
            Some("subroute") => {
                if let Some(routes) = h.get("routes").and_then(|r| r.as_array()) {
                    for inner in routes {
                        if let Some(inner_handle) = inner.get("handle").and_then(|ih| ih.as_array())
                        {
                            collect_upstreams(inner_handle, out);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declares_provider() {
        let b = CaddyBackend::new("caddy");
        assert_eq!(b.provider(), "caddy");
    }

    #[test]
    fn admin_url_joins_cleanly() {
        let cfg = Config::new("http://host:2019/");
        assert_eq!(
            cfg.admin_url("config/apps/http/servers"),
            "http://host:2019/config/apps/http/servers"
        );
        assert_eq!(cfg.admin_url("/config/"), "http://host:2019/config/");
    }

    /// Realistic `apps.http.servers` blob: one direct host→reverse_proxy route,
    /// one route whose proxy is nested inside a `subroute`, and one non-proxy
    /// route (static_response) that must be skipped.
    fn sample_servers() -> serde_json::Value {
        plugin_toolkit::serde_json::json!({
            "srv0": {
                "routes": [
                    {
                        "@id": "app",
                        "match": [{ "host": ["app.example.com"] }],
                        "handle": [
                            {
                                "handler": "reverse_proxy",
                                "upstreams": [{ "dial": "10.0.0.10:8080" }]
                            }
                        ]
                    },
                    {
                        "match": [{ "host": ["nested.example.com"] }],
                        "handle": [
                            {
                                "handler": "subroute",
                                "routes": [
                                    {
                                        "handle": [
                                            {
                                                "handler": "reverse_proxy",
                                                "upstreams": [{ "dial": "10.0.0.11:9090" }]
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "match": [{ "host": ["static.example.com"] }],
                        "handle": [
                            { "handler": "static_response", "body": "ok" }
                        ]
                    }
                ]
            }
        })
    }

    #[test]
    fn parse_routes_extracts_direct_and_nested_skips_non_proxy() {
        let routes = parse_routes(&sample_servers());
        assert_eq!(routes.len(), 2, "non-proxy route must be skipped");

        let app = &routes[0];
        assert_eq!(app.server, "srv0");
        assert_eq!(app.host, vec!["app.example.com"]);
        assert_eq!(app.upstreams, vec!["10.0.0.10:8080"]);
        assert_eq!(app.id.as_deref(), Some("app"));

        let nested = &routes[1];
        assert_eq!(nested.host, vec!["nested.example.com"]);
        assert_eq!(nested.upstreams, vec!["10.0.0.11:9090"], "subroute walked");
        assert_eq!(nested.id, None);
    }

    #[test]
    fn count_status_counts_servers_and_routes() {
        let s = count_status(&sample_servers());
        assert!(s.reachable);
        assert_eq!(s.servers, 1);
        assert_eq!(s.routes, 3, "counts every route, proxy or not");
    }

    #[test]
    fn parse_routes_tolerates_empty_config() {
        assert!(parse_routes(&serde_json::Value::Null).is_empty());
        let s = count_status(&serde_json::Value::Null);
        assert!(s.reachable);
        assert_eq!(s.servers, 0);
        assert_eq!(s.routes, 0);
    }
}
