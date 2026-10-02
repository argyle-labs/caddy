//! Caddy admin-API client + service backend.
//!
//! Drives an already-running Caddy reverse proxy over its documented admin API
//! (default `http://localhost:2019`, but the endpoint is per-instance). The
//! operational surface is reverse-proxy route management (hostname → upstream)
//! plus config read / reload / status — so you stop hand-editing the Caddyfile.
//!
//! The wire surface is the toolkit's cap-backed HTTP client (`delegated-http`),
//! so every request rides orca's `http.request` capability and this plugin links
//! no reqwest/rustls. Hand-written call sites join their `/config/...` route onto
//! [`Config::base_url`].
//!
//! ## Route model — surgical `/config/...` edits, not full `/load`
//! Caddy has no "upsert route by host" primitive and applies every admin write
//! live. We therefore read the full config once (`GET /config/`), mutate only the
//! target server's `routes` array in memory (least-destructive: an existing route
//! matching the host has its `reverse_proxy` upstreams replaced in place; a new
//! host is appended as a canonical route), then write just that subtree back with
//! `PATCH /config/apps/http/servers/<srv>/routes`. This leaves TLS automation and
//! every other app untouched — unlike `POST /load`, which replaces the whole
//! config. `caddy.reload` is the one deliberate full re-apply (see [`reload`]).

#![allow(clippy::disallowed_types)]

pub mod tools;

use plugin_toolkit::reqwest;
use plugin_toolkit::serde_json::{json, Value};
use plugin_toolkit::service::{
    BoxFuture, Routes, Runtime, ServiceBackend, ServiceCapability, ServiceError, ServiceStatus,
    WorkloadSpec,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// caddy service backend — Caddy reverse proxy.
///
/// Implements `ServiceBackend` so the generic `service.*` tools
/// (deploy/backup/restore/configure/status/connect/sync) drive caddy. This facet
/// is registered ALONGSIDE the `#[orca_tool]` route-management surface in
/// [`tools`] — one binary, both facets, via the `Plugin` builder. Modeled on the
/// adguard/nfs backends. See orca/docs/PLUGIN-PROGRAM.md.
///
/// Holds only the provider name; per-instance routes/creds come from the
/// `Routes` the generic `service.*` tools hand each op.
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
        vec!["/config".to_string(), "/data".to_string()]
    }

    fn workload_spec<'a>(
        &'a self,
        _runtime: Runtime,
        _instance: &'a str,
        _routes: &'a Routes,
    ) -> BoxFuture<'a, Result<WorkloadSpec, ServiceError>> {
        // TODO: describe the caddy workload (image/template, ports, mounts,
        // env) for the chosen runtime. The deploy target turns this into a
        // compose service / LXC config / VM. See deploy-target::WorkloadSpec.
        Box::pin(async move { Err(ServiceError::unimplemented("caddy.workload_spec")) })
    }

    fn configure<'a>(
        &'a self,
        _instance: &'a str,
        _routes: &'a Routes,
        _config: &'a str,
    ) -> BoxFuture<'a, Result<(), ServiceError>> {
        // TODO: apply caddy-specific config idempotently.
        Box::pin(async move { Err(ServiceError::unimplemented("caddy.configure")) })
    }

    fn status<'a>(
        &'a self,
        _instance: &'a str,
        _routes: &'a Routes,
    ) -> BoxFuture<'a, Result<ServiceStatus, ServiceError>> {
        // TODO: real health/diagnostics.
        Box::pin(async move { Err(ServiceError::unimplemented("caddy.status")) })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Surfaced view types
// ═══════════════════════════════════════════════════════════════════════════

/// A single reverse-proxy route as surfaced by `caddy.route.list`/`set`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Route {
    /// The http server this route lives under (`apps.http.servers.<server>`).
    pub server: String,
    /// The hostnames this route matches (`match[].host[]`).
    pub hosts: Vec<String>,
    /// The reverse-proxy upstream dial addresses (`handle[].upstreams[].dial`).
    pub upstreams: Vec<String>,
}

/// The subset of running state `caddy.status` surfaces. Caddy's admin API exposes
/// no version endpoint, so status is derived from `GET /config/` reachability.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Status {
    /// `GET /config/` returned 2xx.
    pub reachable: bool,
    /// Names of the configured `apps.http.servers`.
    pub servers: Vec<String>,
    /// Total reverse-proxy routes across all http servers.
    pub routes: usize,
    /// Live upstreams reported by `GET /reverse_proxy/upstreams`.
    pub upstreams: usize,
}

#[derive(Debug, Error)]
pub enum CaddyError {
    #[error("caddy transport: {0}")]
    Transport(String),
    #[error("caddy api error (status {status}): {body}")]
    Api { status: u16, body: String },
    #[error("malformed caddy response: {0}")]
    Malformed(String),
    #[error("caddy config: {0}")]
    Config(String),
}

#[derive(Debug, Clone)]
pub struct Config {
    /// Base URL of the Caddy admin API (e.g. `http://10.0.0.5:2019`). The
    /// `/config/...` API path is joined onto this.
    pub base_url: String,
    /// Optional bearer token. The admin API is unauthenticated on localhost by
    /// default; set this only when a front-end/proxy guards it.
    pub api_key: Option<String>,
    /// Skip TLS verification (self-signed cert on an https admin front-end).
    pub insecure: bool,
}

impl Config {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: None,
            insecure: false,
        }
    }

    pub fn api_key(mut self, key: Option<String>) -> Self {
        self.api_key = key.filter(|k| !k.is_empty());
        self
    }

    pub fn insecure(mut self, on: bool) -> Self {
        self.insecure = on;
        self
    }

    /// Build the cap-backed HTTP client, attaching a bearer `authorization`
    /// header only when an api_key is configured (admin API is usually open).
    pub fn build_client(&self) -> Result<reqwest::Client, CaddyError> {
        let mut builder = plugin_toolkit::api_client::ApiClientBuilder::new();
        if let Some(key) = &self.api_key {
            builder = builder
                .header("authorization", format!("Bearer {key}"))
                .map_err(|e| CaddyError::Transport(format!("client build: {e}")))?;
        }
        builder
            .insecure(self.insecure)
            .build()
            .map_err(|e| CaddyError::Transport(format!("client build: {e}")))
    }

    /// Join an admin-API `path` onto the base URL (leading `/` optional).
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

// ═══════════════════════════════════════════════════════════════════════════
// Admin-API primitives
// ═══════════════════════════════════════════════════════════════════════════

/// `GET /config/` — the full current config as JSON.
pub async fn get_config(client: &reqwest::Client, cfg: &Config) -> Result<Value, CaddyError> {
    let resp = client
        .get(cfg.admin_url("config/"))
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
    // An empty config comes back as the literal `null`; normalize to an object.
    if body.trim().is_empty() || body.trim() == "null" {
        return Ok(json!({}));
    }
    plugin_toolkit::serde_json::from_str(&body).map_err(|e| CaddyError::Malformed(e.to_string()))
}

/// `POST /load` — replace the entire config. Forces a reload even if unchanged.
pub async fn load_config(
    client: &reqwest::Client,
    cfg: &Config,
    config: &Value,
) -> Result<(), CaddyError> {
    let resp = client
        .post(cfg.admin_url("load"))
        .header(
            "cache-control",
            reqwest::header::HeaderValue::from_static("must-revalidate"),
        )
        .json(config)
        .send()
        .await
        .map_err(transport)?;
    ok_or_api(resp).await
}

/// `PATCH /config/<path>` — strictly replace the value at an existing config
/// path. Used to write one server's `routes` array back after an in-memory edit.
pub async fn patch_path(
    client: &reqwest::Client,
    cfg: &Config,
    path: &str,
    value: &Value,
) -> Result<(), CaddyError> {
    let resp = client
        .patch(cfg.admin_url(&format!("config/{}", path.trim_start_matches('/'))))
        .json(value)
        .send()
        .await
        .map_err(transport)?;
    ok_or_api(resp).await
}

/// Number of live upstreams from `GET /reverse_proxy/upstreams` (0 if the
/// endpoint is unavailable on this build).
pub async fn upstream_count(client: &reqwest::Client, cfg: &Config) -> usize {
    let Ok(resp) = client
        .get(cfg.admin_url("reverse_proxy/upstreams"))
        .send()
        .await
    else {
        return 0;
    };
    if !resp.status().is_success() {
        return 0;
    }
    let Ok(body) = resp.text().await else {
        return 0;
    };
    plugin_toolkit::serde_json::from_str::<Value>(&body)
        .ok()
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0)
}

async fn ok_or_api(resp: reqwest::Response) -> Result<(), CaddyError> {
    let status = resp.status();
    if status.is_success() {
        Ok(())
    } else {
        let body = resp.text().await.unwrap_or_default();
        Err(CaddyError::Api {
            status: status.as_u16(),
            body,
        })
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Route operations (read-modify-write on the routes array)
// ═══════════════════════════════════════════════════════════════════════════

/// Enumerate every reverse-proxy route across all http servers.
pub fn list_routes(config: &Value) -> Vec<Route> {
    let mut out = Vec::new();
    let Some(servers) = servers_map(config) else {
        return out;
    };
    for (server, srv) in servers {
        for route in server_routes(srv) {
            if let Some(upstreams) = route_upstreams(route) {
                out.push(Route {
                    server: server.clone(),
                    hosts: route_hosts(route),
                    upstreams,
                });
            }
        }
    }
    out
}

/// Total reverse-proxy routes across all http servers.
pub fn route_count(config: &Value) -> usize {
    list_routes(config).len()
}

/// The names of the configured `apps.http.servers`.
pub fn server_names(config: &Value) -> Vec<String> {
    servers_map(config)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Pick the http server to operate on: the caller's choice if given, else the
/// sole server. Errors (listing candidates) when the choice is ambiguous/absent.
pub fn choose_server(config: &Value, requested: Option<&str>) -> Result<String, CaddyError> {
    let names = server_names(config);
    match requested {
        Some(name) => {
            if names.iter().any(|n| n == name) {
                Ok(name.to_string())
            } else {
                Err(CaddyError::Config(format!(
                    "no http server '{name}' (have: {})",
                    join_or_none(&names)
                )))
            }
        }
        None => match names.as_slice() {
            [only] => Ok(only.clone()),
            [] => Err(CaddyError::Config(
                "no apps.http.servers configured; specify --server".into(),
            )),
            _ => Err(CaddyError::Config(format!(
                "multiple http servers ({}); specify --server",
                join_or_none(&names)
            ))),
        },
    }
}

/// Least-destructive upsert of one server's routes: if a route already matches
/// `host`, replace its reverse_proxy upstreams in place (preserving its other
/// fields); otherwise append a canonical `host → upstreams` route. Returns the
/// new routes array for that server. Pure — the caller PATCHes it back.
pub fn upsert_route(
    config: &Value,
    server: &str,
    host: &str,
    upstreams: &[String],
) -> Result<Value, CaddyError> {
    let mut routes = server_routes_owned(config, server);
    let dials: Vec<Value> = upstreams.iter().map(|u| json!({ "dial": u })).collect();

    if let Some(route) = routes
        .iter_mut()
        .find(|r| route_upstreams(r).is_some() && route_matches_host(r, host))
    {
        // Replace the reverse_proxy handler's upstreams in place.
        if let Some(handlers) = route.get_mut("handle").and_then(Value::as_array_mut) {
            for h in handlers {
                if h.get("handler").and_then(Value::as_str) == Some("reverse_proxy") {
                    h["upstreams"] = Value::Array(dials.clone());
                }
            }
        }
    } else {
        routes.push(json!({
            "match": [{ "host": [host] }],
            "handle": [{ "handler": "reverse_proxy", "upstreams": dials }],
            "terminal": true,
        }));
    }
    Ok(Value::Array(routes))
}

/// Drop every reverse-proxy route matching `host` from a server; returns the new
/// routes array and whether anything was removed.
pub fn delete_route(config: &Value, server: &str, host: &str) -> (Value, bool) {
    let routes = server_routes_owned(config, server);
    let before = routes.len();
    let kept: Vec<Value> = routes
        .into_iter()
        .filter(|r| !(route_upstreams(r).is_some() && route_matches_host(r, host)))
        .collect();
    let removed = kept.len() != before;
    (Value::Array(kept), removed)
}

// ── pure helpers over the config Value ──────────────────────────────────────

fn servers_map(config: &Value) -> Option<&plugin_toolkit::serde_json::Map<String, Value>> {
    config.get("apps")?.get("http")?.get("servers")?.as_object()
}

fn server_routes(srv: &Value) -> &[Value] {
    srv.get("routes")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn server_routes_owned(config: &Value, server: &str) -> Vec<Value> {
    servers_map(config)
        .and_then(|m| m.get(server))
        .map(server_routes)
        .map(<[Value]>::to_vec)
        .unwrap_or_default()
}

/// The `handle[].reverse_proxy.upstreams[].dial` list, or `None` if the route has
/// no reverse_proxy handler.
fn route_upstreams(route: &Value) -> Option<Vec<String>> {
    let handlers = route.get("handle")?.as_array()?;
    let mut found = false;
    let mut dials = Vec::new();
    for h in handlers {
        if h.get("handler").and_then(Value::as_str) == Some("reverse_proxy") {
            found = true;
            if let Some(ups) = h.get("upstreams").and_then(Value::as_array) {
                for u in ups {
                    if let Some(d) = u.get("dial").and_then(Value::as_str) {
                        dials.push(d.to_string());
                    }
                }
            }
        }
    }
    found.then_some(dials)
}

fn route_hosts(route: &Value) -> Vec<String> {
    let mut hosts = Vec::new();
    if let Some(matchers) = route.get("match").and_then(Value::as_array) {
        for m in matchers {
            if let Some(hs) = m.get("host").and_then(Value::as_array) {
                for h in hs {
                    if let Some(s) = h.as_str() {
                        hosts.push(s.to_string());
                    }
                }
            }
        }
    }
    hosts
}

fn route_matches_host(route: &Value, host: &str) -> bool {
    route_hosts(route).iter().any(|h| h == host)
}

fn join_or_none(names: &[String]) -> String {
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        json!({
            "apps": { "http": { "servers": {
                "srv0": { "listen": [":443"], "routes": [
                    {
                        "match": [{ "host": ["a.example.com"] }],
                        "handle": [{ "handler": "reverse_proxy",
                                     "upstreams": [{ "dial": "10.0.0.5:8080" }] }],
                        "terminal": true
                    },
                    {
                        "match": [{ "host": ["static.example.com"] }],
                        "handle": [{ "handler": "file_server" }]
                    }
                ]}
            }}}
        })
    }

    #[test]
    fn declares_provider() {
        assert_eq!(CaddyBackend::new("caddy").provider(), "caddy");
    }

    #[test]
    fn admin_url_joins_cleanly() {
        let cfg = Config::new("http://host:2019/");
        assert_eq!(cfg.admin_url("config/"), "http://host:2019/config/");
        assert_eq!(cfg.admin_url("/load"), "http://host:2019/load");
    }

    #[test]
    fn list_routes_surfaces_only_reverse_proxy() {
        let routes = list_routes(&sample());
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].server, "srv0");
        assert_eq!(routes[0].hosts, vec!["a.example.com"]);
        assert_eq!(routes[0].upstreams, vec!["10.0.0.5:8080"]);
    }

    #[test]
    fn choose_server_picks_sole_and_rejects_missing() {
        let cfg = sample();
        assert_eq!(choose_server(&cfg, None).unwrap(), "srv0");
        assert_eq!(choose_server(&cfg, Some("srv0")).unwrap(), "srv0");
        assert!(choose_server(&cfg, Some("nope")).is_err());
    }

    #[test]
    fn upsert_updates_existing_host_in_place() {
        let cfg = sample();
        let routes = upsert_route(&cfg, "srv0", "a.example.com", &["10.0.0.9:80".into()]).unwrap();
        let arr = routes.as_array().unwrap();
        // No new route appended — still two, and the file_server route is intact.
        assert_eq!(arr.len(), 2);
        assert_eq!(route_upstreams(&arr[0]).unwrap(), vec!["10.0.0.9:80"]);
        assert_eq!(route_hosts(&arr[1]), vec!["static.example.com"]);
    }

    #[test]
    fn upsert_appends_new_host() {
        let cfg = sample();
        let routes =
            upsert_route(&cfg, "srv0", "b.example.com", &["10.0.0.7:3000".into()]).unwrap();
        let arr = routes.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        let last = arr.last().unwrap();
        assert_eq!(route_hosts(last), vec!["b.example.com"]);
        assert_eq!(route_upstreams(last).unwrap(), vec!["10.0.0.7:3000"]);
        assert_eq!(last.get("terminal").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn delete_removes_matching_reverse_proxy_route() {
        let cfg = sample();
        let (routes, removed) = delete_route(&cfg, "srv0", "a.example.com");
        assert!(removed);
        let arr = routes.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(route_hosts(&arr[0]), vec!["static.example.com"]);

        let (_, removed_none) = delete_route(&cfg, "srv0", "missing.example.com");
        assert!(!removed_none);
    }

    #[test]
    fn server_names_and_route_count() {
        let cfg = sample();
        assert_eq!(server_names(&cfg), vec!["srv0"]);
        assert_eq!(route_count(&cfg), 1);
    }
}
