//! Caddy tool surface.
//!
//! Endpoint registry: `caddy.{list, detail, create, update, delete}` — generated
//! wholesale by `#[endpoint_resource]` (row struct, db helpers, schema fragment,
//! args/output types, and the five `#[orca_tool]` fns).
//!
//! Hand-written tools over the admin API:
//!   - `caddy.route.list`    enumerate reverse-proxy routes (host → upstream)
//!   - `caddy.route.set`     idempotent upsert: point `host` at `upstream`
//!   - `caddy.route.delete`  remove the reverse-proxy route(s) matching `host`
//!   - `caddy.config.get`    the full current config JSON
//!   - `caddy.reload`        re-apply the running config (`POST /load`)
//!   - `caddy.status`        reachability + server/route/upstream counts
//!
//! Imports flow through `plugin_toolkit::prelude::*` only.

use plugin_toolkit::prelude::*;

use crate::{Config, Route, Status};

// ═══════════════════════════════════════════════════════════════════════════
// caddy.{list,detail,create,update,delete} — endpoint registry CRUD.
// ═══════════════════════════════════════════════════════════════════════════

// `routes` is a built-in column on every `#[endpoint_resource]` — an ordered
// fallback list (`--route kind=url`, repeatable, e.g.
// `--route lan=http://10.0.0.5:2019`) resolved by `route::resolve_reachable`.
// Each entry points at a Caddy admin API endpoint. `api_key` is optional: the
// admin API is unauthenticated on localhost by default.
#[endpoint_resource(plugin = "caddy")]
pub struct CaddyEndpoint {
    pub name: String,
    #[secret]
    pub api_key: String,
    pub insecure: bool,
    pub enabled: bool,
}

// ── HTTP client helper ─────────────────────────────────────────────────────

/// Resolve a registered endpoint into a ready [`Config`]: the first reachable
/// admin-API base URL (`resolve_reachable` over the endpoint's `routes` fallback
/// list) plus the optional secure-first api_key.
pub(crate) async fn resolve_config(name: &str) -> Result<Config> {
    let row = endpoint_db::require(name)?;
    // Optional bearer token: prefer the abstract secrets domain
    // (`caddy.<endpoint>.api_key`), else a legacy inline column, else none.
    let api_key = plugin_toolkit::secrets::get(&format!("caddy.{name}.api_key"))?
        .or_else(|| (!row.api_key.is_empty()).then(|| row.api_key.clone()));
    let base_url = route::resolve_reachable(name, &row.routes, row.insecure).await?;
    Ok(Config::new(base_url)
        .api_key(api_key)
        .insecure(row.insecure))
}

// ═══════════════════════════════════════════════════════════════════════════
// caddy.status
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct EndpointArgs {
    /// Registered caddy endpoint name.
    #[arg(long)]
    pub name: String,
}

/// Read a Caddy instance's reachability plus server/route/upstream counts.
/// Caddy's admin API exposes no version endpoint, so this is derived from
/// `GET /config/` and `GET /reverse_proxy/upstreams`.
#[orca_tool(domain = "caddy", verb = "status", role = "any")]
async fn caddy_status(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Status> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let config = crate::get_config(&client, &cfg).await?;
    Ok(Status {
        reachable: true,
        servers: crate::server_names(&config),
        routes: crate::route_count(&config),
        upstreams: crate::upstream_count(&client, &cfg).await,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// caddy.config.get
// ═══════════════════════════════════════════════════════════════════════════

/// Read the full current Caddy config as JSON (`GET /config/`).
#[orca_tool(domain = "caddy", verb = "config.get", role = "any")]
async fn caddy_config_get(args: EndpointArgs, _ctx: &ToolCtx) -> Result<JsonAny> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    Ok(JsonAny(crate::get_config(&client, &cfg).await?))
}

// ═══════════════════════════════════════════════════════════════════════════
// caddy.reload
// ═══════════════════════════════════════════════════════════════════════════

/// [MUTATES STATE] Re-apply the running config. Caddy applies every admin write
/// live and has no dedicated "reload" verb, so this reads the current config
/// (`GET /config/`) and posts it straight back (`POST /load` with
/// `Cache-Control: must-revalidate`), forcing a full reload of the exact config
/// that is already running — a safe no-op refresh.
#[orca_tool(domain = "caddy", verb = "reload", data_mutation = true)]
async fn caddy_reload(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Status> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let config = crate::get_config(&client, &cfg).await?;
    crate::load_config(&client, &cfg, &config).await?;
    Ok(Status {
        reachable: true,
        servers: crate::server_names(&config),
        routes: crate::route_count(&config),
        upstreams: crate::upstream_count(&client, &cfg).await,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// caddy.route.list
// ═══════════════════════════════════════════════════════════════════════════

/// List every reverse-proxy route (host match → upstream dial) across all http
/// servers on a Caddy instance.
#[orca_tool(domain = "caddy", verb = "route.list", role = "any")]
async fn caddy_route_list(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Vec<Route>> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let config = crate::get_config(&client, &cfg).await?;
    Ok(crate::list_routes(&config))
}

// ═══════════════════════════════════════════════════════════════════════════
// caddy.route.set / caddy.route.delete
// ═══════════════════════════════════════════════════════════════════════════

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct RouteSetArgs {
    /// Registered caddy endpoint name.
    #[arg(long)]
    pub name: String,
    /// The hostname to route (e.g. `service.example.com`).
    #[arg(long)]
    pub host: String,
    /// Upstream dial target(s), `host:port`. Repeat/comma-separate for several.
    #[arg(long)]
    pub upstream: String,
    /// The http server to edit (`apps.http.servers.<server>`). Optional when the
    /// instance has exactly one server.
    #[arg(long)]
    pub server: Option<String>,
}

#[derive(clap::Args, Serialize, Deserialize, JsonSchema)]
pub struct RouteDeleteArgs {
    /// Registered caddy endpoint name.
    #[arg(long)]
    pub name: String,
    /// The hostname whose reverse-proxy route(s) to remove.
    #[arg(long)]
    pub host: String,
    /// The http server to edit. Optional when the instance has one server.
    #[arg(long)]
    pub server: Option<String>,
}

/// [MUTATES STATE] Point `host` at `upstream`, idempotently. If a reverse-proxy
/// route already matches `host`, its upstreams are replaced in place; otherwise a
/// new route is appended. Applied surgically via
/// `PATCH /config/apps/http/servers/<server>/routes` — TLS automation and other
/// apps are untouched.
#[orca_tool(domain = "caddy", verb = "route.set", data_mutation = true)]
async fn caddy_route_set(args: RouteSetArgs, _ctx: &ToolCtx) -> Result<Route> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let config = crate::get_config(&client, &cfg).await?;
    let server = crate::choose_server(&config, args.server.as_deref())?;
    let upstreams: Vec<String> = args
        .upstream
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let routes = crate::upsert_route(&config, &server, &args.host, &upstreams)?;
    crate::patch_path(
        &client,
        &cfg,
        &format!("apps/http/servers/{server}/routes"),
        &routes,
    )
    .await?;
    Ok(Route {
        server,
        hosts: vec![args.host],
        upstreams,
    })
}

/// [MUTATES STATE] Remove the reverse-proxy route(s) matching `host` from a
/// server, applied surgically via `PATCH .../routes`.
#[orca_tool(domain = "caddy", verb = "route.delete", data_mutation = true)]
async fn caddy_route_delete(args: RouteDeleteArgs, _ctx: &ToolCtx) -> Result<Route> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    let config = crate::get_config(&client, &cfg).await?;
    let server = crate::choose_server(&config, args.server.as_deref())?;
    let (routes, removed) = crate::delete_route(&config, &server, &args.host);
    if !removed {
        anyhow::bail!(
            "no reverse-proxy route for host '{}' on server '{server}'",
            args.host
        );
    }
    crate::patch_path(
        &client,
        &cfg,
        &format!("apps/http/servers/{server}/routes"),
        &routes,
    )
    .await?;
    Ok(Route {
        server,
        hosts: vec![args.host],
        upstreams: vec![],
    })
}
