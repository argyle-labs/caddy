//! Caddy read-only tool surface.
//!
//! Endpoint registry: `caddy.{list, detail, create, update, delete}` —
//! generated wholesale by `#[endpoint_resource]` (row struct, db helpers, schema
//! fragment, args/output types, and the five `#[orca_tool]` fns).
//!
//! Hand-written READ-ONLY tools over the admin API (default `:2019`):
//!   - `caddy.status`       reachable + server/route counts
//!   - `caddy.route.list`   reverse-proxy routes (host → upstreams)
//!
//! Deliberately NO route write-CRUD (set/delete) in this slice: a wrong config
//! JSON shape could break a live reverse proxy, so writes wait on live
//! validation. Imports flow through `plugin_toolkit::prelude::*` only.

use plugin_toolkit::prelude::*;

use crate::{CaddyRoute, Config, Status};

// ═══════════════════════════════════════════════════════════════════════════
// caddy.{list,detail,create,update,delete} — endpoint registry CRUD.
// ═══════════════════════════════════════════════════════════════════════════

// `routes` is a built-in column on every `#[endpoint_resource]` — an ordered
// fallback list (`--route kind=url`, repeatable, e.g.
// `--route lan=http://host:2019`) resolved by `route::resolve_reachable`. Each
// entry's free-form `kind` (`fqdn` / `lan` / `tailscale`) doubles as the
// locality class the fewest-hop router consumes. The admin API is unauthed by
// default, so this slice registers no secret.
#[endpoint_resource(plugin = "caddy")]
pub struct CaddyEndpoint {
    pub name: String,
    pub insecure: bool,
    pub enabled: bool,
}

// ── HTTP client helper ─────────────────────────────────────────────────────

/// Resolve a registered endpoint into a ready [`Config`]: the first reachable
/// admin base URL (`resolve_reachable` over the endpoint's `routes` fallback
/// list).
pub(crate) async fn resolve_config(name: &str) -> Result<Config> {
    let row = endpoint_db::require(name)?;
    let base_url = route::resolve_reachable(name, &row.routes, row.insecure).await?;
    Ok(Config::new(base_url).insecure(row.insecure))
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

/// Read a running Caddy's liveness and server/route counts over its admin API.
/// An unreachable admin API returns `reachable: false` rather than erroring.
#[orca_tool(domain = "caddy", verb = "status", role = "any")]
async fn caddy_status(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Status> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    Ok(crate::status(&client, &cfg).await?)
}

// ═══════════════════════════════════════════════════════════════════════════
// caddy.route.list
// ═══════════════════════════════════════════════════════════════════════════

/// List every reverse-proxy route Caddy is serving (host matchers → upstreams),
/// walking nested `subroute` handlers. Non-proxy routes are skipped.
#[orca_tool(domain = "caddy", verb = "route.list", role = "any")]
async fn caddy_route_list(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Vec<CaddyRoute>> {
    let cfg = resolve_config(&args.name).await?;
    let client = cfg.build_client()?;
    Ok(crate::list_routes(&client, &cfg).await?)
}
