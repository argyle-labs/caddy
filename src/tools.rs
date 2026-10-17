use plugin_toolkit::prelude::*;
use plugin_toolkit::secrets::{self, MissingSecret, Secret};

use plugin_toolkit::serde_json::Value;

use crate::api::{check_dial, check_host, check_segment, Caddy, Snapshot};
use crate::endpoint_db;
use crate::routes::{self, ProxyRoute};
use crate::tls::{self, TlsReport};

pub const PROVIDER: &str = "caddy";

pub fn api_key(name: &str) -> Result<Option<Secret<String>>> {
    match secrets::resolve_scoped(PROVIDER, name, "api_key") {
        Ok(key) => Ok(Some(key)),
        Err(e) if e.downcast_ref::<MissingSecret>().is_some() => Ok(None),
        Err(e) => Err(e),
    }
}

pub async fn connect(name: &str) -> Result<Caddy> {
    let key = api_key(name)?;
    let row = endpoint_db::require(name)?;
    require_routes(name, &row.routes)?;
    let base_url = route::resolve_reachable(name, &row.routes, false).await?;
    Caddy::new(&base_url, key.as_ref().map(|k| k.expose_secret().as_str()))
}

pub fn require_routes<T>(name: &str, routes: &[T]) -> Result<()> {
    if routes.is_empty() {
        bail!("endpoint {name} has no routes; set routes to the Caddy admin API (port 2019)");
    }
    Ok(())
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct Status {
    pub servers: Vec<String>,
    pub routes: usize,
    pub upstreams: Option<usize>,
}

async fn status(c: &Caddy, config: &Value) -> Status {
    Status {
        servers: routes::server_names(config),
        routes: routes::list_routes(config).len(),
        upstreams: c.upstream_count().await.ok(),
    }
}

#[orca_struct(args)]
pub struct EndpointArgs {
    /// Registered caddy endpoint name.
    #[arg(long)]
    pub name: String,
}

/// Http servers, reverse-proxy route count and live upstream count
/// (`GET /config/`, `GET /reverse_proxy/upstreams`).
#[orca_tool(domain = "caddy", verb = "status", role = "read")]
async fn caddy_status(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Status> {
    let c = connect(&args.name).await?;
    let snap = c.config().await?;
    Ok(status(&c, &snap.config).await)
}

/// The current config with secret-shaped fields redacted (`GET /config/`).
#[orca_tool(domain = "caddy", verb = "config.get", role = "read")]
async fn caddy_config_get(args: EndpointArgs, _ctx: &ToolCtx) -> Result<JsonAny> {
    let snap = connect(&args.name).await?.config().await?;
    Ok(JsonAny(plugin_toolkit::scrub::redact_json(snap.config)))
}

/// Reload the running config unchanged (`GET /config/`, then `POST /load` with
/// `Cache-Control: must-revalidate`).
#[orca_tool(
    domain = "caddy",
    verb = "reload",
    role = "admin",
    execute_gated = true
)]
async fn caddy_reload(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Status> {
    let c = connect(&args.name).await?;
    let snap = c.config().await?;
    c.load(&snap.config).await?;
    Ok(status(&c, &snap.config).await)
}

/// Reverse-proxy routes (host → upstreams) across all http servers.
#[orca_tool(domain = "caddy", verb = "route.list", role = "read")]
async fn caddy_route_list(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Vec<ProxyRoute>> {
    let snap = connect(&args.name).await?.config().await?;
    Ok(routes::list_routes(&snap.config))
}

#[orca_struct(args)]
pub struct RouteSetArgs {
    /// Registered caddy endpoint name.
    #[arg(long)]
    pub name: String,
    /// Hostname to route, e.g. `service.example.com`.
    #[arg(long)]
    pub host: String,
    /// Upstream dial addresses (`host:port`). Comma-separated on the CLI.
    #[arg(long, value_delimiter = ',', required = true)]
    pub upstream: Vec<String>,
    /// Http server to edit; optional when the instance has exactly one.
    #[arg(long)]
    pub server: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct RouteSetReport {
    pub route: ProxyRoute,
    pub changed: bool,
    pub tls: TlsReport,
}

pub async fn ensure_tls(c: &Caddy, host: &str) -> Result<TlsReport> {
    check_host(host)?;
    let snap = c.config().await?;
    let plan = tls::plan(&snap.config, host);
    if let Some((path, value)) = &plan.write {
        c.patch(path, value, snap.etag.as_deref()).await?;
    }
    Ok(plan.report)
}

async fn write_routes(c: &Caddy, snap: &Snapshot, server: &str, routes: &Value) -> Result<()> {
    let path = format!("apps/http/servers/{server}/routes");
    if snap
        .config
        .pointer(&format!("/apps/http/servers/{server}/routes"))
        .is_some()
    {
        c.patch(&path, routes, snap.etag.as_deref()).await
    } else {
        c.put(&path, routes, snap.etag.as_deref()).await
    }
}

pub async fn set_route(c: &Caddy, args: &RouteSetArgs) -> Result<RouteSetReport> {
    check_host(&args.host)?;
    let upstreams: Vec<String> = args.upstream.iter().map(|u| u.trim().to_string()).collect();
    if upstreams.is_empty() {
        bail!("pass at least one upstream");
    }
    for u in &upstreams {
        check_dial(u)?;
    }
    let tls = ensure_tls(c, &args.host).await?;
    let snap = c.config().await?;
    let server = routes::choose_server(&snap.config, args.server.as_deref())?;
    check_segment("server", &server)?;
    let current = snap
        .config
        .pointer(&format!("/apps/http/servers/{server}/routes"))
        .cloned()
        .unwrap_or_else(|| Value::Array(vec![]));
    let new = routes::upsert_route(&snap.config, &server, &args.host, &upstreams)?;
    let changed = new != current;
    if changed {
        write_routes(c, &snap, &server, &new).await?;
    }
    Ok(RouteSetReport {
        route: ProxyRoute {
            server,
            hosts: vec![args.host.clone()],
            upstreams,
        },
        changed,
        tls,
    })
}

/// Point a host at upstreams and make sure Caddy will issue its certificate.
/// TLS first: a host covered by no automation policy is added to the subjects
/// of the closest DNS-01 policy. Then an existing reverse-proxy route for the
/// host (including a Caddyfile-style subroute) has its upstreams replaced, or a
/// new route is inserted ahead of any wildcard or catch-all route that would
/// shadow it. No-op when nothing changes. Writes use
/// `PATCH /config/apps/tls/automation/policies/<i>/subjects` and
/// `PATCH /config/apps/http/servers/<server>/routes`, each with `If-Match`.
#[orca_tool(
    domain = "caddy",
    verb = "route.set",
    role = "admin",
    execute_gated = true
)]
async fn caddy_route_set(args: RouteSetArgs, _ctx: &ToolCtx) -> Result<RouteSetReport> {
    set_route(&connect(&args.name).await?, &args).await
}

#[orca_struct(args)]
pub struct TlsEnsureArgs {
    /// Registered caddy endpoint name.
    #[arg(long)]
    pub name: String,
    /// Hostname that needs a certificate.
    #[arg(long)]
    pub host: String,
}

/// Make sure Caddy's TLS automation covers a host: a catch-all policy or a
/// matching subject (exact or one-label wildcard) leaves it alone; otherwise
/// the host joins the subjects of the closest DNS-01 policy
/// (`PATCH /config/apps/tls/automation/policies/<i>/subjects`, `If-Match`).
/// Without a DNS-01 policy nothing is written and Caddy's default issuers apply.
#[orca_tool(
    domain = "caddy",
    verb = "tls.ensure",
    role = "admin",
    execute_gated = true
)]
async fn caddy_tls_ensure(args: TlsEnsureArgs, _ctx: &ToolCtx) -> Result<TlsReport> {
    ensure_tls(&connect(&args.name).await?, &args.host).await
}

/// The full running config, unredacted, for persisting as the instance's JSON
/// config (`GET /config/`). May contain credentials, so admin only.
#[orca_tool(
    domain = "caddy",
    verb = "config.export",
    role = "admin",
    execute_gated = false
)]
async fn caddy_config_export(args: EndpointArgs, _ctx: &ToolCtx) -> Result<JsonAny> {
    Ok(JsonAny(connect(&args.name).await?.config().await?.config))
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct PersistReport {
    pub persist: bool,
    pub changed: bool,
}

pub async fn persist(c: &Caddy) -> Result<PersistReport> {
    let snap = c.config().await?;
    let off = snap.config.pointer("/admin/config/persist") == Some(&Value::Bool(false));
    if off {
        c.patch(
            "admin/config/persist",
            &Value::Bool(true),
            snap.etag.as_deref(),
        )
        .await?;
    }
    Ok(PersistReport {
        persist: true,
        changed: off,
    })
}

/// Make sure Caddy autosaves every admin-API change to `autosave.json`
/// (`admin.config.persist`, default true). Only an explicit `false` is
/// rewritten (`PATCH /config/admin/config/persist`). Run Caddy with
/// `caddy run --resume` so the autosave is what it starts from.
#[orca_tool(
    domain = "caddy",
    verb = "config.persist",
    role = "admin",
    execute_gated = true
)]
async fn caddy_config_persist(args: EndpointArgs, _ctx: &ToolCtx) -> Result<PersistReport> {
    persist(&connect(&args.name).await?).await
}

#[orca_struct(args)]
pub struct RouteDeleteArgs {
    /// Registered caddy endpoint name.
    #[arg(long)]
    pub name: String,
    /// Hostname whose reverse-proxy route to remove.
    #[arg(long)]
    pub host: String,
    /// Http server to edit; optional when the instance has exactly one.
    #[arg(long)]
    pub server: Option<String>,
}

pub async fn delete_route(c: &Caddy, args: &RouteDeleteArgs) -> Result<ProxyRoute> {
    check_host(&args.host)?;
    let snap = c.config().await?;
    let server = routes::choose_server(&snap.config, args.server.as_deref())?;
    check_segment("server", &server)?;
    let (new, removed) = routes::delete_route(&snap.config, &server, &args.host);
    if !removed {
        bail!(
            "no reverse-proxy route for host '{}' on server '{server}'",
            args.host
        );
    }
    write_routes(c, &snap, &server, &new).await?;
    Ok(ProxyRoute {
        server,
        hosts: vec![args.host.clone()],
        upstreams: vec![],
    })
}

/// Remove the reverse-proxy route for a host. A route shared with other hosts
/// keeps serving them and only drops this host from its matcher
/// (`PATCH /config/apps/http/servers/<server>/routes`, `If-Match`).
#[orca_tool(
    domain = "caddy",
    verb = "route.delete",
    role = "admin",
    execute_gated = true
)]
async fn caddy_route_delete(args: RouteDeleteArgs, _ctx: &ToolCtx) -> Result<ProxyRoute> {
    delete_route(&connect(&args.name).await?, &args).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_routes_give_a_clear_error() {
        let e = require_routes::<String>("edge", &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains("no routes"), "{e}");
        assert!(require_routes("edge", &["http://c.test".to_string()]).is_ok());
    }

    #[test]
    fn tools_declare_roles_and_gating() {
        let role = |n| plugin_toolkit::dispatch::required_role(n);
        let gated = plugin_toolkit::dispatch::execute_gated_names();
        for n in ["caddy.status", "caddy.config.get", "caddy.route.list"] {
            assert_eq!(role(n), Some("read"), "{n}");
            assert!(!gated.contains(&n), "{n}");
        }
        assert_eq!(role("caddy.config.export"), Some("admin"));
        assert!(!gated.contains(&"caddy.config.export"));
        for n in [
            "caddy.reload",
            "caddy.route.set",
            "caddy.route.delete",
            "caddy.tls.ensure",
            "caddy.config.persist",
        ] {
            assert_eq!(role(n), Some("admin"), "{n}");
            assert!(gated.contains(&n), "{n}");
        }
    }

    #[test]
    fn inputs_are_validated() {
        assert!(check_host("orca.scottkey.me").is_ok());
        assert!(check_host("*.example.com").is_ok());
        for bad in ["", "a b.com", "a/b", "a..b", "x.com/"] {
            assert!(check_host(bad).is_err(), "{bad}");
        }
        assert!(check_dial("10.0.0.6:12000").is_ok());
        assert!(check_dial("[::1]:80").is_ok());
        for bad in ["10.0.0.6", "10.0.0.6:0", "a b:80", ":80", "h:99999"] {
            assert!(check_dial(bad).is_err(), "{bad}");
        }
        assert!(check_segment("server", "srv0").is_ok());
        assert!(check_segment("server", "a/b").is_err());
    }
}
