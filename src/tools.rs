use plugin_toolkit::contract::paging::{Page, PageParams};
use plugin_toolkit::prelude::*;
use plugin_toolkit::secrets::{self, MissingSecret, Secret};
use plugin_toolkit::serde_json::Value;

use crate::api::{check_dial, check_segment, is_conflict, normalize_host, Caddy};
use crate::redact::{redact_config, redact_value, Redacted};
use crate::routes::{self, ProxyRoute, RouteAction};
use crate::tls::{self, host_matches, Change, TlsReport};
use crate::{endpoint_db, EndpointEntry};

pub const PROVIDER: &str = "caddy";
pub const MAX_ATTEMPTS: usize = 3;
const DEFAULT_ADMIN: &str = "localhost:2019";

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

fn entry(row: crate::EndpointRow) -> EndpointEntry {
    EndpointEntry {
        name: row.name,
        routes: row.routes,
        enabled: row.enabled,
    }
}

#[orca_struct(args)]
pub struct ListArgs {
    /// Max endpoints to return this page (clamped to [1, 200]; default 50).
    #[arg(long)]
    pub limit: Option<u32>,
    /// Opaque cursor from a previous page's `nextCursor`. Omit for the first page.
    #[arg(long)]
    pub cursor: Option<String>,
}

#[orca_struct]
pub struct ListOutput {
    pub endpoints: Vec<EndpointEntry>,
    pub next_cursor: Option<String>,
    pub total: Option<u64>,
}

/// Registered caddy endpoints.
#[orca_tool(domain = "caddy", verb = "list", role = "read")]
async fn caddy_list(args: ListArgs, _ctx: &ToolCtx) -> Result<ListOutput> {
    let mut endpoints: Vec<EndpointEntry> = endpoint_db::list()?.into_iter().map(entry).collect();
    endpoints.sort_by(|a, b| a.name.cmp(&b.name));
    let page = Page::from_slice(
        endpoints,
        &PageParams {
            limit: args.limit,
            cursor: args.cursor,
        },
    );
    Ok(ListOutput {
        endpoints: page.items,
        next_cursor: page.next_cursor,
        total: page.total,
    })
}

#[orca_struct(args)]
pub struct EndpointArgs {
    /// Registered caddy endpoint name.
    #[arg(long)]
    pub name: String,
}

#[orca_struct]
pub struct DetailOutput {
    pub endpoint: EndpointEntry,
}

/// One registered caddy endpoint.
#[orca_tool(domain = "caddy", verb = "detail", role = "read")]
async fn caddy_detail(args: EndpointArgs, _ctx: &ToolCtx) -> Result<DetailOutput> {
    Ok(DetailOutput {
        endpoint: entry(endpoint_db::require(&args.name)?),
    })
}

pub fn config_warnings(config: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if config
        .pointer("/admin/config/load")
        .is_some_and(|v| !v.is_null())
    {
        out.push(
            "admin.config.load is set: Caddy pulls its config from a loader, which can replace \
             changes made through the admin API"
                .to_string(),
        );
    }
    out
}

#[orca_struct]
#[derive(Debug, Clone)]
pub struct Status {
    pub servers: Vec<String>,
    pub routes: usize,
    pub upstreams: Option<usize>,
    pub upstreams_error: Option<String>,
    pub warnings: Vec<String>,
}

pub async fn status(c: &Caddy, config: &Value) -> Status {
    let (upstreams, upstreams_error) = match c.upstream_count().await {
        Ok(n) => (Some(n), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    Status {
        servers: routes::server_names(config),
        routes: routes::list_routes(config).len(),
        upstreams,
        upstreams_error,
        warnings: config_warnings(config),
    }
}

/// Http servers, reverse-proxy route count and live upstream count
/// (`GET /config/`, `GET /reverse_proxy/upstreams`).
#[orca_tool(domain = "caddy", verb = "status", role = "read")]
async fn caddy_status(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Status> {
    let c = connect(&args.name).await?;
    let snap = c.config().await?;
    Ok(status(&c, &snap.config).await)
}

/// The current config with secret-shaped keys and DNS provider / EAB settings
/// redacted (`GET /config/`).
#[orca_tool(domain = "caddy", verb = "config.get", role = "read")]
async fn caddy_config_get(args: EndpointArgs, _ctx: &ToolCtx) -> Result<JsonAny> {
    let snap = connect(&args.name).await?.config().await?;
    Ok(JsonAny(redact_value(snap.config)))
}

/// The current config for review, redacted like `caddy.config.get`, with the
/// JSON pointer of every redacted value (`GET /config/`). It is not a restorable
/// copy: back up Caddy's `autosave.json` through `service.backup` for that.
#[orca_tool(
    domain = "caddy",
    verb = "config.export",
    role = "read",
    execute_gated = false
)]
async fn caddy_config_export(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Redacted> {
    let snap = connect(&args.name).await?.config().await?;
    Ok(redact_config(snap.config))
}

#[derive(Debug, Clone)]
pub struct Planned<T> {
    pub out: T,
    pub changes: Vec<Change>,
}

pub async fn commit<T>(
    c: &Caddy,
    dry_run: bool,
    mut plan: impl FnMut(&mut Value) -> Result<Planned<T>>,
) -> Result<Planned<T>> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let snap = c.config().await?;
        let mut cfg = snap.config.clone();
        let planned = plan(&mut cfg)?;
        if dry_run || cfg == snap.config {
            return Ok(planned);
        }
        let etag = require_etag(&snap)?;
        let empty = plugin_toolkit::serde_json::Map::new();
        let before = snap.config.as_object().unwrap_or(&empty);
        let after = cfg.as_object().unwrap_or(&empty);
        let touched: Vec<&String> = before
            .keys()
            .chain(after.keys())
            .filter(|k| before.get(*k) != after.get(*k))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let [key] = touched.as_slice() else {
            bail!("refusing a write that spans several top-level keys: {touched:?}");
        };
        check_segment("config key", key)?;
        let Some(value) = after.get(*key) else {
            bail!("refusing to remove top-level config key {key}");
        };
        let res = if before.contains_key(*key) {
            c.patch(key, value, Some(etag)).await
        } else {
            c.put(key, value, Some(etag)).await
        };
        match res {
            Ok(()) => return Ok(planned),
            Err(e) if is_conflict(&e) && attempt < MAX_ATTEMPTS => continue,
            Err(e) => return Err(e),
        }
    }
}

pub fn require_etag(snap: &crate::api::Snapshot) -> Result<&str> {
    snap.etag.as_deref().ok_or_else(|| {
        anyhow!(
            "GET /config/ returned no Etag; refusing to write without If-Match, since a \
             concurrent change could be silently overwritten"
        )
    })
}

fn admin_listen(config: &Value) -> String {
    let raw = config
        .pointer("/admin/listen")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_ADMIN);
    raw.strip_prefix("tcp/").unwrap_or(raw).to_string()
}

fn split_addr(addr: &str) -> Option<(String, String)> {
    let (host, port) = addr.rsplit_once(':')?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let ip = host.parse::<std::net::IpAddr>().ok().map(|ip| match ip {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
        v4 => v4,
    });
    let host = match ip {
        _ if host.is_empty() => "*".to_string(),
        Some(ip) if ip.is_unspecified() => "*".to_string(),
        Some(ip) if ip.is_loopback() => "loopback".to_string(),
        Some(ip) => ip.to_string(),
        None if host == "localhost" => "loopback".to_string(),
        None => host,
    };
    Some((host, port.to_string()))
}

pub fn same_addr(dial: &str, listen: &str) -> bool {
    if dial.starts_with("unix/") || listen.starts_with("unix/") {
        return dial.trim_start_matches("unix/").trim_start_matches('/')
            == listen.trim_start_matches("unix/").trim_start_matches('/');
    }
    match (split_addr(dial), split_addr(listen)) {
        (Some((dh, dp)), Some((lh, lp))) => dp == lp && (lh == "*" || dh == lh),
        _ => false,
    }
}

fn base_authority(base_url: &str) -> (String, Option<String>) {
    let rest = base_url.split_once("://").map_or(base_url, |(_, r)| r);
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    };
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let with_port = authority.contains(':').then(|| authority.to_string());
    (host, with_port)
}

pub fn guard_self(config: &Value, base_url: &str, host: &str, upstreams: &[String]) -> Result<()> {
    let listen = admin_listen(config);
    let (base_host, base_addr) = base_authority(base_url);
    for u in upstreams {
        if same_addr(u, &listen) || base_addr.as_deref().is_some_and(|a| same_addr(u, a)) {
            bail!("refusing to route to {u}: it is this Caddy's admin API");
        }
    }
    if base_host.parse::<std::net::IpAddr>().is_err() && host_matches(host, &base_host) {
        bail!("refusing to change the route for {host}: orca reaches this Caddy's admin API through it");
    }
    Ok(())
}

#[orca_struct(args)]
pub struct RouteSetArgs {
    /// Registered caddy endpoint name.
    #[arg(long)]
    pub name: String,
    /// Hostname to route, e.g. `service.example.com`. ASCII only (punycode for
    /// internationalized names); `*.example.com` matches exactly one label.
    #[arg(long)]
    pub host: String,
    /// Upstream dial addresses: `host:port`, `[ipv6]:port` or `unix//path`.
    /// Comma-separated on the CLI.
    #[arg(long, value_delimiter = ',', required = true)]
    pub upstream: Vec<String>,
    /// Http server to edit; optional when the instance has exactly one.
    #[arg(long)]
    pub server: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone)]
pub struct RouteSetReport {
    #[serde(rename = "dryRun")]
    pub dry_run: bool,
    pub route: ProxyRoute,
    pub action: RouteAction,
    pub index: usize,
    pub changed: bool,
    pub tls: TlsReport,
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
}

pub async fn set_route(c: &Caddy, args: &RouteSetArgs, dry_run: bool) -> Result<RouteSetReport> {
    let host = normalize_host(&args.host)?;
    let upstreams: Vec<String> = args.upstream.iter().map(|u| u.trim().to_string()).collect();
    if upstreams.is_empty() {
        bail!("pass at least one upstream");
    }
    for u in &upstreams {
        check_dial(u)?;
    }
    let base_url = c.base_url().to_string();
    let planned = commit(c, dry_run, |cfg| {
        let server = routes::choose_server(cfg, args.server.as_deref())?;
        check_segment("server", &server)?;
        let existing = routes::host_route(cfg, &server, &host)?
            .and_then(|(_, r)| routes::route_upstreams(r))
            .unwrap_or_default();
        guard_self(
            cfg,
            &base_url,
            &host,
            &[upstreams.clone(), existing].concat(),
        )?;
        let edit = routes::upsert_route(cfg, &server, &host, &upstreams)?;
        let (tls, tls_changes) = tls::apply(cfg, &host, false);
        let mut changes = tls_changes;
        changes.extend(edit.changes);
        let mut warnings = config_warnings(cfg);
        warnings.extend(tls.warnings.iter().cloned());
        Ok(Planned {
            out: RouteSetReport {
                dry_run,
                route: ProxyRoute {
                    server,
                    hosts: vec![host.clone()],
                    upstreams: upstreams.clone(),
                    nested: false,
                },
                action: edit.action,
                index: edit.index,
                changed: !changes.is_empty(),
                tls,
                changes: changes.clone(),
                warnings,
            },
            changes,
        })
    })
    .await?;
    Ok(planned.out)
}

/// Point a host at upstreams and make sure a TLS automation policy covers it,
/// in one `If-Match` write of `/config/apps` computed from one snapshot. The
/// route is planned first, so a refused route writes nothing. An uncovered
/// host joins the subjects of the DNS-01 policy sharing at least two domain
/// labels with it. An existing route that matches only by host has its single
/// `reverse_proxy` upstreams replaced; otherwise a route is inserted ahead of
/// any wildcard or catch-all route that would shadow it. `dryRun` returns the
/// same report without writing.
#[orca_tool(
    domain = "caddy",
    verb = "route.set",
    role = "admin",
    execute_gated = false,
    dry_run_aware = true
)]
async fn caddy_route_set(args: RouteSetArgs, ctx: &ToolCtx) -> Result<RouteSetReport> {
    set_route(&connect(&args.name).await?, &args, ctx.dry_run()).await
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

#[orca_struct]
#[derive(Debug, Clone)]
pub struct RouteDeleteReport {
    #[serde(rename = "dryRun")]
    pub dry_run: bool,
    pub server: String,
    pub host: String,
    pub action: RouteAction,
    pub index: usize,
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
}

pub async fn delete_route(
    c: &Caddy,
    args: &RouteDeleteArgs,
    dry_run: bool,
) -> Result<RouteDeleteReport> {
    let host = normalize_host(&args.host)?;
    let base_url = c.base_url().to_string();
    let planned = commit(c, dry_run, |cfg| {
        let server = routes::choose_server(cfg, args.server.as_deref())?;
        check_segment("server", &server)?;
        let existing = routes::host_route(cfg, &server, &host)?
            .and_then(|(_, r)| routes::route_upstreams(r))
            .unwrap_or_default();
        guard_self(cfg, &base_url, &host, &existing)?;
        let edit = routes::delete_route(cfg, &server, &host)?;
        Ok(Planned {
            out: RouteDeleteReport {
                dry_run,
                server,
                host: host.clone(),
                action: edit.action,
                index: edit.index,
                changes: edit.changes.clone(),
                warnings: config_warnings(cfg),
            },
            changes: edit.changes,
        })
    })
    .await?;
    Ok(planned.out)
}

/// Remove the reverse-proxy route for a host. A route shared with other hosts
/// keeps serving them and only drops this host. Routes with non-host matchers,
/// or hosts matched inside a subroute, are refused. One `If-Match` write of
/// `/config/apps`; `dryRun` returns the report without writing.
#[orca_tool(
    domain = "caddy",
    verb = "route.delete",
    role = "admin",
    execute_gated = false,
    dry_run_aware = true
)]
async fn caddy_route_delete(args: RouteDeleteArgs, ctx: &ToolCtx) -> Result<RouteDeleteReport> {
    delete_route(&connect(&args.name).await?, &args, ctx.dry_run()).await
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

#[orca_struct]
#[derive(Debug, Clone)]
pub struct TlsEnsureReport {
    #[serde(rename = "dryRun")]
    pub dry_run: bool,
    pub tls: TlsReport,
    pub changed: bool,
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
}

pub async fn ensure_tls(c: &Caddy, host: &str, dry_run: bool) -> Result<TlsEnsureReport> {
    let host = normalize_host(host)?;
    let planned = commit(c, dry_run, |cfg| {
        let (tls, changes) = tls::apply(cfg, &host, true);
        let mut warnings = config_warnings(cfg);
        warnings.extend(tls.warnings.iter().cloned());
        Ok(Planned {
            out: TlsEnsureReport {
                dry_run,
                changed: !changes.is_empty(),
                tls,
                changes: changes.clone(),
                warnings,
            },
            changes,
        })
    })
    .await?;
    Ok(planned.out)
}

/// Have Caddy obtain and renew a certificate for a host with no route. If no
/// automation policy covers the host, it joins the subjects of the DNS-01
/// policy sharing at least two domain labels with it; then the host is added
/// to `apps.tls.certificates.automate`. Reports the covering policy's challenge
/// type and warns when it is not DNS-01. Without a qualifying policy nothing is
/// written. One `If-Match` write of `/config/apps`; `dryRun` previews.
#[orca_tool(
    domain = "caddy",
    verb = "tls.ensure",
    role = "admin",
    execute_gated = false,
    dry_run_aware = true
)]
async fn caddy_tls_ensure(args: TlsEnsureArgs, ctx: &ToolCtx) -> Result<TlsEnsureReport> {
    ensure_tls(&connect(&args.name).await?, &args.host, ctx.dry_run()).await
}

#[orca_struct]
#[derive(Debug, Clone)]
pub struct PersistReport {
    #[serde(rename = "dryRun")]
    pub dry_run: bool,
    pub changed: bool,
    pub changes: Vec<Change>,
    pub warnings: Vec<String>,
}

pub async fn persist(c: &Caddy, dry_run: bool) -> Result<PersistReport> {
    let planned = commit(c, dry_run, |cfg| {
        let mut changes = Vec::new();
        let path = "/admin/config/persist";
        if cfg.pointer(path) == Some(&Value::Bool(false)) {
            if let Some(v) = cfg.pointer_mut(path) {
                *v = Value::Bool(true);
            }
            changes.push(Change::new(
                path,
                Some(Value::Bool(false)),
                Some(Value::Bool(true)),
            ));
        }
        Ok(Planned {
            out: PersistReport {
                dry_run,
                changed: !changes.is_empty(),
                changes: changes.clone(),
                warnings: config_warnings(cfg),
            },
            changes,
        })
    })
    .await?;
    Ok(planned.out)
}

/// Make sure Caddy autosaves admin-API changes to `autosave.json`
/// (`admin.config.persist`, default true). Only an explicit `false` is
/// rewritten, in one `If-Match` write of `/config/admin`. Caddy must run with
/// `--resume` to start from the autosave. `dryRun` previews.
#[orca_tool(
    domain = "caddy",
    verb = "config.persist",
    role = "admin",
    execute_gated = false,
    dry_run_aware = true
)]
async fn caddy_config_persist(args: EndpointArgs, ctx: &ToolCtx) -> Result<PersistReport> {
    persist(&connect(&args.name).await?, ctx.dry_run()).await
}

#[orca_struct]
#[derive(Debug, Clone)]
pub struct ReloadReport {
    #[serde(rename = "dryRun")]
    pub dry_run: bool,
    pub reloaded: bool,
    pub status: Status,
}

pub async fn reload(c: &Caddy, dry_run: bool) -> Result<ReloadReport> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let snap = c.config().await?;
        if !dry_run {
            match c.replace(&snap.config, Some(require_etag(&snap)?)).await {
                Ok(()) => {}
                Err(e) if is_conflict(&e) && attempt < MAX_ATTEMPTS => continue,
                Err(e) => return Err(e),
            }
        }
        return Ok(ReloadReport {
            dry_run,
            reloaded: !dry_run,
            status: status(c, &snap.config).await,
        });
    }
}

/// Reload the running config unchanged: `GET /config/`, then `POST /config/`
/// with the same body, `Cache-Control: must-revalidate` and `If-Match`
/// (`POST /load` ignores `If-Match`), re-read on HTTP 412 up to three times.
/// `dryRun` only reads.
#[orca_tool(
    domain = "caddy",
    verb = "reload",
    role = "admin",
    execute_gated = false,
    dry_run_aware = true
)]
async fn caddy_reload(args: EndpointArgs, ctx: &ToolCtx) -> Result<ReloadReport> {
    reload(&connect(&args.name).await?, ctx.dry_run()).await
}

/// Reverse-proxy routes (host → upstreams) across all http servers, including
/// hosts matched inside subroutes (`nested`).
#[orca_tool(domain = "caddy", verb = "route.list", role = "read")]
async fn caddy_route_list(args: EndpointArgs, _ctx: &ToolCtx) -> Result<Vec<ProxyRoute>> {
    let snap = connect(&args.name).await?.config().await?;
    Ok(routes::list_routes(&snap.config))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WRITES: [&str; 5] = [
        "caddy.reload",
        "caddy.route.set",
        "caddy.route.delete",
        "caddy.tls.ensure",
        "caddy.config.persist",
    ];

    #[test]
    fn empty_routes_give_a_clear_error() {
        let e = require_routes::<String>("edge", &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains("no routes"), "{e}");
        assert!(require_routes("edge", &["http://c.test".to_string()]).is_ok());
    }

    #[test]
    fn tools_declare_roles_and_dry_run() {
        let role = |n| plugin_toolkit::dispatch::required_role(n);
        let aware = plugin_toolkit::dispatch::dry_run_aware_names();
        for n in [
            "caddy.list",
            "caddy.detail",
            "caddy.status",
            "caddy.config.get",
            "caddy.config.export",
            "caddy.route.list",
        ] {
            assert_eq!(role(n), Some("read"), "{n}");
            assert!(!aware.contains(&n), "{n}");
        }
        for n in WRITES {
            assert_eq!(role(n), Some("admin"), "{n}");
            assert!(aware.contains(&n), "{n}");
        }
        let gated = plugin_toolkit::dispatch::execute_gated_names();
        assert!(WRITES.iter().all(|n| !gated.contains(n)));
    }

    #[test]
    fn hosts_are_normalized_and_validated() {
        assert_eq!(
            normalize_host("Orca.ScottKey.ME").unwrap(),
            "orca.scottkey.me"
        );
        assert!(normalize_host("*.example.com").is_ok());
        let long = format!("{}.com", "a".repeat(64));
        for bad in [
            "", "a b.com", "a/b", "a..b", "x.com/", "-a.com", "a-.com", "*", "a.*.com", &long,
        ] {
            assert!(normalize_host(bad).is_err(), "{bad}");
        }
        let e = normalize_host("bücher.example").unwrap_err().to_string();
        assert!(e.contains("punycode"), "{e}");
    }

    #[test]
    fn dials_are_validated() {
        for ok in [
            "10.0.0.6:12000",
            "[::1]:80",
            "app.lan:8080",
            "unix//run/app.sock",
        ] {
            assert!(check_dial(ok).is_ok(), "{ok}");
        }
        for bad in [
            "10.0.0.6",
            "10.0.0.6:0",
            "a b:80",
            ":80",
            "h:99999",
            "{http.request.host}:80",
            "[::zz]:80",
            "http://x:80",
            "unix//",
        ] {
            assert!(check_dial(bad).is_err(), "{bad}");
        }
        assert!(check_segment("server", "srv0").is_ok());
        assert!(check_segment("server", "a/b").is_err());
    }

    #[test]
    fn admin_address_matching() {
        assert!(same_addr("127.0.0.1:2019", "localhost:2019"));
        assert!(same_addr("[::1]:2019", "localhost:2019"));
        assert!(same_addr("127.0.0.2:2019", "localhost:2019"));
        assert!(same_addr("127.255.0.1:2019", "127.0.0.1:2019"));
        assert!(same_addr("[::ffff:127.0.0.1]:2019", "localhost:2019"));
        assert!(same_addr("10.0.0.16:2019", "[::ffff:0.0.0.0]:2019"));
        assert!(same_addr("10.0.0.16:2019", "0.0.0.0:2019"));
        assert!(same_addr("10.0.0.16:2019", ":2019"));
        assert!(!same_addr("10.0.0.16:2019", "localhost:2019"));
        assert!(!same_addr("127.0.0.1:2020", "localhost:2019"));
        assert!(same_addr("unix//run/caddy.sock", "unix//run/caddy.sock"));
    }

    #[test]
    fn guard_refuses_the_admin_api_and_the_endpoints_own_host() {
        let cfg = json!({});
        let ups = |u: &str| vec![u.to_string()];
        assert!(guard_self(
            &cfg,
            "http://localhost:2019",
            "a.example.com",
            &ups("10.0.0.6:80")
        )
        .is_ok());
        assert!(guard_self(
            &cfg,
            "http://localhost:2019",
            "a.example.com",
            &ups("127.0.0.1:2019")
        )
        .is_err());
        let custom = json!({"admin": {"listen": "tcp/10.0.0.16:2999"}});
        assert!(guard_self(&custom, "http://x", "a.example.com", &ups("10.0.0.16:2999")).is_err());
        let base = "https://caddy-admin.example.com/";
        assert!(guard_self(&cfg, base, "caddy-admin.example.com", &ups("10.0.0.6:80")).is_err());
        assert!(guard_self(&cfg, base, "*.example.com", &ups("10.0.0.6:80")).is_err());
        assert!(guard_self(
            &cfg,
            "http://10.0.0.16:2019",
            "a.example.com",
            &ups("10.0.0.16:2019")
        )
        .is_err());
    }

    #[test]
    fn admin_config_load_is_warned_about() {
        assert!(config_warnings(&json!({})).is_empty());
        let w = config_warnings(&json!({"admin": {"config": {"load": {"module": "http"}}}}));
        assert!(w[0].contains("admin.config.load"), "{w:?}");
    }
}
