#![allow(clippy::disallowed_types)]

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Map, Value};

use crate::tls::{host_matches, Change};

#[orca_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRoute {
    pub server: String,
    pub hosts: Vec<String>,
    pub upstreams: Vec<String>,
    pub nested: bool,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    plugin_toolkit::serde::Serialize,
    plugin_toolkit::serde::Deserialize,
    plugin_toolkit::schemars::JsonSchema,
)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Unchanged,
    Updated,
    Inserted,
    Removed,
    HostDropped,
}

#[derive(Debug, Clone)]
pub struct RouteEdit {
    pub action: RouteAction,
    pub index: usize,
    pub changes: Vec<Change>,
}

pub fn list_routes(config: &Value) -> Vec<ProxyRoute> {
    let mut out = Vec::new();
    for (server, srv) in servers_map(config).into_iter().flatten() {
        walk(server, server_routes(srv), &[], false, &mut out);
    }
    out
}

fn walk(
    server: &str,
    routes: &[Value],
    inherited: &[String],
    nested: bool,
    out: &mut Vec<ProxyRoute>,
) {
    for r in routes {
        let own = route_hosts(r);
        let (hosts, nested) = match (own.is_empty(), inherited.is_empty()) {
            (true, _) => (inherited.to_vec(), nested),
            (false, true) => (own, nested),
            (false, false) => (own, true),
        };
        let handlers = r
            .get("handle")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let dials: Vec<String> = handlers
            .iter()
            .filter(|h| h.get("handler").and_then(Value::as_str) == Some("reverse_proxy"))
            .flat_map(dials_of)
            .collect();
        if handlers
            .iter()
            .any(|h| h.get("handler").and_then(Value::as_str) == Some("reverse_proxy"))
        {
            out.push(ProxyRoute {
                server: server.to_string(),
                hosts: hosts.clone(),
                upstreams: dials,
                nested,
            });
        }
        for sub in handlers
            .iter()
            .filter(|h| h.get("handler").and_then(Value::as_str) == Some("subroute"))
        {
            let inner = sub
                .get("routes")
                .and_then(Value::as_array)
                .map_or(&[][..], Vec::as_slice);
            walk(server, inner, &hosts, nested, out);
        }
    }
}

fn dials_of(h: &Value) -> Vec<String> {
    h.get("upstreams")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|u| u.get("dial").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

pub fn server_names(config: &Value) -> Vec<String> {
    servers_map(config)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

pub fn choose_server(config: &Value, requested: Option<&str>) -> Result<String> {
    let names = server_names(config);
    match requested {
        Some(name) if names.iter().any(|n| n == name) => Ok(name.to_string()),
        Some(name) => bail!("no http server '{name}' (have: {})", join_or_none(&names)),
        None => match names.as_slice() {
            [only] => Ok(only.clone()),
            [] => bail!("no apps.http.servers configured; specify --server"),
            _ => bail!(
                "multiple http servers ({}); specify --server",
                join_or_none(&names)
            ),
        },
    }
}

fn routes_pointer(server: &str) -> String {
    format!("/apps/http/servers/{server}/routes")
}

pub fn host_route<'a>(
    config: &'a Value,
    server: &str,
    host: &str,
) -> Result<Option<(usize, &'a Value)>> {
    let routes = config
        .pointer(&routes_pointer(server))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if let Some(i) = routes.iter().position(|r| nested_mentions(r, host)) {
        bail!(
            "{host} is matched inside the subroute of route {i} (for example a wildcard site \
             block); change it there"
        );
    }
    let mentions: Vec<usize> = routes
        .iter()
        .enumerate()
        .filter(|(_, r)| mentions(r, host))
        .map(|(i, _)| i)
        .collect();
    match mentions.as_slice() {
        [] => Ok(None),
        [i] => {
            let r = &routes[*i];
            if !pure_host_matchers(r) {
                bail!(
                    "route {i} matches {host} together with other conditions (path, method, \
                     header, ...); change it by hand"
                );
            }
            if route_upstreams(r).is_none() {
                bail!("route {i} for {host} is not a reverse proxy; change it by hand");
            }
            Ok(Some((*i, r)))
        }
        many => bail!("routes {many:?} all match {host}; change them by hand"),
    }
}

pub fn upsert_route(
    config: &mut Value,
    server: &str,
    host: &str,
    upstreams: &[String],
) -> Result<RouteEdit> {
    let dials: Vec<Value> = upstreams.iter().map(|u| json!({ "dial": u })).collect();
    let pointer = routes_pointer(server);
    let existing = host_route(config, server, host)?.map(|(i, r)| (i, r.clone()));
    let routes = routes_mut(config, server)?;
    if let Some((i, before)) = existing {
        let others = other_hosts(&before, host);
        if !others.is_empty() {
            bail!(
                "the route for {host} also serves {}; split it before setting upstreams",
                others.join(", ")
            );
        }
        let mut after = before.clone();
        let mut found = Vec::new();
        if let Some(handle) = after.get_mut("handle") {
            proxies_mut(handle, &mut found);
        }
        match found.as_mut_slice() {
            [only] => only["upstreams"] = Value::Array(dials),
            many => bail!(
                "the route for {host} has {} reverse_proxy handlers; refusing to rewrite them all",
                many.len()
            ),
        }
        if after == before {
            return Ok(RouteEdit {
                action: RouteAction::Unchanged,
                index: i,
                changes: vec![],
            });
        }
        routes[i] = after.clone();
        return Ok(RouteEdit {
            action: RouteAction::Updated,
            index: i,
            changes: vec![Change::new(
                format!("{pointer}/{i}"),
                Some(before),
                Some(after),
            )],
        });
    }
    let at = routes
        .iter()
        .position(|r| shadows(r, host))
        .unwrap_or(routes.len());
    let route = json!({
        "match": [{ "host": [host] }],
        "handle": [{ "handler": "reverse_proxy", "upstreams": dials }],
        "terminal": true,
    });
    routes.insert(at, route.clone());
    Ok(RouteEdit {
        action: RouteAction::Inserted,
        index: at,
        changes: vec![Change::new(format!("{pointer}/{at}"), None, Some(route))],
    })
}

pub fn delete_route(config: &mut Value, server: &str, host: &str) -> Result<RouteEdit> {
    let pointer = routes_pointer(server);
    let Some((i, before)) = host_route(config, server, host)?.map(|(i, r)| (i, r.clone())) else {
        bail!("no reverse-proxy route for host '{host}' on server '{server}'");
    };
    let routes = routes_mut(config, server)?;
    if other_hosts(&before, host).is_empty() {
        routes.remove(i);
        return Ok(RouteEdit {
            action: RouteAction::Removed,
            index: i,
            changes: vec![Change::new(format!("{pointer}/{i}"), Some(before), None)],
        });
    }
    let mut after = before.clone();
    if let Some(matchers) = after.get_mut("match").and_then(Value::as_array_mut) {
        for m in matchers.iter_mut() {
            if let Some(hosts) = m.get_mut("host").and_then(Value::as_array_mut) {
                hosts.retain(|h| !h.as_str().is_some_and(|h| h.eq_ignore_ascii_case(host)));
            }
        }
        matchers.retain(|m| {
            m.get("host")
                .and_then(Value::as_array)
                .is_some_and(|h| !h.is_empty())
        });
    }
    routes[i] = after.clone();
    Ok(RouteEdit {
        action: RouteAction::HostDropped,
        index: i,
        changes: vec![Change::new(
            format!("{pointer}/{i}"),
            Some(before),
            Some(after),
        )],
    })
}

fn routes_mut<'a>(config: &'a mut Value, server: &str) -> Result<&'a mut Vec<Value>> {
    let srv = config
        .pointer_mut(&format!("/apps/http/servers/{server}"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| anyhow!("no http server '{server}'"))?;
    srv.entry("routes")
        .or_insert_with(|| Value::Array(vec![]))
        .as_array_mut()
        .ok_or_else(|| anyhow!("apps.http.servers.{server}.routes is not a list"))
}

fn servers_map(config: &Value) -> Option<&Map<String, Value>> {
    config.get("apps")?.get("http")?.get("servers")?.as_object()
}

fn server_routes(srv: &Value) -> &[Value] {
    srv.get("routes")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn proxies(handle: &Value, out: &mut Vec<Value>) {
    for h in handle.as_array().into_iter().flatten() {
        match h.get("handler").and_then(Value::as_str) {
            Some("reverse_proxy") => out.push(h.clone()),
            Some("subroute") => {
                for r in h
                    .get("routes")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(inner) = r.get("handle") {
                        proxies(inner, out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn proxies_mut<'a>(handle: &'a mut Value, out: &mut Vec<&'a mut Value>) {
    for h in handle.as_array_mut().into_iter().flatten() {
        let kind = h.get("handler").and_then(Value::as_str).map(str::to_string);
        match kind.as_deref() {
            Some("reverse_proxy") => out.push(h),
            Some("subroute") => {
                for r in h
                    .get_mut("routes")
                    .and_then(Value::as_array_mut)
                    .into_iter()
                    .flatten()
                {
                    if let Some(inner) = r.get_mut("handle") {
                        proxies_mut(inner, out);
                    }
                }
            }
            _ => {}
        }
    }
}

pub fn route_upstreams(route: &Value) -> Option<Vec<String>> {
    let mut found = Vec::new();
    proxies(route.get("handle")?, &mut found);
    if found.is_empty() {
        return None;
    }
    Some(found.iter().flat_map(dials_of).collect())
}

pub fn route_hosts(route: &Value) -> Vec<String> {
    route
        .get("match")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|m| m.get("host").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn mentions(route: &Value, host: &str) -> bool {
    route_hosts(route)
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
}

fn nested_mentions(route: &Value, host: &str) -> bool {
    route
        .get("handle")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|h| h.get("handler").and_then(Value::as_str) == Some("subroute"))
        .filter_map(|h| h.get("routes").and_then(Value::as_array))
        .flatten()
        .any(|r| mentions(r, host) || nested_mentions(r, host))
}

fn pure_host_matchers(route: &Value) -> bool {
    route
        .get("match")
        .and_then(Value::as_array)
        .is_some_and(|ms| {
            !ms.is_empty()
                && ms.iter().all(|m| {
                    m.as_object()
                        .is_some_and(|o| o.len() == 1 && o.get("host").is_some_and(Value::is_array))
                })
        })
}

fn other_hosts(route: &Value, host: &str) -> Vec<String> {
    route_hosts(route)
        .into_iter()
        .filter(|h| !h.eq_ignore_ascii_case(host))
        .collect()
}

fn shadows(route: &Value, host: &str) -> bool {
    let matchers = route
        .get("match")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    matchers.is_empty()
        || matchers
            .iter()
            .any(|m| match m.get("host").and_then(Value::as_array) {
                None => true,
                Some(hosts) => hosts
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|p| host_matches(p, host)),
            })
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

    fn caddyfile_style() -> Value {
        json!({
            "apps": { "http": { "servers": {
                "srv0": { "listen": [":443"], "routes": [
                    {
                        "match": [{ "host": ["gitea.scottkey.me"] }],
                        "handle": [{ "handler": "subroute", "routes": [
                            { "handle": [{ "handler": "reverse_proxy",
                                           "upstreams": [{ "dial": "10.0.0.20:3000" }] }] }
                        ]}],
                        "terminal": true
                    },
                    {
                        "match": [{ "host": ["a.scottkey.me", "b.scottkey.me"] }],
                        "handle": [{ "handler": "subroute", "routes": [
                            { "handle": [{ "handler": "reverse_proxy",
                                           "upstreams": [{ "dial": "10.0.0.21:80" }] }] }
                        ]}],
                        "terminal": true
                    },
                    {
                        "match": [{ "host": ["*.scottkey.me"] }],
                        "handle": [{ "handler": "subroute", "routes": [
                            { "match": [{ "host": ["jelly.scottkey.me"] }],
                              "handle": [{ "handler": "reverse_proxy",
                                           "upstreams": [{ "dial": "10.0.0.30:8096" }] }] },
                            { "handle": [{ "handler": "static_response", "abort": true }] }
                        ]}],
                        "terminal": true
                    }
                ]}
            }}}
        })
    }

    fn routes(cfg: &Value) -> &Vec<Value> {
        cfg["apps"]["http"]["servers"]["srv0"]["routes"]
            .as_array()
            .unwrap()
    }

    #[test]
    fn list_attributes_nested_matchers_to_their_own_hosts() {
        let listed = list_routes(&caddyfile_style());
        let find = |h: &str| {
            listed
                .iter()
                .find(|r| r.hosts == vec![h.to_string()])
                .unwrap()
                .clone()
        };
        assert_eq!(find("gitea.scottkey.me").upstreams, vec!["10.0.0.20:3000"]);
        assert!(!find("gitea.scottkey.me").nested);
        let jelly = find("jelly.scottkey.me");
        assert_eq!(jelly.upstreams, vec!["10.0.0.30:8096"]);
        assert!(jelly.nested);
        assert!(listed
            .iter()
            .all(|r| r.hosts != vec!["*.scottkey.me".to_string()]));
    }

    #[test]
    fn choose_server_picks_sole_and_rejects_missing() {
        let cfg = sample();
        assert_eq!(choose_server(&cfg, None).unwrap(), "srv0");
        assert_eq!(choose_server(&cfg, Some("srv0")).unwrap(), "srv0");
        assert!(choose_server(&cfg, Some("nope")).is_err());
        assert!(choose_server(&json!({}), None).is_err());
    }

    #[test]
    fn upsert_updates_existing_host_in_place() {
        let mut cfg = sample();
        let e = upsert_route(&mut cfg, "srv0", "a.example.com", &["10.0.0.9:80".into()]).unwrap();
        assert_eq!(e.action, RouteAction::Updated);
        assert_eq!(e.index, 0);
        assert_eq!(routes(&cfg).len(), 2);
        assert_eq!(
            route_upstreams(&routes(&cfg)[0]).unwrap(),
            vec!["10.0.0.9:80"]
        );
        assert_eq!(e.changes[0].path, "/apps/http/servers/srv0/routes/0");
    }

    #[test]
    fn subroute_proxy_is_updated() {
        let mut cfg = caddyfile_style();
        upsert_route(
            &mut cfg,
            "srv0",
            "gitea.scottkey.me",
            &["10.0.0.22:3000".into()],
        )
        .unwrap();
        assert_eq!(
            routes(&cfg)[0]["handle"][0]["routes"][0]["handle"][0]["upstreams"],
            json!([{ "dial": "10.0.0.22:3000" }])
        );
    }

    #[test]
    fn new_host_is_inserted_before_a_shadowing_wildcard() {
        let mut cfg = caddyfile_style();
        let e = upsert_route(
            &mut cfg,
            "srv0",
            "orca.scottkey.me",
            &["10.0.0.6:12000".into()],
        )
        .unwrap();
        assert_eq!(e.action, RouteAction::Inserted);
        assert_eq!(e.index, 2);
        assert_eq!(route_hosts(&routes(&cfg)[2]), vec!["orca.scottkey.me"]);
        assert_eq!(route_hosts(&routes(&cfg)[3]), vec!["*.scottkey.me"]);
        assert!(e.changes[0].before.is_none());
    }

    #[test]
    fn new_host_is_inserted_before_a_catch_all() {
        let mut cfg = sample();
        cfg["apps"]["http"]["servers"]["srv0"]["routes"]
            .as_array_mut()
            .unwrap()
            .insert(1, json!({"handle": [{"handler": "file_server"}]}));
        let e = upsert_route(&mut cfg, "srv0", "b.example.com", &["10.0.0.7:80".into()]).unwrap();
        assert_eq!(e.index, 1);
    }

    #[test]
    fn missing_routes_array_is_created() {
        let mut cfg = json!({"apps": {"http": {"servers": {"srv0": {"listen": [":443"]}}}}});
        let e = upsert_route(&mut cfg, "srv0", "b.example.com", &["10.0.0.7:80".into()]).unwrap();
        assert_eq!(e.index, 0);
        assert_eq!(routes(&cfg).len(), 1);
    }

    #[test]
    fn upsert_is_idempotent() {
        let mut cfg = sample();
        upsert_route(&mut cfg, "srv0", "b.example.com", &["10.0.0.7:80".into()]).unwrap();
        let once = cfg.clone();
        let e = upsert_route(&mut cfg, "srv0", "B.example.com", &["10.0.0.7:80".into()]).unwrap();
        assert_eq!(e.action, RouteAction::Unchanged);
        assert!(e.changes.is_empty());
        assert_eq!(cfg, once);
    }

    #[test]
    fn upsert_refuses_shared_multi_proxy_or_non_proxy_routes() {
        let e = upsert_route(
            &mut caddyfile_style(),
            "srv0",
            "a.scottkey.me",
            &["x:1".into()],
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("b.scottkey.me"), "{e}");
        let mut cfg = caddyfile_style();
        let sub = &mut cfg["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"];
        let extra = sub[0].clone();
        sub.as_array_mut().unwrap().push(extra);
        let e = upsert_route(&mut cfg, "srv0", "gitea.scottkey.me", &["x:1".into()])
            .unwrap_err()
            .to_string();
        assert!(e.contains("2 reverse_proxy handlers"), "{e}");
        let e = upsert_route(&mut sample(), "srv0", "static.example.com", &["x:1".into()])
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a reverse proxy"), "{e}");
    }

    fn with_matchers(m: Value) -> Value {
        let mut cfg = sample();
        cfg["apps"]["http"]["servers"]["srv0"]["routes"][0]["match"] = m;
        cfg
    }

    #[test]
    fn routes_with_extra_conditions_are_refused_for_upsert_and_delete() {
        for m in [
            json!([{ "host": ["a.example.com"], "path": ["/api/*"] }]),
            json!([{ "host": ["a.example.com"] }, { "method": ["GET"] }]),
            json!([{ "host": ["a.example.com"], "header": {"X": ["1"]} }]),
        ] {
            let mut cfg = with_matchers(m.clone());
            let before = cfg.clone();
            let e = upsert_route(&mut cfg, "srv0", "a.example.com", &["x:1".into()])
                .unwrap_err()
                .to_string();
            assert!(e.contains("other conditions"), "{m}: {e}");
            let e = delete_route(&mut cfg, "srv0", "a.example.com")
                .unwrap_err()
                .to_string();
            assert!(e.contains("other conditions"), "{m}: {e}");
            assert_eq!(cfg, before);
        }
    }

    #[test]
    fn nested_host_matchers_are_refused_for_upsert_and_delete() {
        let mut cfg = caddyfile_style();
        let e = upsert_route(&mut cfg, "srv0", "jelly.scottkey.me", &["x:1".into()])
            .unwrap_err()
            .to_string();
        assert!(e.contains("subroute of route 2"), "{e}");
        let e = delete_route(&mut cfg, "srv0", "jelly.scottkey.me")
            .unwrap_err()
            .to_string();
        assert!(e.contains("subroute of route 2"), "{e}");
    }

    #[test]
    fn delete_removes_an_exclusive_route() {
        let mut cfg = sample();
        let e = delete_route(&mut cfg, "srv0", "a.example.com").unwrap();
        assert_eq!(e.action, RouteAction::Removed);
        assert_eq!(routes(&cfg).len(), 1);
        assert!(e.changes[0].after.is_none());
        assert!(delete_route(&mut sample(), "srv0", "missing.example.com").is_err());
    }

    #[test]
    fn delete_of_a_shared_route_only_drops_the_host() {
        let mut cfg = caddyfile_style();
        let e = delete_route(&mut cfg, "srv0", "A.scottkey.me").unwrap();
        assert_eq!(e.action, RouteAction::HostDropped);
        assert_eq!(route_hosts(&routes(&cfg)[1]), vec!["b.scottkey.me"]);
        assert_eq!(
            route_upstreams(&routes(&cfg)[1]).unwrap(),
            vec!["10.0.0.21:80"]
        );
    }

    #[test]
    fn delete_drops_an_emptied_host_matcher_set() {
        let mut cfg =
            with_matchers(json!([{ "host": ["a.example.com"] }, { "host": ["c.example.com"] }]));
        delete_route(&mut cfg, "srv0", "a.example.com").unwrap();
        assert_eq!(
            routes(&cfg)[0]["match"],
            json!([{ "host": ["c.example.com"] }])
        );
    }
}
