#![allow(clippy::disallowed_types)]

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Map, Value};

use crate::tls::host_matches;

#[orca_struct]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRoute {
    pub server: String,
    pub hosts: Vec<String>,
    pub upstreams: Vec<String>,
}

pub fn list_routes(config: &Value) -> Vec<ProxyRoute> {
    let mut out = Vec::new();
    let Some(servers) = servers_map(config) else {
        return out;
    };
    for (server, srv) in servers {
        for route in server_routes(srv) {
            if let Some(upstreams) = route_upstreams(route) {
                out.push(ProxyRoute {
                    server: server.clone(),
                    hosts: route_hosts(route),
                    upstreams,
                });
            }
        }
    }
    out
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

pub fn upsert_route(
    config: &Value,
    server: &str,
    host: &str,
    upstreams: &[String],
) -> Result<Value> {
    let mut routes = server_routes_owned(config, server);
    let dials: Vec<Value> = upstreams.iter().map(|u| json!({ "dial": u })).collect();
    if let Some(route) = routes.iter_mut().find(|r| is_proxy_for(r, host)) {
        let others = other_hosts(route, host);
        if !others.is_empty() {
            bail!(
                "the route for '{host}' also serves {}; split it before setting upstreams",
                others.join(", ")
            );
        }
        let mut found = Vec::new();
        if let Some(handle) = route.get_mut("handle") {
            proxies_mut(handle, &mut found);
        }
        match found.as_mut_slice() {
            [only] => only["upstreams"] = Value::Array(dials),
            many => bail!(
                "the route for '{host}' has {} reverse_proxy handlers; refusing to rewrite them all",
                many.len()
            ),
        }
    } else {
        let at = routes
            .iter()
            .position(|r| shadows(r, host))
            .unwrap_or(routes.len());
        routes.insert(
            at,
            json!({
                "match": [{ "host": [host] }],
                "handle": [{ "handler": "reverse_proxy", "upstreams": dials }],
                "terminal": true,
            }),
        );
    }
    Ok(Value::Array(routes))
}

pub fn delete_route(config: &Value, server: &str, host: &str) -> (Value, bool) {
    let mut routes = server_routes_owned(config, server);
    let before = routes.clone();
    routes.retain(|r| !(is_proxy_for(r, host) && other_hosts(r, host).is_empty()));
    for r in routes.iter_mut().filter(|r| is_proxy_for(r, host)) {
        if let Some(matchers) = r.get_mut("match").and_then(Value::as_array_mut) {
            for m in matchers.iter_mut() {
                if let Some(hosts) = m.get_mut("host").and_then(Value::as_array_mut) {
                    hosts.retain(|h| !h.as_str().is_some_and(|h| h.eq_ignore_ascii_case(host)));
                }
            }
            matchers.retain(|m| {
                m.get("host")
                    .and_then(Value::as_array)
                    .is_none_or(|h| !h.is_empty())
            });
        }
    }
    let removed = routes != before;
    (Value::Array(routes), removed)
}

fn servers_map(config: &Value) -> Option<&Map<String, Value>> {
    config.get("apps")?.get("http")?.get("servers")?.as_object()
}

fn server_routes(srv: &Value) -> &[Value] {
    srv.get("routes")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn server_routes_owned(config: &Value, server: &str) -> Vec<Value> {
    servers_map(config)
        .and_then(|m| m.get(server))
        .map(|s| server_routes(s).to_vec())
        .unwrap_or_default()
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

pub(crate) fn route_upstreams(route: &Value) -> Option<Vec<String>> {
    let mut found = Vec::new();
    proxies(route.get("handle")?, &mut found);
    if found.is_empty() {
        return None;
    }
    Some(
        found
            .iter()
            .filter_map(|h| h.get("upstreams").and_then(Value::as_array))
            .flatten()
            .filter_map(|u| u.get("dial").and_then(Value::as_str))
            .map(str::to_string)
            .collect(),
    )
}

pub(crate) fn route_hosts(route: &Value) -> Vec<String> {
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

fn is_proxy_for(route: &Value, host: &str) -> bool {
    route_upstreams(route).is_some()
        && route_hosts(route)
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
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

    #[test]
    fn list_routes_surfaces_only_reverse_proxy() {
        let routes = list_routes(&sample());
        assert_eq!(
            routes,
            vec![ProxyRoute {
                server: "srv0".into(),
                hosts: vec!["a.example.com".into()],
                upstreams: vec!["10.0.0.5:8080".into()],
            }]
        );
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
        let routes =
            upsert_route(&sample(), "srv0", "a.example.com", &["10.0.0.9:80".into()]).unwrap();
        let arr = routes.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(route_upstreams(&arr[0]).unwrap(), vec!["10.0.0.9:80"]);
        assert_eq!(route_hosts(&arr[1]), vec!["static.example.com"]);
    }

    #[test]
    fn upsert_appends_new_host() {
        let routes = upsert_route(
            &sample(),
            "srv0",
            "b.example.com",
            &["10.0.0.7:3000".into()],
        )
        .unwrap();
        let arr = routes.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        let last = arr.last().unwrap();
        assert_eq!(route_hosts(last), vec!["b.example.com"]);
        assert_eq!(route_upstreams(last).unwrap(), vec!["10.0.0.7:3000"]);
        assert_eq!(last["terminal"], json!(true));
    }

    #[test]
    fn delete_removes_matching_reverse_proxy_route() {
        let (routes, removed) = delete_route(&sample(), "srv0", "a.example.com");
        assert!(removed);
        let arr = routes.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(route_hosts(&arr[0]), vec!["static.example.com"]);
        assert!(!delete_route(&sample(), "srv0", "missing.example.com").1);
    }

    #[test]
    fn server_names_lists_http_servers() {
        assert_eq!(server_names(&sample()), vec!["srv0"]);
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
                        "handle": [{ "handler": "static_response", "abort": true }],
                        "terminal": true
                    }
                ]}
            }}}
        })
    }

    #[test]
    fn subroute_proxies_are_listed_and_updated() {
        let cfg = caddyfile_style();
        let listed = list_routes(&cfg);
        assert_eq!(listed[0].hosts, vec!["gitea.scottkey.me"]);
        assert_eq!(listed[0].upstreams, vec!["10.0.0.20:3000"]);
        let routes = upsert_route(
            &cfg,
            "srv0",
            "gitea.scottkey.me",
            &["10.0.0.22:3000".into()],
        )
        .unwrap();
        let arr = routes.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(
            arr[0]["handle"][0]["routes"][0]["handle"][0]["upstreams"],
            json!([{ "dial": "10.0.0.22:3000" }])
        );
    }

    #[test]
    fn new_host_is_inserted_before_a_shadowing_wildcard() {
        let routes = upsert_route(
            &caddyfile_style(),
            "srv0",
            "orca.scottkey.me",
            &["10.0.0.6:12000".into()],
        )
        .unwrap();
        let arr = routes.as_array().unwrap();
        assert_eq!(arr.len(), 4);
        assert_eq!(route_hosts(&arr[2]), vec!["orca.scottkey.me"]);
        assert_eq!(route_hosts(&arr[3]), vec!["*.scottkey.me"]);
    }

    #[test]
    fn new_host_is_inserted_before_a_catch_all() {
        let mut cfg = sample();
        cfg["apps"]["http"]["servers"]["srv0"]["routes"]
            .as_array_mut()
            .unwrap()
            .insert(1, json!({"handle": [{"handler": "file_server"}]}));
        let routes = upsert_route(&cfg, "srv0", "b.example.com", &["10.0.0.7:80".into()]).unwrap();
        assert_eq!(route_hosts(&routes[1]), vec!["b.example.com"]);
    }

    #[test]
    fn upsert_is_idempotent() {
        let once =
            upsert_route(&sample(), "srv0", "b.example.com", &["10.0.0.7:80".into()]).unwrap();
        let mut cfg = sample();
        cfg["apps"]["http"]["servers"]["srv0"]["routes"] = once.clone();
        let twice = upsert_route(&cfg, "srv0", "b.example.com", &["10.0.0.7:80".into()]).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn upsert_refuses_a_shared_or_multi_proxy_route() {
        let e = upsert_route(&caddyfile_style(), "srv0", "a.scottkey.me", &["x:1".into()])
            .unwrap_err()
            .to_string();
        assert!(e.contains("b.scottkey.me"), "{e}");
        let mut cfg = caddyfile_style();
        let sub = &mut cfg["apps"]["http"]["servers"]["srv0"]["routes"][0]["handle"][0]["routes"];
        let extra = sub[0].clone();
        sub.as_array_mut().unwrap().push(extra);
        let e = upsert_route(&cfg, "srv0", "gitea.scottkey.me", &["x:1".into()])
            .unwrap_err()
            .to_string();
        assert!(e.contains("2 reverse_proxy handlers"), "{e}");
    }

    #[test]
    fn delete_of_a_shared_route_only_drops_the_host() {
        let (routes, removed) = delete_route(&caddyfile_style(), "srv0", "A.scottkey.me");
        assert!(removed);
        let arr = routes.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(route_hosts(&arr[1]), vec!["b.scottkey.me"]);
        assert_eq!(route_upstreams(&arr[1]).unwrap(), vec!["10.0.0.21:80"]);
    }

    #[test]
    fn delete_never_widens_a_matcher() {
        let mut cfg = sample();
        cfg["apps"]["http"]["servers"]["srv0"]["routes"][0]["match"] =
            json!([{ "host": ["a.example.com"], "path": ["/x"] }, { "host": ["c.example.com"] }]);
        let (routes, removed) = delete_route(&cfg, "srv0", "a.example.com");
        assert!(removed);
        assert_eq!(routes[0]["match"], json!([{ "host": ["c.example.com"] }]));
    }
}
