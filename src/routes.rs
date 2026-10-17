#![allow(clippy::disallowed_types)]

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Map, Value};

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

pub fn upsert_route(config: &Value, server: &str, host: &str, upstreams: &[String]) -> Value {
    let mut routes = server_routes_owned(config, server);
    let dials: Vec<Value> = upstreams.iter().map(|u| json!({ "dial": u })).collect();
    if let Some(route) = routes
        .iter_mut()
        .find(|r| route_upstreams(r).is_some() && route_matches_host(r, host))
    {
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
    Value::Array(routes)
}

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

pub(crate) fn route_upstreams(route: &Value) -> Option<Vec<String>> {
    let handlers = route.get("handle")?.as_array()?;
    let mut found = false;
    let mut dials = Vec::new();
    for h in handlers {
        if h.get("handler").and_then(Value::as_str) == Some("reverse_proxy") {
            found = true;
            for u in h
                .get("upstreams")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(d) = u.get("dial").and_then(Value::as_str) {
                    dials.push(d.to_string());
                }
            }
        }
    }
    found.then_some(dials)
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
        let routes = upsert_route(&sample(), "srv0", "a.example.com", &["10.0.0.9:80".into()]);
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
        );
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
}
