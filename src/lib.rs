#![allow(clippy::disallowed_types)]

pub mod api;
pub mod routes;
pub mod tls;
pub mod tools;

use plugin_toolkit::clap;

use plugin_toolkit::service::{
    BoxFuture, Routes, Runtime, ServiceBackend, ServiceCapability, ServiceError, ServiceStatus,
    WorkloadSpec,
};

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

    fn data_paths(&self) -> Vec<String> {
        vec!["/config".to_string(), "/data".to_string()]
    }

    fn workload_spec<'a>(
        &'a self,
        _runtime: Runtime,
        _instance: &'a str,
        _routes: &'a Routes,
    ) -> BoxFuture<'a, Result<WorkloadSpec, ServiceError>> {
        Box::pin(async move { Err(ServiceError::unimplemented("caddy.workload_spec")) })
    }

    fn configure<'a>(
        &'a self,
        _instance: &'a str,
        _routes: &'a Routes,
        _config: &'a str,
    ) -> BoxFuture<'a, Result<(), ServiceError>> {
        Box::pin(async move { Err(ServiceError::unimplemented("caddy.configure")) })
    }

    fn status<'a>(
        &'a self,
        _instance: &'a str,
        _routes: &'a Routes,
    ) -> BoxFuture<'a, Result<ServiceStatus, ServiceError>> {
        Box::pin(async move { Err(ServiceError::unimplemented("caddy.status")) })
    }
}

#[plugin_toolkit::endpoint_resource(plugin = "caddy")]
pub struct CaddyEndpoint {
    pub name: String,
    #[secret]
    pub api_key: String,
    pub enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::serde_json::{self, json, Value};
    use std::sync::{Arc, Mutex};

    const KEY: &str = "caddykey-0123456789abcdef";

    type Reply = Option<(u16, Vec<(String, String)>, String)>;

    #[derive(Debug, Clone)]
    struct Call {
        method: String,
        path: String,
        headers: String,
        body: Value,
    }

    fn serve<F>(route: impl Fn(&str, &str) -> Reply + 'static, body: F) -> Vec<Call>
    where
        F: FnOnce(),
    {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |cap: &str, req: &str| {
                assert_eq!(cap, "http.request");
                let req: Value = serde_json::from_str(req).unwrap();
                let url = req["url"].as_str().unwrap();
                let path = url
                    .strip_prefix("http://c.test/")
                    .unwrap_or_else(|| panic!("unexpected url {url}"))
                    .to_string();
                let method = req["method"].as_str().unwrap().to_string();
                let body = match req["body"].as_array() {
                    Some(b) if !b.is_empty() => {
                        let bytes: Vec<u8> = b.iter().map(|x| x.as_u64().unwrap() as u8).collect();
                        serde_json::from_slice(&bytes).unwrap()
                    }
                    _ => Value::Null,
                };
                log.lock().unwrap().push(Call {
                    method: method.clone(),
                    path: path.clone(),
                    headers: req["headers"].to_string(),
                    body,
                });
                let (status, headers, body) =
                    route(&method, &path).unwrap_or((404, vec![], "Not Found".into()));
                Ok(
                    json!({"status": status, "headers": headers, "body": body.into_bytes()})
                        .to_string(),
                )
            }),
            body,
        );
        let out = seen.lock().unwrap().clone();
        out
    }

    fn block<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    fn c() -> api::Caddy {
        api::Caddy::new("http://c.test/", Some(KEY)).unwrap()
    }

    fn etag(tag: &str) -> Vec<(String, String)> {
        vec![("Etag".into(), tag.into())]
    }

    fn sample() -> Value {
        json!({
            "apps": { "http": { "servers": {
                "srv0": { "listen": [":443"], "routes": [
                    {
                        "match": [{ "host": ["a.example.com"] }],
                        "handle": [{ "handler": "reverse_proxy",
                                     "upstreams": [{ "dial": "10.0.0.5:8080" }] }],
                        "terminal": true
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
    fn config_reads_body_and_etag_with_bearer() {
        let mut snap = None;
        let calls = serve(
            |_, _| Some((200, etag(r#""/config/ abc""#), sample().to_string())),
            || snap = Some(block(c().config()).unwrap()),
        );
        let snap = snap.unwrap();
        assert_eq!(snap.config, sample());
        assert_eq!(snap.etag.as_deref(), Some(r#""/config/ abc""#));
        assert_eq!(calls[0].method, "GET");
        assert_eq!(calls[0].path, "config/");
        assert!(
            calls[0].headers.contains(&format!("Bearer {KEY}")),
            "{}",
            calls[0].headers
        );
    }

    #[test]
    fn empty_config_reads_as_an_object() {
        serve(
            |_, _| Some((200, vec![], "null\n".into())),
            || assert_eq!(block(c().config()).unwrap().config, json!({})),
        );
    }

    #[test]
    fn no_api_key_sends_no_authorization() {
        let calls = serve(
            |_, _| Some((200, vec![], "{}".into())),
            || {
                block(api::Caddy::new("http://c.test", None).unwrap().config()).unwrap();
            },
        );
        assert!(
            !calls[0].headers.to_lowercase().contains("authorization"),
            "{}",
            calls[0].headers
        );
    }

    #[test]
    fn patch_sends_if_match_and_body() {
        let calls = serve(
            |_, _| Some((200, vec![], String::new())),
            || {
                block(c().patch(
                    "apps/http/servers/srv0/routes",
                    &json!([]),
                    Some("\"/config/ abc\""),
                ))
                .unwrap()
            },
        );
        assert_eq!(calls[0].method, "PATCH");
        assert_eq!(calls[0].path, "config/apps/http/servers/srv0/routes");
        assert_eq!(calls[0].body, json!([]));
        assert!(
            calls[0].headers.contains("if-match"),
            "{}",
            calls[0].headers
        );
    }

    #[test]
    fn precondition_failed_reports_a_concurrent_change() {
        let e = serve_err(
            |_, _| Some((412, vec![], "etag mismatch".into())),
            |c| block(c.patch("apps", &json!({}), Some("\"x\""))).unwrap_err(),
        );
        assert!(e.contains("changed concurrently"), "{e}");
    }

    #[test]
    fn load_forces_a_reload() {
        let calls = serve(
            |_, _| Some((200, vec![], String::new())),
            || block(c().load(&sample())).unwrap(),
        );
        assert_eq!(calls[0].method, "POST");
        assert_eq!(calls[0].path, "load");
        assert!(
            calls[0].headers.contains("must-revalidate"),
            "{}",
            calls[0].headers
        );
        assert_eq!(calls[0].body, sample());
    }

    fn serve_err(
        route: impl Fn(&str, &str) -> Reply + 'static,
        f: impl FnOnce(api::Caddy) -> plugin_toolkit::anyhow::Error,
    ) -> String {
        let mut out = String::new();
        serve(route, || out = format!("{:#}", f(c())));
        out
    }

    #[test]
    fn api_errors_are_redacted_scrubbed_and_truncated() {
        let e = serve_err(
            |_, _| {
                Some((
                    400,
                    vec![],
                    format!(
                        r#"{{"error":"bad {KEY}","api_token":"cf-secret-value"}}{}"#,
                        "x".repeat(api::ERROR_EXCERPT * 2)
                    ),
                ))
            },
            |c| block(c.config()).unwrap_err(),
        );
        assert!(e.starts_with("GET /config/: HTTP 400"), "{e}");
        assert!(!e.contains(KEY), "{e}");
        assert!(!e.contains("cf-secret-value"), "{e}");
        assert!(e.len() < api::ERROR_EXCERPT + 64, "{}", e.len());
    }

    #[test]
    fn transport_errors_are_redacted() {
        let e = plugin_toolkit::capsink::with_cap_sink(
            Box::new(|_: &str, _: &str| Err(format!("connect refused Bearer {KEY}"))),
            || format!("{:#}", block(c().config()).unwrap_err()),
        );
        assert!(e.starts_with("GET /config/:"), "{e}");
        assert!(!e.contains(KEY), "{e}");
    }

    #[test]
    fn upstream_count_counts_entries() {
        serve(
            |_, p| {
                (p == "reverse_proxy/upstreams").then(|| {
                    (
                        200,
                        vec![],
                        json!([{"address": "10.0.0.5:8080"}, {"address": "x:1"}]).to_string(),
                    )
                })
            },
            || assert_eq!(block(c().upstream_count()).unwrap(), 2),
        );
    }

    #[test]
    fn missing_api_key_secret_means_no_auth() {
        let out = plugin_toolkit::capsink::with_cap_sink(
            Box::new(|cap: &str, _: &str| match cap {
                "secret.op" => Ok(json!({"value": null, "found": false}).to_string()),
                _ => Err(format!("unexpected {cap}")),
            }),
            || tools::api_key("edge").unwrap(),
        );
        assert!(out.is_none());
    }

    #[test]
    fn api_key_lookup_failure_is_an_error() {
        let e = plugin_toolkit::capsink::with_cap_sink(
            Box::new(|_: &str, _: &str| Err("store offline".into())),
            || tools::api_key("edge").unwrap_err(),
        );
        assert!(format!("{e:#}").contains("store offline"), "{e:#}");
    }

    #[test]
    fn dry_run_writes_make_no_request() {
        let cfg = Arc::new(plugin_toolkit::contract::config::Config::load().unwrap());
        let ctx = plugin_toolkit::contract::ToolCtx::new(cfg);
        let caps = Arc::new(Mutex::new(Vec::new()));
        let log = caps.clone();
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(move |cap: &str, _: &str| {
                log.lock().unwrap().push(cap.to_string());
                Err(format!("unexpected {cap}"))
            }),
            || {
                for (tool, args) in [
                    ("caddy.reload", json!({"name": "edge", "dryRun": true})),
                    (
                        "caddy.route.set",
                        json!({"name": "edge", "host": "a.example.com", "upstream": ["10.0.0.5:80"], "dryRun": true}),
                    ),
                    (
                        "caddy.route.delete",
                        json!({"name": "edge", "host": "a.example.com", "dryRun": true}),
                    ),
                    (
                        "caddy.tls.ensure",
                        json!({"name": "edge", "host": "a.example.com", "dryRun": true}),
                    ),
                    (
                        "caddy.config.persist",
                        json!({"name": "edge", "dryRun": true}),
                    ),
                ] {
                    let out = block(plugin_toolkit::dispatch::dispatch(tool, args, &ctx))
                        .unwrap_or_else(|e| panic!("{tool}: {e:#}"));
                    assert_eq!(out["dryRun"], json!(true), "{tool}: {out}");
                }
            },
        );
        assert!(
            caps.lock().unwrap().is_empty(),
            "{:?}",
            caps.lock().unwrap()
        );
    }

    fn live() -> Value {
        json!({
            "apps": {
                "http": { "servers": { "srv0": { "listen": [":443"], "routes": [
                    {
                        "match": [{ "host": ["gitea.scottkey.me"] }],
                        "handle": [{ "handler": "subroute", "routes": [
                            { "handle": [{ "handler": "reverse_proxy",
                                           "upstreams": [{ "dial": "10.0.0.20:3000" }] }] }
                        ]}],
                        "terminal": true
                    }
                ]}}},
                "tls": { "automation": { "policies": [
                    { "subjects": ["gitea.scottkey.me"],
                      "issuers": [{ "module": "acme", "challenges": { "dns": { "provider":
                          { "name": "cloudflare", "api_token": "cf-literal-token" } } } }] }
                ]}}
            }
        })
    }

    fn stateful(initial: Value) -> (Arc<Mutex<Value>>, impl Fn(&str, &str) -> Reply + 'static) {
        let state = Arc::new(Mutex::new(initial));
        let s = state.clone();
        let route = move |method: &str, path: &str| {
            let cfg = s.lock().unwrap().clone();
            match (method, path) {
                ("GET", "config/") => {
                    let tag = format!("\"/config/ {:x}\"", cfg.to_string().len());
                    Some((200, etag(&tag), cfg.to_string()))
                }
                ("PATCH", _) | ("PUT", _) => Some((200, vec![], String::new())),
                _ => None,
            }
        };
        (state, route)
    }

    fn apply(state: &Arc<Mutex<Value>>, calls: &[Call]) {
        let mut cfg = state.lock().unwrap();
        for call in calls.iter().filter(|c| c.method != "GET") {
            let ptr = format!("/{}", call.path.trim_start_matches("config/"));
            *cfg.pointer_mut(&ptr).unwrap() = call.body.clone();
        }
    }

    fn set_args() -> tools::RouteSetArgs {
        tools::RouteSetArgs {
            name: "edge".into(),
            host: "orca.scottkey.me".into(),
            upstream: vec!["10.0.0.6:12000".into()],
            server: None,
        }
    }

    #[test]
    fn route_set_adds_the_tls_subject_then_the_route() {
        let (state, route) = stateful(live());
        let mut out = None;
        let calls = serve(route, || {
            out = Some(block(tools::set_route(&c(), &set_args())).unwrap())
        });
        let out = out.unwrap();
        assert!(out.changed);
        assert_eq!(out.tls.action, tls::TlsAction::SubjectAdded);
        let writes: Vec<&Call> = calls.iter().filter(|c| c.method != "GET").collect();
        assert_eq!(writes.len(), 2, "{calls:?}");
        assert_eq!(writes[0].method, "PATCH");
        assert_eq!(
            writes[0].path,
            "config/apps/tls/automation/policies/0/subjects"
        );
        assert_eq!(
            writes[0].body,
            json!(["gitea.scottkey.me", "orca.scottkey.me"])
        );
        assert_eq!(writes[1].path, "config/apps/http/servers/srv0/routes");
        assert_eq!(
            writes[1].body[1]["match"],
            json!([{ "host": ["orca.scottkey.me"] }])
        );
        assert_eq!(
            writes[1].body[1]["handle"][0]["upstreams"],
            json!([{ "dial": "10.0.0.6:12000" }])
        );
        for w in writes {
            assert!(w.headers.contains("if-match"), "{}", w.headers);
        }
        apply(&state, &calls);
        let calls = serve(stateful(state.lock().unwrap().clone()).1, || {
            let again = block(tools::set_route(&c(), &set_args())).unwrap();
            assert!(!again.changed);
            assert_eq!(again.tls.action, tls::TlsAction::Covered);
        });
        assert!(calls.iter().all(|c| c.method == "GET"), "{calls:?}");
    }

    #[test]
    fn route_set_creates_a_missing_routes_array() {
        let mut cfg = live();
        cfg["apps"]["http"]["servers"]["srv0"]
            .as_object_mut()
            .unwrap()
            .remove("routes");
        let (_, route) = stateful(cfg);
        let calls = serve(route, || {
            block(tools::set_route(&c(), &set_args())).unwrap();
        });
        let last = calls.last().unwrap();
        assert_eq!(last.method, "PUT");
        assert_eq!(last.path, "config/apps/http/servers/srv0/routes");
    }

    #[test]
    fn route_set_rejects_bad_input_before_any_request() {
        let calls = serve(
            |_, _| None,
            || {
                let mut a = set_args();
                a.upstream = vec!["10.0.0.6".into()];
                assert!(block(tools::set_route(&c(), &a)).is_err());
                let mut a = set_args();
                a.host = "orca.scottkey.me/x".into();
                assert!(block(tools::set_route(&c(), &a)).is_err());
            },
        );
        assert!(calls.is_empty(), "{calls:?}");
    }

    #[test]
    fn route_delete_writes_the_trimmed_routes() {
        let (_, route) = stateful(live());
        let calls = serve(route, || {
            let args = tools::RouteDeleteArgs {
                name: "edge".into(),
                host: "gitea.scottkey.me".into(),
                server: None,
            };
            block(tools::delete_route(&c(), &args)).unwrap();
        });
        let last = calls.last().unwrap();
        assert_eq!(last.method, "PATCH");
        assert_eq!(last.body, json!([]));
    }

    #[test]
    fn persist_only_rewrites_an_explicit_false() {
        let (_, route) = stateful(live());
        let calls = serve(route, || {
            assert!(!block(tools::persist(&c())).unwrap().changed);
        });
        assert!(calls.iter().all(|c| c.method == "GET"));
        let mut cfg = live();
        cfg["admin"] = json!({"config": {"persist": false}});
        let (_, route) = stateful(cfg);
        let calls = serve(route, || {
            assert!(block(tools::persist(&c())).unwrap().changed);
        });
        let last = calls.last().unwrap();
        assert_eq!(last.path, "config/admin/config/persist");
        assert_eq!(last.body, json!(true));
    }

    #[test]
    fn config_redaction_hides_dns_tokens_and_reads_are_lossless() {
        let redacted = plugin_toolkit::scrub::redact_json(live());
        assert!(!redacted.to_string().contains("cf-literal-token"));
        let (_, route) = stateful(live());
        serve(route, || {
            assert_eq!(block(c().config()).unwrap().config, live());
        });
    }
}
