#![allow(clippy::disallowed_types)]

pub mod api;
pub mod redact;
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

#[plugin_toolkit::endpoint_resource(plugin = "caddy", skip = "list,detail")]
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
        let e = plugin_toolkit::capsink::with_cap_sink(
            Box::new(|_: &str, _: &str| {
                Ok(json!({"status": 412, "headers": [], "body": []}).to_string())
            }),
            || block(c().patch("apps", &json!({}), None)).unwrap_err(),
        );
        assert!(api::is_conflict(&e));
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
    fn write_verbs_accept_dry_run() {
        let cfg = Arc::new(plugin_toolkit::contract::config::Config::load().unwrap());
        let ctx = plugin_toolkit::contract::ToolCtx::new(cfg);
        plugin_toolkit::capsink::with_cap_sink(
            Box::new(|cap: &str, _: &str| Err(format!("unexpected {cap}"))),
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
                    let e =
                        block(plugin_toolkit::dispatch::dispatch(tool, args, &ctx)).unwrap_err();
                    let e = format!("{e:#}");
                    assert!(!e.contains("does not support dryRun"), "{tool}: {e}");
                    assert!(e.contains("unexpected secret.op"), "{tool}: {e}");
                }
            },
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
                    },
                    {
                        "match": [{ "host": ["static.scottkey.me"], "path": ["/x"] }],
                        "handle": [{ "handler": "reverse_proxy",
                                     "upstreams": [{ "dial": "10.0.0.21:80" }] }]
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

    struct Fake {
        state: Arc<Mutex<Value>>,
        conflicts: Arc<Mutex<usize>>,
    }

    impl Fake {
        fn new(initial: Value, conflicts: usize) -> Self {
            Self {
                state: Arc::new(Mutex::new(initial)),
                conflicts: Arc::new(Mutex::new(conflicts)),
            }
        }

        fn route(&self) -> impl Fn(&str, &str) -> Reply + 'static {
            let state = self.state.clone();
            let conflicts = self.conflicts.clone();
            move |method: &str, path: &str| {
                let cfg = state.lock().unwrap().clone();
                let tag = format!("\"/config/ {:x}\"", cfg.to_string().len());
                match (method, path) {
                    ("GET", "config/") => Some((200, etag(&tag), cfg.to_string())),
                    ("PATCH", _) | ("PUT", _) => {
                        let mut left = conflicts.lock().unwrap();
                        if *left > 0 {
                            *left -= 1;
                            return Some((412, vec![], String::new()));
                        }
                        Some((200, vec![], String::new()))
                    }
                    _ => None,
                }
            }
        }

        fn serve(&self, f: impl FnOnce()) -> Vec<Call> {
            let calls = serve(self.route(), f);
            let mut cfg = self.state.lock().unwrap();
            for call in calls.iter().filter(|c| c.method != "GET") {
                let key = call.path.trim_start_matches("config/").to_string();
                cfg[key] = call.body.clone();
            }
            calls
        }

        fn config(&self) -> Value {
            self.state.lock().unwrap().clone()
        }
    }

    fn writes(calls: &[Call]) -> Vec<&Call> {
        calls.iter().filter(|c| c.method != "GET").collect()
    }

    fn set_args() -> tools::RouteSetArgs {
        tools::RouteSetArgs {
            name: "edge".into(),
            host: "Orca.ScottKey.me".into(),
            upstream: vec!["10.0.0.6:12000".into()],
            server: None,
        }
    }

    #[test]
    fn route_set_writes_tls_and_route_atomically() {
        let fake = Fake::new(live(), 0);
        let mut out = None;
        let calls =
            fake.serve(|| out = Some(block(tools::set_route(&c(), &set_args(), false)).unwrap()));
        let out = out.unwrap();
        assert!(out.changed && !out.dry_run);
        assert_eq!(out.route.hosts, vec!["orca.scottkey.me"]);
        assert_eq!(out.action, routes::RouteAction::Inserted);
        assert_eq!(out.tls.action, tls::TlsAction::SubjectAdded);
        assert_eq!(out.tls.challenge, tls::Challenge::Dns01);
        let w = writes(&calls);
        assert_eq!(w.len(), 1, "{calls:?}");
        assert_eq!(
            (w[0].method.as_str(), w[0].path.as_str()),
            ("PATCH", "config/apps")
        );
        assert!(w[0].headers.contains("if-match"), "{}", w[0].headers);
        assert_eq!(
            w[0].body["tls"]["automation"]["policies"][0]["subjects"],
            json!(["gitea.scottkey.me", "orca.scottkey.me"])
        );
        assert_eq!(
            w[0].body["tls"]["automation"]["policies"][0]["issuers"][0]["challenges"]["dns"]
                ["provider"]["api_token"],
            json!("cf-literal-token")
        );
        assert_eq!(
            w[0].body["http"]["servers"]["srv0"]["routes"][2]["match"],
            json!([{ "host": ["orca.scottkey.me"] }])
        );
        let report = serde_json::to_string(&out).unwrap();
        assert!(!report.contains("cf-literal-token"), "{report}");
        assert!(report.contains("\"dryRun\":false"), "{report}");

        let calls = fake.serve(|| {
            let again = block(tools::set_route(&c(), &set_args(), false)).unwrap();
            assert!(!again.changed);
            assert_eq!(again.action, routes::RouteAction::Unchanged);
            assert_eq!(again.tls.action, tls::TlsAction::Covered);
        });
        assert!(writes(&calls).is_empty(), "{calls:?}");
    }

    #[test]
    fn route_set_dry_run_reads_and_plans_without_writing() {
        let fake = Fake::new(live(), 0);
        let mut out = None;
        let calls =
            fake.serve(|| out = Some(block(tools::set_route(&c(), &set_args(), true)).unwrap()));
        let out = out.unwrap();
        assert!(out.dry_run && out.changed);
        assert_eq!(out.index, 2);
        assert_eq!(out.changes.len(), 2);
        assert_eq!(
            out.changes[0].path,
            "/apps/tls/automation/policies/0/subjects"
        );
        assert_eq!(out.changes[1].path, "/apps/http/servers/srv0/routes/2");
        assert!(calls.iter().all(|c| c.method == "GET"), "{calls:?}");
        assert_eq!(fake.config(), live());
    }

    #[test]
    fn a_refused_route_writes_no_tls_either() {
        let fake = Fake::new(live(), 0);
        let calls = fake.serve(|| {
            let mut a = set_args();
            a.host = "static.scottkey.me".into();
            let e = block(tools::set_route(&c(), &a, false))
                .unwrap_err()
                .to_string();
            assert!(e.contains("other conditions"), "{e}");
        });
        assert!(writes(&calls).is_empty(), "{calls:?}");
        assert_eq!(fake.config(), live());
    }

    #[test]
    fn route_set_refuses_to_route_to_the_admin_api() {
        let fake = Fake::new(live(), 0);
        let calls = fake.serve(|| {
            let mut a = set_args();
            a.upstream = vec!["127.0.0.1:2019".into()];
            let e = block(tools::set_route(&c(), &a, false))
                .unwrap_err()
                .to_string();
            assert!(e.contains("admin API"), "{e}");
        });
        assert!(writes(&calls).is_empty());
    }

    #[test]
    fn concurrent_changes_are_retried_then_reported() {
        let fake = Fake::new(live(), 2);
        let calls = fake.serve(|| {
            block(tools::set_route(&c(), &set_args(), false)).unwrap();
        });
        assert_eq!(writes(&calls).len(), 3);
        assert_eq!(calls.iter().filter(|c| c.method == "GET").count(), 3);

        let fake = Fake::new(live(), tools::MAX_ATTEMPTS);
        let calls = fake.serve(|| {
            let e = block(tools::set_route(&c(), &set_args(), false)).unwrap_err();
            assert!(api::is_conflict(&e), "{e:#}");
        });
        assert_eq!(writes(&calls).len(), tools::MAX_ATTEMPTS);
    }

    #[test]
    fn route_set_rejects_bad_input_before_any_request() {
        let calls = serve(
            |_, _| None,
            || {
                for (host, up) in [
                    ("orca.scottkey.me", "10.0.0.6"),
                    ("orca.scottkey.me/x", "10.0.0.6:1"),
                    ("orca.scottkey.me", "{upstream}:80"),
                ] {
                    let mut a = set_args();
                    a.host = host.into();
                    a.upstream = vec![up.into()];
                    assert!(
                        block(tools::set_route(&c(), &a, false)).is_err(),
                        "{host} {up}"
                    );
                }
            },
        );
        assert!(calls.is_empty(), "{calls:?}");
    }

    #[test]
    fn route_delete_writes_apps_and_dry_run_does_not() {
        let args = tools::RouteDeleteArgs {
            name: "edge".into(),
            host: "gitea.scottkey.me".into(),
            server: None,
        };
        let fake = Fake::new(live(), 0);
        let calls = fake.serve(|| {
            let r = block(tools::delete_route(&c(), &args, true)).unwrap();
            assert!(r.dry_run);
            assert_eq!(r.action, routes::RouteAction::Removed);
        });
        assert!(writes(&calls).is_empty());
        let calls = fake.serve(|| {
            block(tools::delete_route(&c(), &args, false)).unwrap();
        });
        let w = writes(&calls);
        assert_eq!(w[0].path, "config/apps");
        assert_eq!(
            w[0].body["http"]["servers"]["srv0"]["routes"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn tls_ensure_adds_the_subject_and_automate_in_one_write() {
        let fake = Fake::new(live(), 0);
        let calls = fake.serve(|| {
            let r = block(tools::ensure_tls(&c(), "orca.scottkey.me", false)).unwrap();
            assert!(r.changed && r.tls.automate);
        });
        let w = writes(&calls);
        assert_eq!(w.len(), 1);
        assert_eq!(
            w[0].body["tls"]["certificates"]["automate"],
            json!(["orca.scottkey.me"])
        );
        let calls = fake.serve(|| {
            assert!(
                !block(tools::ensure_tls(&c(), "orca.scottkey.me", false))
                    .unwrap()
                    .changed
            );
        });
        assert!(writes(&calls).is_empty());
        let calls = fake.serve(|| {
            let r = block(tools::ensure_tls(&c(), "orca.other.example", false)).unwrap();
            assert_eq!(r.tls.action, tls::TlsAction::Default);
            assert!(!r.changed && !r.warnings.is_empty());
        });
        assert!(writes(&calls).is_empty());
    }

    #[test]
    fn persist_only_rewrites_an_explicit_false() {
        let fake = Fake::new(live(), 0);
        let calls = fake.serve(|| {
            assert!(!block(tools::persist(&c(), false)).unwrap().changed);
        });
        assert!(writes(&calls).is_empty());
        let mut cfg = live();
        cfg["admin"] = json!({"config": {"persist": false}});
        let fake = Fake::new(cfg, 0);
        let calls = fake.serve(|| {
            assert!(block(tools::persist(&c(), true)).unwrap().changed);
        });
        assert!(writes(&calls).is_empty());
        let calls = fake.serve(|| {
            assert!(block(tools::persist(&c(), false)).unwrap().changed);
        });
        let w = writes(&calls);
        assert_eq!(w[0].path, "config/admin");
        assert_eq!(w[0].body, json!({"config": {"persist": true}}));
    }

    #[test]
    fn reload_dry_run_only_reads() {
        let fake = Fake::new(live(), 0);
        let calls = fake.serve(|| {
            let r = block(tools::reload(&c(), true)).unwrap();
            assert!(r.dry_run && !r.reloaded);
            assert!(r.status.upstreams_error.is_some());
        });
        assert!(calls.iter().all(|c| c.method == "GET"), "{calls:?}");
    }

    #[test]
    fn export_and_get_never_return_provider_secrets() {
        let r = redact::redact_config(live());
        assert!(!r.config.0.to_string().contains("cf-literal-token"));
        assert_eq!(
            r.redacted,
            vec!["/apps/tls/automation/policies/0/issuers/0/challenges/dns/provider/api_token"]
        );
    }
}
