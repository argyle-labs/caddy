#![allow(clippy::disallowed_types)]

pub mod api;
pub mod routes;
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

    #[derive(Debug, Clone)]
    struct Call {
        method: String,
        path: String,
        headers: String,
        body: Value,
    }

    fn serve<F>(
        route: impl Fn(&str, &str) -> Option<(u16, Vec<(String, String)>, String)> + 'static,
        body: F,
    ) -> Vec<Call>
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
        route: impl Fn(&str, &str) -> Option<(u16, Vec<(String, String)>, String)> + 'static,
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
}
