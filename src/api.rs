#![allow(clippy::disallowed_types)]

use plugin_toolkit::api_client::ApiClientBuilder;
use plugin_toolkit::prelude::*;
use plugin_toolkit::reqwest::{Client as HttpClient, RequestBuilder};
use plugin_toolkit::serde_json::{self, Value};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub struct Caddy {
    base_url: String,
    api_key: Option<String>,
    http: HttpClient,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Snapshot {
    pub config: Value,
    pub etag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    pub op: String,
}

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: config changed concurrently (HTTP 412)", self.op)
    }
}

impl std::error::Error for Conflict {}

pub fn is_conflict(e: &plugin_toolkit::anyhow::Error) -> bool {
    e.downcast_ref::<Conflict>().is_some()
}

impl Caddy {
    pub fn new(base_url: &str, api_key: Option<&str>) -> Result<Self> {
        let api_key = api_key.filter(|k| !k.is_empty()).map(str::to_string);
        let mut builder =
            ApiClientBuilder::new().timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS));
        if let Some(key) = &api_key {
            builder = builder
                .bearer(key)
                .map_err(|_| anyhow!("api_key is not a valid header value"))?;
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
            http: builder.build()?,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url, path.trim_start_matches('/'))
    }

    fn config_url(&self, path: &str) -> String {
        self.url(&format!("config/{}", path.trim_start_matches('/')))
    }

    async fn send(&self, req: RequestBuilder, op: &str) -> Result<(Option<String>, String)> {
        let resp = req
            .send()
            .await
            .map_err(|e| anyhow!("{op}: {}", self.excerpt(&e.to_string())))?;
        let status = resp.status().as_u16();
        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let body = resp
            .text()
            .await
            .map_err(|e| anyhow!("{op}: {}", self.excerpt(&e.to_string())))?;
        if status == 412 {
            return Err(Conflict { op: op.to_string() }.into());
        }
        if !(200..300).contains(&status) {
            bail!("{op}: HTTP {status} {}", self.excerpt(&body));
        }
        Ok((etag, body))
    }

    fn if_match(req: RequestBuilder, etag: Option<&str>) -> Result<RequestBuilder> {
        Ok(match etag {
            Some(tag) => req.header(
                "if-match",
                plugin_toolkit::reqwest::header::HeaderValue::from_str(tag)
                    .map_err(|_| anyhow!("invalid etag"))?,
            ),
            None => req,
        })
    }

    pub async fn config(&self) -> Result<Snapshot> {
        let (etag, body) = self
            .send(self.http.get(self.config_url("")), "GET /config/")
            .await?;
        let config = match body.trim() {
            "" | "null" => json!({}),
            text => serde_json::from_str(text)
                .map_err(|e| anyhow!("GET /config/: unexpected response: {e}"))?,
        };
        Ok(Snapshot { config, etag })
    }

    pub async fn replace(&self, config: &Value, etag: Option<&str>) -> Result<()> {
        let req = self
            .http
            .post(self.config_url(""))
            .header(
                "cache-control",
                plugin_toolkit::reqwest::header::HeaderValue::from_static("must-revalidate"),
            )
            .json(config);
        let req = Self::if_match(req, etag)?;
        self.send(req, "POST /config/").await.map(drop)
    }

    pub async fn patch(&self, path: &str, value: &Value, etag: Option<&str>) -> Result<()> {
        let op = format!("PATCH /config/{path}");
        let req = Self::if_match(self.http.patch(self.config_url(path)).json(value), etag)?;
        self.send(req, &op).await.map(drop)
    }

    pub async fn put(&self, path: &str, value: &Value, etag: Option<&str>) -> Result<()> {
        let op = format!("PUT /config/{path}");
        let req = Self::if_match(self.http.put(self.config_url(path)).json(value), etag)?;
        self.send(req, &op).await.map(drop)
    }

    pub async fn upstream_count(&self) -> Result<usize> {
        let (_, body) = self
            .send(
                self.http.get(self.url("reverse_proxy/upstreams")),
                "GET /reverse_proxy/upstreams",
            )
            .await?;
        let v: Value = serde_json::from_str(&body)
            .map_err(|e| anyhow!("GET /reverse_proxy/upstreams: unexpected response: {e}"))?;
        Ok(v.as_array().map_or(0, Vec::len))
    }

    fn excerpt(&self, text: &str) -> String {
        let text = redact(text.trim(), self.api_key.as_deref().unwrap_or(""));
        let text = plugin_toolkit::logging::scrub(&text);
        text.char_indices()
            .nth(ERROR_EXCERPT)
            .map_or(&*text, |(i, _)| &text[..i])
            .to_string()
    }
}

pub const ERROR_EXCERPT: usize = 256;
const REQUEST_TIMEOUT_SECS: u64 = 30;

pub fn redact(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        text.to_string()
    } else {
        text.replace(secret, "***")
    }
}

pub fn check_segment(kind: &str, s: &str) -> Result<()> {
    if s.is_empty()
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        bail!("invalid {kind} {s:?}");
    }
    Ok(())
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn valid_hostname(h: &str) -> bool {
    h.len() <= 253 && h.split('.').all(valid_label)
}

pub fn normalize_host(host: &str) -> Result<String> {
    if !host.is_ascii() {
        bail!("invalid host {host:?}: use the punycode (xn--) form of internationalized names");
    }
    let lower = host.to_ascii_lowercase();
    let bare = lower.strip_prefix("*.").unwrap_or(&lower);
    if !valid_hostname(bare) {
        bail!("invalid host {host:?}");
    }
    Ok(lower)
}

pub fn check_dial(dial: &str) -> Result<()> {
    let bad =
        || anyhow!("invalid upstream {dial:?}: expected host:port, [ipv6]:port or unix//path");
    if let Some(path) = dial.strip_prefix("unix//") {
        if path.is_empty() || path.chars().any(|c| c.is_whitespace() || c == '{') {
            return Err(bad());
        }
        return Ok(());
    }
    let (host, port) = dial.rsplit_once(':').ok_or_else(bad)?;
    if port.parse::<u16>().map_or(true, |p| p == 0) {
        return Err(bad());
    }
    let ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<Ipv6Addr>().is_ok(),
        None => host.parse::<Ipv4Addr>().is_ok() || valid_hostname(host),
    };
    if !ok {
        return Err(bad());
    }
    Ok(())
}
