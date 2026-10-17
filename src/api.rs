#![allow(clippy::disallowed_types)]

use plugin_toolkit::api_client::ApiClientBuilder;
use plugin_toolkit::prelude::*;
use plugin_toolkit::reqwest::{Client as HttpClient, RequestBuilder};
use plugin_toolkit::serde_json::{self, Value};
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
            bail!("{op}: config changed concurrently (HTTP 412); retry");
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

    pub async fn load(&self, config: &Value) -> Result<()> {
        let req = self
            .http
            .post(self.url("load"))
            .header(
                "cache-control",
                plugin_toolkit::reqwest::header::HeaderValue::from_static("must-revalidate"),
            )
            .json(config);
        self.send(req, "POST /load").await.map(drop)
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

pub fn check_host(host: &str) -> Result<()> {
    let bare = host.strip_prefix("*.").unwrap_or(host);
    if bare.is_empty()
        || host.len() > 253
        || !bare
            .split('.')
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
    {
        bail!("invalid host {host:?}");
    }
    Ok(())
}

pub fn check_dial(dial: &str) -> Result<()> {
    let Some((host, port)) = dial.rsplit_once(':') else {
        bail!("invalid upstream {dial:?}: expected host:port");
    };
    if host.is_empty()
        || host.chars().any(|c| c.is_whitespace() || c == '/')
        || port.parse::<u16>().map_or(true, |p| p == 0)
    {
        bail!("invalid upstream {dial:?}: expected host:port");
    }
    Ok(())
}
