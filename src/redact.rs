#![allow(clippy::disallowed_types)]

use plugin_toolkit::prelude::*;
use plugin_toolkit::scrub::{is_sensitive_key, REDACTED};
use plugin_toolkit::serde_json::Value;

#[orca_struct]
#[derive(Debug, Clone)]
pub struct Redacted {
    pub config: plugin_toolkit::contract::JsonAny,
    pub redacted: Vec<String>,
}

const WHOLESALE: &[(&str, &str)] = &[
    ("provider", "name"),
    ("dns", "name"),
    ("external_account", "key_id"),
];

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn sensitive(key: &str) -> bool {
    let n: String = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    is_sensitive_key(key)
        || n.contains("connectionstring")
        || n.ends_with("dsn")
        || n.ends_with("uri")
}

const SENSITIVE_PARAMS: &[&str] = &[
    "signature",
    "sig",
    "credential",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
];

const DNS_CHALLENGE_PUBLIC: &[&str] = &[
    "ttl",
    "resolvers",
    "override_domain",
    "propagation_delay",
    "propagation_timeout",
];

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (
            bytes[i],
            bytes.get(i + 1).copied().and_then(hex),
            bytes.get(i + 2).copied().and_then(hex),
        ) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b'+', _, _) => {
                out.push(b' ');
                i += 1;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn sensitive_param(raw: &str) -> bool {
    let name = percent_decode(raw);
    is_sensitive_key(&name)
        || SENSITIVE_PARAMS
            .iter()
            .any(|p| name.eq_ignore_ascii_case(p))
}

fn redact_query(tail: &str) -> String {
    let Some((before, query)) = tail.split_once('?') else {
        return tail.to_string();
    };
    let (query, fragment) = match query.split_once('#') {
        Some((q, f)) => (q, Some(f)),
        None => (query, None),
    };
    let query: Vec<String> = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((k, _)) if sensitive_param(k) => format!("{k}={REDACTED}"),
            _ => pair.to_string(),
        })
        .collect();
    let mut out = format!("{before}?{}", query.join("&"));
    if let Some(f) = fragment {
        out.push('#');
        out.push_str(f);
    }
    out
}

fn clean_token(token: &str) -> String {
    match token.split_once("://") {
        Some((scheme, rest)) => {
            let rest = match rest.rsplit_once('@') {
                Some((_, after)) => format!("{REDACTED}@{after}"),
                None => rest.to_string(),
            };
            format!("{scheme}://{}", redact_query(&rest))
        }
        None => {
            let token = match token.rsplit_once('@') {
                Some((userinfo, after)) if userinfo.contains(':') => format!("{REDACTED}@{after}"),
                _ => token.to_string(),
            };
            redact_query(&token)
        }
    }
}

pub fn strip_userinfo(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut token = String::new();
    for c in s.chars() {
        if c.is_whitespace() {
            out.push_str(&clean_token(&token));
            token.clear();
            out.push(c);
        } else {
            token.push(c);
        }
    }
    out.push_str(&clean_token(&token));
    (out != s).then_some(out)
}

fn walk(value: &mut Value, path: &str, out: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            if let Some(clean) = strip_userinfo(text) {
                *text = clean;
                out.push(path.to_string());
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                let here = format!("{path}/{}", escape(k));
                if k == "dns" && path.ends_with("/challenges") && v.is_object() {
                    if let Some(dns) = v.as_object_mut() {
                        for (dk, dv) in dns.iter_mut() {
                            let at = format!("{here}/{}", escape(dk));
                            if dk == "provider" || DNS_CHALLENGE_PUBLIC.contains(&dk.as_str()) {
                                let mut wrapper = plugin_toolkit::serde_json::Map::new();
                                wrapper.insert(dk.clone(), std::mem::take(dv));
                                let mut wrapped = Value::Object(wrapper);
                                walk(&mut wrapped, &here, out);
                                if let Some(back) = wrapped.get_mut(dk.as_str()) {
                                    *dv = std::mem::take(back);
                                }
                            } else {
                                *dv = Value::String(REDACTED.to_string());
                                out.push(at);
                            }
                        }
                    }
                } else if sensitive(k) {
                    *v = Value::String(REDACTED.to_string());
                    out.push(here);
                } else if let Some((_, keep)) = WHOLESALE.iter().find(|(key, _)| key == k) {
                    if let Some(module) = v.as_object_mut() {
                        for (mk, mv) in module
                            .iter_mut()
                            .filter(|(mk, mv)| !(mk == keep && mv.is_string()))
                        {
                            *mv = Value::String(REDACTED.to_string());
                            out.push(format!("{here}/{}", escape(mk)));
                        }
                    } else if !v.is_null() {
                        *v = Value::String(REDACTED.to_string());
                        out.push(here);
                    }
                } else {
                    walk(v, &here, out);
                }
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter_mut().enumerate() {
                walk(v, &format!("{path}/{i}"), out);
            }
        }
        _ => {}
    }
}

pub fn redact_config(mut config: Value) -> Redacted {
    let mut redacted = Vec::new();
    walk(&mut config, "", &mut redacted);
    Redacted {
        config: plugin_toolkit::contract::JsonAny(config),
        redacted,
    }
}

pub fn redact_value(value: Value) -> Value {
    redact_config(value).config.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_provider_config_is_redacted_wholesale_except_its_name() {
        let r = redact_config(json!({"apps": {"tls": {
            "dns": {"name": "cloudflare", "zone_id": "z1"},
            "automation": {"policies": [{"issuers": [{
                "module": "acme",
                "email": "ops@example.com",
                "external_account": {"key_id": "kid", "mac_key": "mk-secret"},
                "challenges": {"dns": {"provider": {"name": "route53", "access_key_id": "AKIA1", "hmac": "h1", "region": "x"}}}
            }]}]}
        }}}));
        let text = r.config.0.to_string();
        for leaked in ["z1", "AKIA1", "h1", "\"x\"", "mk-secret"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        assert!(
            text.contains("cloudflare") && text.contains("route53"),
            "{text}"
        );
        assert!(text.contains("\"kid\""), "{text}");
        assert!(text.contains("ops@example.com"), "{text}");
        assert!(r.redacted.contains(
            &"/apps/tls/automation/policies/0/issuers/0/challenges/dns/provider/hmac".to_string()
        ));
        assert!(r.redacted.contains(&"/apps/tls/dns/zone_id".to_string()));
    }

    #[test]
    fn secret_shaped_keys_anywhere_are_redacted() {
        let r = redact_config(json!({"apps": {"http": {"servers": {"s": {"routes": [
            {"handle": [{"handler": "authentication", "providers": {"http_basic": {"accounts": [{"username": "u", "password": "pw-secret"}]}}}]}
        ]}}}}}));
        assert!(!r.config.0.to_string().contains("pw-secret"));
        assert_eq!(r.redacted.len(), 1);
    }

    #[test]
    fn credentials_in_values_are_redacted() {
        let r = redact_config(json!({
            "admin": {"config": {"load": {"module": "http", "url": "https://ops:hunter2@cfg.example.com/caddy.json"}}},
            "storage": {"module": "postgres", "connection_string": "postgres://caddy:pgpass@db:5432/caddy"},
            "apps": {"x": {"address": "redis://:redispass@10.0.0.5:6379/0", "plain": "user:pw@10.0.0.9:6379",
                           "email": "ops@example.com", "site": "https://example.com/a", "database_uri": "u"}}
        }));
        let text = r.config.0.to_string();
        for leaked in ["hunter2", "pgpass", "redispass", ":pw@"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        assert!(
            text.contains("ops@example.com") && text.contains("\"https://example.com/a\""),
            "{text}"
        );
        assert!(
            text.contains("https://<redacted>@cfg.example.com/caddy.json"),
            "{text}"
        );
        for p in [
            "/admin/config/load/url",
            "/storage/connection_string",
            "/apps/x/address",
            "/apps/x/plain",
            "/apps/x/database_uri",
        ] {
            assert!(r.redacted.contains(&p.to_string()), "{p}: {:?}", r.redacted);
        }
    }

    #[test]
    fn module_objects_are_redacted_whatever_their_shape() {
        let r = redact_config(json!({
            "a": {"provider": {"name": {"nested": "secret1"}, "token2": "secret2"}},
            "b": {"external_account": {"mac": "secret3"}},
            "c": {"dns": "secret4"},
            "d": {"provider": {"name": "cloudflare"}}
        }));
        let text = r.config.0.to_string();
        for leaked in ["secret1", "secret2", "secret3", "secret4"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        assert!(text.contains("cloudflare"), "{text}");
    }

    #[test]
    fn userinfo_is_over_redacted_when_ambiguous() {
        assert_eq!(
            strip_userinfo("postgres://u:pa/ss@db/x").unwrap(),
            "postgres://<redacted>@db/x"
        );
        assert_eq!(
            strip_userinfo("u:p#w@host:6379").unwrap(),
            "<redacted>@host:6379"
        );
        assert_eq!(
            strip_userinfo("https://example.com/a@b").unwrap(),
            "https://<redacted>@b"
        );
        assert!(strip_userinfo("ops@example.com").is_none());
        assert!(strip_userinfo("https://example.com/x").is_none());
    }

    #[test]
    fn tokens_inside_free_text_are_cleaned() {
        assert_eq!(
            strip_userinfo("redis://:pw@10.0.0.5:6379 ").unwrap(),
            "redis://<redacted>@10.0.0.5:6379 "
        );
        assert_eq!(
            strip_userinfo("fetch https://a:b@cfg.example.com/x then retry").unwrap(),
            "fetch https://<redacted>@cfg.example.com/x then retry"
        );
    }

    #[test]
    fn secret_query_params_are_redacted() {
        assert_eq!(
            strip_userinfo("https://cfg.example.com/c.json?token=abc&v=2#top").unwrap(),
            "https://cfg.example.com/c.json?token=<redacted>&v=2#top"
        );
        assert!(strip_userinfo("https://cfg.example.com/c.json?v=2").is_none());
    }

    #[test]
    fn only_challenge_dns_objects_keep_their_shape() {
        let r = redact_config(json!({"apps": {"tls": {
            "dns": {"name": "cloudflare", "provider": {"name": "x", "api_token": "t1"}, "zone": "z1"},
            "automation": {"policies": [{"issuers": [{"challenges": {"dns": {
                "provider": {"name": "cloudflare", "api_token": "t2"}, "ttl": "120s"}}}]}]}
        }}}));
        let text = r.config.0.to_string();
        for leaked in ["t1", "t2", "z1"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        assert!(
            r.redacted.contains(&"/apps/tls/dns/provider".to_string()),
            "{:?}",
            r.redacted
        );
        assert!(text.contains("120s"), "{text}");
    }

    #[test]
    fn schemeless_and_encoded_query_names_are_redacted() {
        assert_eq!(
            strip_userinfo("host/path?token=abc").unwrap(),
            "host/path?token=<redacted>"
        );
        assert_eq!(
            strip_userinfo("https://x.example.com/a?api%5Fkey=x&v=1").unwrap(),
            "https://x.example.com/a?api%5Fkey=<redacted>&v=1"
        );
    }

    #[test]
    fn presigned_s3_urls_are_redacted() {
        let url = "https://bucket.s3.amazonaws.com/k?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                   &X-Amz-Credential=AKIA%2F20260101&X-Amz-Signature=deadbeef\
                   &X-Amz-Security-Token=tok&sig=s1&X-Amz-Expires=60";
        let out = strip_userinfo(url).unwrap();
        for leaked in ["AKIA", "deadbeef", "=tok", "s1"] {
            assert!(!out.contains(leaked), "{leaked} in {out}");
        }
        assert!(
            out.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256") && out.contains("X-Amz-Expires=60"),
            "{out}"
        );
    }

    #[test]
    fn unknown_dns_challenge_siblings_are_redacted() {
        let r = redact_config(json!({"issuers": [{"challenges": {"dns": {
            "provider": {"name": "cloudflare", "api_token": "t1"},
            "ttl": "120s", "resolvers": ["1.1.1.1"], "propagation_timeout": "2m",
            "mystery": "m1"
        }}}]}));
        let text = r.config.0.to_string();
        assert!(!text.contains("t1") && !text.contains("m1"), "{text}");
        assert!(
            text.contains("120s") && text.contains("1.1.1.1") && text.contains("2m"),
            "{text}"
        );
        assert!(text.contains("cloudflare"), "{text}");
        assert!(
            r.redacted
                .contains(&"/issuers/0/challenges/dns/mystery".to_string()),
            "{:?}",
            r.redacted
        );
        assert!(
            r.redacted
                .contains(&"/issuers/0/challenges/dns/provider/api_token".to_string()),
            "{:?}",
            r.redacted
        );
    }
}
