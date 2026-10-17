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

pub fn strip_userinfo(s: &str) -> Option<String> {
    if s.chars().any(char::is_whitespace) {
        return None;
    }
    let (scheme, rest) = match s.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, s),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (userinfo, host) = authority.rsplit_once('@')?;
    if host.is_empty() || (scheme.is_none() && !userinfo.contains(':')) {
        return None;
    }
    Some(match scheme {
        Some(scheme) => format!("{scheme}://{REDACTED}@{host}{tail}"),
        None => format!("{REDACTED}@{host}{tail}"),
    })
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
                if sensitive(k) {
                    *v = Value::String(REDACTED.to_string());
                    out.push(here);
                } else if let Some((_, keep)) = WHOLESALE
                    .iter()
                    .find(|(key, _)| key == k && !(k == "dns" && v.get("provider").is_some()))
                {
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
                           "email": "ops@example.com", "site": "https://example.com/a@b", "database_uri": "u"}}
        }));
        let text = r.config.0.to_string();
        for leaked in ["hunter2", "pgpass", "redispass", ":pw@"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        assert!(
            text.contains("ops@example.com") && text.contains("https://example.com/a@b"),
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
}
