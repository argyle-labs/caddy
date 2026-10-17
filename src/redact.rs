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

fn walk(value: &mut Value, path: &str, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                let here = format!("{path}/{}", escape(k));
                if is_sensitive_key(k) {
                    *v = Value::String(REDACTED.to_string());
                    out.push(here);
                } else if let Some((_, keep)) = WHOLESALE
                    .iter()
                    .find(|(key, keep)| key == k && v.get(keep).is_some_and(Value::is_string))
                {
                    if let Some(module) = v.as_object_mut() {
                        for (mk, mv) in module.iter_mut().filter(|(mk, _)| mk != keep) {
                            *mv = Value::String(REDACTED.to_string());
                            out.push(format!("{here}/{}", escape(mk)));
                        }
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
}
