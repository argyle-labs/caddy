#![allow(clippy::disallowed_types)]

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    plugin_toolkit::serde::Serialize,
    plugin_toolkit::serde::Deserialize,
    plugin_toolkit::schemars::JsonSchema,
)]
#[serde(crate = "plugin_toolkit::serde")]
#[schemars(crate = "plugin_toolkit::schemars")]
#[serde(rename_all = "snake_case")]
pub enum TlsAction {
    Covered,
    SubjectAdded,
    Default,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct TlsReport {
    pub host: String,
    pub action: TlsAction,
    pub policy: Option<usize>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TlsPlan {
    pub report: TlsReport,
    pub write: Option<(String, Value)>,
}

pub fn host_matches(pattern: &str, host: &str) -> bool {
    let p: Vec<&str> = pattern.split('.').collect();
    let h: Vec<&str> = host.split('.').collect();
    p.len() == h.len()
        && p.iter()
            .zip(&h)
            .all(|(p, h)| *p == "*" || p.eq_ignore_ascii_case(h))
}

fn policies(config: &Value) -> &[Value] {
    config
        .pointer("/apps/tls/automation/policies")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn subjects(policy: &Value) -> Vec<&str> {
    policy
        .get("subjects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

fn is_dns01(policy: &Value) -> bool {
    policy
        .get("issuers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|i| i.pointer("/challenges/dns").is_some_and(|d| !d.is_null()))
}

fn shared_suffix(a: &str, b: &str) -> usize {
    a.trim_start_matches("*.")
        .rsplit('.')
        .zip(b.rsplit('.'))
        .take_while(|(x, y)| x.eq_ignore_ascii_case(y))
        .count()
}

pub fn plan(config: &Value, host: &str) -> TlsPlan {
    let report = |action, policy, detail: String| TlsReport {
        host: host.to_string(),
        action,
        policy,
        detail,
    };
    let all = policies(config);
    for (i, p) in all.iter().enumerate() {
        let subs = subjects(p);
        if subs.is_empty() {
            return TlsPlan {
                report: report(
                    TlsAction::Covered,
                    Some(i),
                    format!("catch-all automation policy {i}"),
                ),
                write: None,
            };
        }
        if let Some(s) = subs.iter().find(|s| host_matches(s, host)) {
            return TlsPlan {
                report: report(
                    TlsAction::Covered,
                    Some(i),
                    format!("automation policy {i} subject {s}"),
                ),
                write: None,
            };
        }
    }
    let target = all
        .iter()
        .enumerate()
        .filter(|(_, p)| is_dns01(p))
        .max_by_key(|(i, p)| {
            let best = subjects(p)
                .iter()
                .map(|s| shared_suffix(s, host))
                .max()
                .unwrap_or(0);
            (best, std::cmp::Reverse(*i))
        });
    match target {
        Some((i, p)) => {
            let mut subs: Vec<Value> = subjects(p).into_iter().map(Value::from).collect();
            subs.push(Value::from(host));
            TlsPlan {
                report: report(
                    TlsAction::SubjectAdded,
                    Some(i),
                    format!("added to DNS-01 automation policy {i}"),
                ),
                write: Some((
                    format!("apps/tls/automation/policies/{i}/subjects"),
                    Value::Array(subs),
                )),
            }
        }
        None => TlsPlan {
            report: report(
                TlsAction::Default,
                None,
                "no DNS-01 automation policy; Caddy's default issuers (HTTP-01/TLS-ALPN-01) apply"
                    .into(),
            ),
            write: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns(subjects: &[&str]) -> Value {
        json!({
            "subjects": subjects,
            "issuers": [{"module": "acme", "challenges": {"dns": {"provider": {"name": "cloudflare", "api_token": "{env.CF_API_TOKEN}"}}}}]
        })
    }

    fn cfg(policies: Vec<Value>) -> Value {
        json!({"apps": {"tls": {"automation": {"policies": policies}}}})
    }

    #[test]
    fn wildcard_matches_exactly_one_label() {
        assert!(host_matches("*.scottkey.me", "orca.scottkey.me"));
        assert!(host_matches("Orca.ScottKey.me", "orca.scottkey.me"));
        assert!(!host_matches("*.scottkey.me", "scottkey.me"));
        assert!(!host_matches("*.scottkey.me", "a.b.scottkey.me"));
    }

    #[test]
    fn exact_and_wildcard_subjects_cover() {
        let p = plan(&cfg(vec![dns(&["*.scottkey.me"])]), "orca.scottkey.me");
        assert_eq!(p.report.action, TlsAction::Covered);
        assert_eq!(p.report.policy, Some(0));
        assert!(p.write.is_none());
    }

    #[test]
    fn catch_all_policy_covers() {
        let p = plan(
            &cfg(vec![dns(&["a.example.com"]), json!({"issuers": []})]),
            "orca.scottkey.me",
        );
        assert_eq!(p.report.action, TlsAction::Covered);
        assert_eq!(p.report.policy, Some(1));
    }

    #[test]
    fn uncovered_host_joins_the_closest_dns01_policy_only() {
        let config = cfg(vec![
            json!({"subjects": ["public.example.com"]}),
            dns(&["a.example.com"]),
            dns(&["gitea.scottkey.me", "immich.scottkey.me"]),
        ]);
        let p = plan(&config, "orca.scottkey.me");
        assert_eq!(p.report.action, TlsAction::SubjectAdded);
        assert_eq!(p.report.policy, Some(2));
        assert_eq!(
            p.write,
            Some((
                "apps/tls/automation/policies/2/subjects".into(),
                json!([
                    "gitea.scottkey.me",
                    "immich.scottkey.me",
                    "orca.scottkey.me"
                ])
            ))
        );
    }

    #[test]
    fn replanning_after_the_write_is_a_no_op() {
        let config = cfg(vec![dns(&["gitea.scottkey.me"])]);
        let (_, subs) = plan(&config, "orca.scottkey.me").write.unwrap();
        let mut after = config.clone();
        after["apps"]["tls"]["automation"]["policies"][0]["subjects"] = subs;
        let p = plan(&after, "orca.scottkey.me");
        assert_eq!(p.report.action, TlsAction::Covered);
        assert!(p.write.is_none());
    }

    #[test]
    fn no_dns01_policy_falls_back_to_default_without_writing() {
        for config in [json!({}), cfg(vec![json!({"subjects": ["x.example.com"]})])] {
            let p = plan(&config, "orca.scottkey.me");
            assert_eq!(p.report.action, TlsAction::Default, "{config}");
            assert!(p.write.is_none());
        }
    }
}
