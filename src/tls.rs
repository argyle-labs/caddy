#![allow(clippy::disallowed_types)]

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::redact::redact_value;

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
pub enum Challenge {
    Dns01,
    HttpOrTlsAlpn,
    Internal,
}

#[orca_struct]
#[derive(Debug, Clone)]
pub struct Change {
    pub path: String,
    pub before: Option<plugin_toolkit::contract::JsonAny>,
    pub after: Option<plugin_toolkit::contract::JsonAny>,
}

impl Change {
    pub fn new(path: impl Into<String>, before: Option<Value>, after: Option<Value>) -> Self {
        let wrap = |v: Option<Value>| v.map(|v| plugin_toolkit::contract::JsonAny(redact_value(v)));
        Self {
            path: path.into(),
            before: wrap(before),
            after: wrap(after),
        }
    }
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct TlsReport {
    pub host: String,
    pub action: TlsAction,
    pub policy: Option<usize>,
    pub challenge: Challenge,
    pub automate: bool,
    pub warnings: Vec<String>,
}

pub const MIN_SHARED_LABELS: usize = 2;

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

fn issuers(policy: &Value) -> &[Value] {
    policy
        .get("issuers")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

pub fn challenge(policy: Option<&Value>) -> Challenge {
    let list = policy.map_or(&[][..], issuers);
    if list
        .iter()
        .any(|i| i.pointer("/challenges/dns").is_some_and(|d| !d.is_null()))
    {
        Challenge::Dns01
    } else if !list.is_empty()
        && list
            .iter()
            .all(|i| i.get("module").and_then(Value::as_str) == Some("internal"))
    {
        Challenge::Internal
    } else {
        Challenge::HttpOrTlsAlpn
    }
}

pub fn shared_suffix(a: &str, b: &str) -> usize {
    a.trim_start_matches("*.")
        .rsplit('.')
        .zip(b.rsplit('.'))
        .take_while(|(x, y)| x.eq_ignore_ascii_case(y))
        .count()
}

fn covering(config: &Value, host: &str) -> Option<usize> {
    policies(config).iter().position(|p| {
        let subs = subjects(p);
        subs.is_empty() || subs.iter().any(|s| host_matches(s, host))
    })
}

fn closest_dns01(config: &Value, host: &str) -> Option<usize> {
    policies(config)
        .iter()
        .enumerate()
        .filter(|(_, p)| challenge(Some(p)) == Challenge::Dns01)
        .filter_map(|(i, p)| {
            let best = subjects(p)
                .iter()
                .map(|s| shared_suffix(s, host))
                .max()
                .unwrap_or(0);
            (best >= MIN_SHARED_LABELS).then_some((best, std::cmp::Reverse(i)))
        })
        .max()
        .map(|(_, std::cmp::Reverse(i))| i)
}

fn ensure_array<'a>(root: &'a mut Value, keys: &[&str]) -> Option<&'a mut Vec<Value>> {
    let mut cur = root;
    for k in keys {
        cur = cur
            .as_object_mut()?
            .entry(k.to_string())
            .or_insert_with(|| json!({}));
    }
    if cur.as_object().is_some_and(|m| m.is_empty()) {
        *cur = json!([]);
    }
    cur.as_array_mut()
}

pub fn apply(config: &mut Value, host: &str, automate: bool) -> (TlsReport, Vec<Change>) {
    let mut changes = Vec::new();
    let mut warnings = Vec::new();
    let (action, policy) = match covering(config, host) {
        Some(i) => (TlsAction::Covered, Some(i)),
        None => match closest_dns01(config, host) {
            Some(i) => {
                let path = format!("/apps/tls/automation/policies/{i}/subjects");
                let before = config.pointer(&path).cloned();
                if let Some(subs) = config.pointer_mut(&path).and_then(Value::as_array_mut) {
                    subs.push(Value::from(host));
                }
                changes.push(Change::new(
                    path.clone(),
                    before,
                    config.pointer(&path).cloned(),
                ));
                (TlsAction::SubjectAdded, Some(i))
            }
            None => (TlsAction::Default, None),
        },
    };
    let policy_value = policy.and_then(|i| policies(config).get(i));
    let challenge = challenge(policy_value);
    match (action, challenge) {
        (TlsAction::Default, _) => warnings.push(format!(
            "no automation policy covers {host} and no DNS-01 policy shares a domain of at least \
             {MIN_SHARED_LABELS} labels with it; Caddy's default issuers (HTTP-01/TLS-ALPN-01) \
             apply, which need the host to be publicly reachable"
        )),
        (_, Challenge::Dns01) => {}
        (_, other) => warnings.push(format!(
            "automation policy {} covers {host} with {other:?} issuance, not DNS-01",
            policy.unwrap_or_default()
        )),
    }
    let mut automated = false;
    if automate && action != TlsAction::Default {
        let path = "/apps/tls/certificates/automate";
        let before = config.pointer(path).cloned();
        match ensure_array(config, &["apps", "tls", "certificates", "automate"]) {
            Some(arr) => {
                if !arr
                    .iter()
                    .any(|v| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case(host)))
                {
                    arr.push(Value::from(host));
                    changes.push(Change::new(path, before, Some(Value::Array(arr.clone()))));
                }
                automated = true;
            }
            None => warnings.push(format!("{path} is not a list; not adding {host}")),
        }
    }
    (
        TlsReport {
            host: host.to_string(),
            action,
            policy,
            challenge,
            automate: automated,
            warnings,
        },
        changes,
    )
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
    fn subject_coverage_reports_dns01() {
        let mut c = cfg(vec![dns(&["*.scottkey.me"])]);
        let (r, changes) = apply(&mut c, "orca.scottkey.me", false);
        assert_eq!(r.action, TlsAction::Covered);
        assert_eq!(r.policy, Some(0));
        assert_eq!(r.challenge, Challenge::Dns01);
        assert!(r.warnings.is_empty());
        assert!(changes.is_empty());
    }

    #[test]
    fn non_dns01_coverage_warns() {
        for (policy, want) in [
            (json!({"issuers": []}), Challenge::HttpOrTlsAlpn),
            (
                json!({"subjects": ["orca.scottkey.me"], "issuers": [{"module": "acme"}]}),
                Challenge::HttpOrTlsAlpn,
            ),
            (
                json!({"issuers": [{"module": "internal"}]}),
                Challenge::Internal,
            ),
        ] {
            let mut c = cfg(vec![policy]);
            let (r, _) = apply(&mut c, "orca.scottkey.me", false);
            assert_eq!(r.action, TlsAction::Covered);
            assert_eq!(r.challenge, want);
            assert!(r.warnings[0].contains("not DNS-01"), "{:?}", r.warnings);
        }
    }

    #[test]
    fn uncovered_host_joins_the_closest_dns01_policy_only() {
        let mut c = cfg(vec![
            json!({"subjects": ["public.example.com"]}),
            dns(&["a.example.com"]),
            dns(&["gitea.scottkey.me", "immich.scottkey.me"]),
        ]);
        let before = c.clone();
        let (r, changes) = apply(&mut c, "orca.scottkey.me", false);
        assert_eq!(r.action, TlsAction::SubjectAdded);
        assert_eq!(r.policy, Some(2));
        assert_eq!(
            c["apps"]["tls"]["automation"]["policies"][2]["subjects"],
            json!([
                "gitea.scottkey.me",
                "immich.scottkey.me",
                "orca.scottkey.me"
            ])
        );
        assert_eq!(
            c["apps"]["tls"]["automation"]["policies"][1],
            before["apps"]["tls"]["automation"]["policies"][1]
        );
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "/apps/tls/automation/policies/2/subjects");
    }

    #[test]
    fn a_shared_tld_alone_is_not_enough() {
        for host in ["orca.other.me", "x.co.uk"] {
            let mut c = cfg(vec![dns(&["gitea.scottkey.me", "y.co.uk"])]);
            let (r, changes) = apply(&mut c, host, true);
            if host == "x.co.uk" {
                assert_eq!(
                    r.action,
                    TlsAction::SubjectAdded,
                    "known PSL gap: co.uk shares 2 labels"
                );
                continue;
            }
            assert_eq!(r.action, TlsAction::Default, "{host}");
            assert!(changes.is_empty());
            assert!(!r.automate);
        }
    }

    #[test]
    fn reapplying_is_a_no_op() {
        let mut c = cfg(vec![dns(&["gitea.scottkey.me"])]);
        apply(&mut c, "orca.scottkey.me", true);
        let once = c.clone();
        let (r, changes) = apply(&mut c, "orca.scottkey.me", true);
        assert_eq!(r.action, TlsAction::Covered);
        assert!(changes.is_empty());
        assert_eq!(c, once);
    }

    #[test]
    fn standalone_adds_the_host_to_automate() {
        let mut c = cfg(vec![dns(&["*.scottkey.me"])]);
        let (r, changes) = apply(&mut c, "orca.scottkey.me", true);
        assert!(r.automate);
        assert_eq!(
            c["apps"]["tls"]["certificates"]["automate"],
            json!(["orca.scottkey.me"])
        );
        assert_eq!(changes[0].path, "/apps/tls/certificates/automate");
        assert!(changes[0].before.is_none());
    }

    #[test]
    fn no_dns01_policy_falls_back_to_default_without_writing() {
        for mut c in [json!({}), cfg(vec![json!({"subjects": ["x.example.com"]})])] {
            let before = c.clone();
            let (r, changes) = apply(&mut c, "orca.scottkey.me", true);
            assert_eq!(r.action, TlsAction::Default);
            assert!(changes.is_empty());
            assert_eq!(c, before);
            assert!(!r.warnings.is_empty());
        }
    }
}
