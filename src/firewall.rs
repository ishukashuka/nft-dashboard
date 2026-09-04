use serde_json::Value;
use std::cmp::Ordering;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleDraft {
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub input: String,
    pub output: String,
    pub source_port: String,
    pub destination_port: String,
    pub ct_state: String,
    pub verdict: String,
    pub target_chain: String,
    pub counter: bool,
    pub log: bool,
    pub comment: String,
}

impl RuleDraft {
    pub fn new() -> Self {
        Self {
            protocol: "any".into(),
            verdict: "accept".into(),
            ..Default::default()
        }
    }
    pub fn protocols() -> &'static [&'static str] {
        &["any", "tcp", "udp", "icmp", "icmpv6", "sctp"]
    }
    pub fn verdicts() -> &'static [&'static str] {
        &[
            "accept", "drop", "reject", "continue", "return", "jump", "goto",
        ]
    }
    pub fn generated_for_family(&self, family: &str) -> String {
        let mut parts = Vec::new();
        let address_protocol = |value: &str| {
            if family == "ip6" || value.contains(':') {
                "ip6"
            } else {
                "ip"
            }
        };
        let source_prefix = format!("{} saddr", address_protocol(&self.source));
        let destination_prefix = format!("{} daddr", address_protocol(&self.destination));
        for (value, prefix) in [
            (&self.source, source_prefix.as_str()),
            (&self.destination, destination_prefix.as_str()),
            (&self.input, "iifname"),
            (&self.output, "oifname"),
        ] {
            if !value.trim().is_empty() && value != "any" {
                parts.push(format!("{} {}", prefix, value));
            }
        }
        if self.protocol != "any" {
            parts.push(self.protocol.clone());
        }
        if !self.source_port.trim().is_empty() && self.source_port != "any" {
            parts.push(format!("sport {}", self.source_port));
        }
        if !self.destination_port.trim().is_empty() && self.destination_port != "any" {
            parts.push(format!("dport {}", self.destination_port));
        }
        if !self.ct_state.trim().is_empty() {
            parts.push(format!("ct state {}", self.ct_state));
        }
        if self.counter {
            parts.push("counter".into());
        }
        if self.log {
            parts.push("log".into());
        }
        if matches!(self.verdict.as_str(), "jump" | "goto") {
            parts.push(format!("{} {}", self.verdict, self.target_chain));
        } else {
            parts.push(self.verdict.clone());
        }
        if !self.comment.trim().is_empty() {
            parts.push(format!("comment \"{}\"", self.comment.replace('"', "\\\"")));
        }
        parts.join(" ")
    }

    pub fn validation_error(&self, family: &str) -> Option<String> {
        if !matches!(family, "ip" | "ip6" | "inet" | "arp" | "bridge" | "netdev") {
            return Some("Family must be ip, ip6, inet, arp, bridge, or netdev.".into());
        }
        if !Self::protocols().contains(&self.protocol.as_str()) {
            return Some("Choose a supported protocol.".into());
        }
        if !Self::verdicts().contains(&self.verdict.as_str()) {
            return Some("Choose a supported verdict.".into());
        }
        if matches!(self.verdict.as_str(), "jump" | "goto") && self.target_chain.trim().is_empty() {
            return Some("Jump and goto rules require a target chain.".into());
        }
        if self.protocol == "any"
            && (!self.source_port.trim().is_empty() || !self.destination_port.trim().is_empty())
        {
            return Some("Choose TCP, UDP, or SCTP before specifying ports.".into());
        }
        if !matches!(self.protocol.as_str(), "any" | "tcp" | "udp" | "sctp")
            && (!self.source_port.trim().is_empty() || !self.destination_port.trim().is_empty())
        {
            return Some("Ports are only valid with TCP, UDP, or SCTP.".into());
        }
        if (family == "ip" && self.protocol == "icmpv6")
            || (family == "ip6" && self.protocol == "icmp")
        {
            return Some("The selected ICMP protocol does not match the table family.".into());
        }
        None
    }
}

pub fn from_expr(expr: &[Value]) -> (RuleDraft, bool) {
    let mut draft = RuleDraft::new();
    let mut unsupported = false;
    for item in expr {
        if let Some(m) = item.get("match") {
            let left = m.get("left").map(describe).unwrap_or_default();
            let right = m.get("right").map(describe).unwrap_or_default();
            let lower = left.to_lowercase();
            let operator = m.get("op").and_then(Value::as_str).unwrap_or("==");
            if !matches!(operator, "==" | "!=") {
                unsupported = true;
            }
            let value = if operator == "!=" {
                format!("!= {}", right)
            } else {
                right
            };
            if lower.contains("saddr") {
                unsupported |= !draft.source.is_empty();
                draft.source = value;
            } else if lower.contains("daddr") {
                unsupported |= !draft.destination.is_empty();
                draft.destination = value;
            } else if lower.contains("iif") {
                unsupported |= !draft.input.is_empty();
                draft.input = value;
            } else if lower.contains("oif") {
                unsupported |= !draft.output.is_empty();
                draft.output = value;
            } else if lower.contains("sport") {
                unsupported |= !draft.source_port.is_empty();
                draft.source_port = value;
            } else if lower.contains("dport") {
                unsupported |= !draft.destination_port.is_empty();
                draft.destination_port = value;
            } else if lower.contains("ct state") {
                unsupported |= !draft.ct_state.is_empty();
                draft.ct_state = value;
            } else if lower.contains("l4proto") || lower.contains("protocol") {
                unsupported |= draft.protocol != "any";
                draft.protocol = value.to_lowercase();
            } else {
                unsupported = true;
            }
        } else if item.get("accept").is_some() {
            draft.verdict = "accept".into();
        } else if item.get("drop").is_some() {
            draft.verdict = "drop".into();
        } else if item.get("reject").is_some() {
            draft.verdict = "reject".into();
        } else if item.get("continue").is_some() {
            draft.verdict = "continue".into();
        } else if item.get("return").is_some() {
            draft.verdict = "return".into();
        } else if let Some(j) = item.get("jump") {
            draft.verdict = "jump".into();
            draft.target_chain = j
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into();
        } else if let Some(j) = item.get("goto") {
            draft.verdict = "goto".into();
            draft.target_chain = j
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into();
        } else if let Some(counter) = item.get("counter") {
            draft.counter = true;
            if counter
                .as_object()
                .map(|o| o.keys().any(|k| k != "packets" && k != "bytes"))
                .unwrap_or(false)
            {
                unsupported = true;
            }
        } else if let Some(log) = item.get("log") {
            draft.log = true;
            if log.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
                unsupported = true;
            }
        } else {
            unsupported = true;
        }
    }
    (draft, unsupported)
}

fn describe(value: &Value) -> String {
    if let Some(payload) = value.get("payload") {
        return format!(
            "{} {}",
            payload
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or(""),
            payload.get("field").and_then(Value::as_str).unwrap_or("")
        )
        .trim()
        .into();
    }
    if let Some(meta) = value.get("meta") {
        return format!(
            "meta {}",
            meta.get("key").and_then(Value::as_str).unwrap_or("")
        );
    }
    if let Some(ct) = value.get("ct") {
        return format!("ct {}", ct.get("key").and_then(Value::as_str).unwrap_or(""));
    }
    if let Some(prefix) = value.get("prefix") {
        let address = prefix.get("addr").map(describe).unwrap_or_default();
        let length = prefix.get("len").and_then(Value::as_u64).unwrap_or(0);
        return format!("{address}/{length}");
    }
    if let Some(s) = value.as_str() {
        return s.into();
    }
    if let Some(a) = value.as_array() {
        return format!(
            "{{{}}}",
            a.iter().map(describe).collect::<Vec<_>>().join(", ")
        );
    }
    value.to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    ChainOrder,
    Handle,
    Protocol,
    Source,
    Destination,
    Action,
    Packets,
    Bytes,
}

impl SortKey {
    pub fn title(self) -> &'static str {
        match self {
            Self::ChainOrder => "Chain order",
            Self::Handle => "Handle",
            Self::Protocol => "Protocol",
            Self::Source => "Source",
            Self::Destination => "Destination",
            Self::Action => "Action",
            Self::Packets => "Packets",
            Self::Bytes => "Bytes",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SortData<'a> {
    pub order: usize,
    pub handle: u64,
    pub protocol: &'a str,
    pub source: &'a str,
    pub destination: &'a str,
    pub action: &'a str,
    pub packets: u64,
    pub bytes: u64,
}

pub fn compare(a: &SortData<'_>, b: &SortData<'_>, key: SortKey) -> Ordering {
    match key {
        SortKey::ChainOrder => a.order.cmp(&b.order),
        SortKey::Handle => a.handle.cmp(&b.handle),
        SortKey::Protocol => a.protocol.cmp(b.protocol),
        SortKey::Source => a.source.cmp(b.source),
        SortKey::Destination => a.destination.cmp(b.destination),
        SortKey::Action => a.action.cmp(b.action),
        SortKey::Packets => a.packets.cmp(&b.packets),
        SortKey::Bytes => a.bytes.cmp(&b.bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generates_tcp_dport_accept() {
        let mut d = RuleDraft::new();
        d.protocol = "tcp".into();
        d.destination_port = "443".into();
        assert_eq!(d.generated_for_family("ip"), "tcp dport 443 accept");
    }
    #[test]
    fn generates_udp_ports_and_addresses() {
        let mut d = RuleDraft::new();
        d.protocol = "udp".into();
        d.source_port = "53".into();
        d.destination_port = "5353".into();
        d.source = "10.0.0.0/8".into();
        assert!(d
            .generated_for_family("ip")
            .contains("ip saddr 10.0.0.0/8 udp sport 53 dport 5353 accept"));
    }
    #[test]
    fn jump_requires_target() {
        let mut d = RuleDraft::new();
        d.verdict = "jump".into();
        d.target_chain = "log_chain".into();
        assert!(d.generated_for_family("ip").ends_with("jump log_chain"));
    }
    #[test]
    fn numeric_sort_is_numeric() {
        let a = SortData {
            handle: 2,
            ..Default::default()
        };
        let b = SortData {
            handle: 10,
            ..Default::default()
        };
        assert_eq!(compare(&a, &b, SortKey::Handle), Ordering::Less);
    }
    #[test]
    fn packet_sort_is_numeric() {
        let a = SortData {
            packets: 9,
            ..Default::default()
        };
        let b = SortData {
            packets: 100,
            ..Default::default()
        };
        assert_eq!(compare(&a, &b, SortKey::Packets), Ordering::Less);
    }
    #[test]
    fn default_order_is_preserved() {
        let a = SortData {
            order: 1,
            ..Default::default()
        };
        let b = SortData {
            order: 2,
            ..Default::default()
        };
        assert_eq!(compare(&a, &b, SortKey::ChainOrder), Ordering::Less);
    }
    #[test]
    fn unsupported_expression_is_detected() {
        let (_, unsupported) = from_expr(&[serde_json::json!({"limit": {"rate": "5/second"}})]);
        assert!(unsupported);
    }

    #[test]
    fn ipv6_family_generates_ipv6_address_matches() {
        let mut draft = RuleDraft::new();
        draft.source = "2001:db8::/32".into();
        assert_eq!(
            draft.generated_for_family("ip6"),
            "ip6 saddr 2001:db8::/32 accept"
        );
    }

    #[test]
    fn ports_require_a_transport_protocol() {
        let mut draft = RuleDraft::new();
        draft.destination_port = "443".into();
        assert!(draft.validation_error("inet").is_some());
        draft.protocol = "tcp".into();
        assert!(draft.validation_error("inet").is_none());
    }

    #[test]
    fn jump_requires_a_non_empty_target() {
        let mut draft = RuleDraft::new();
        draft.verdict = "jump".into();
        assert!(draft.validation_error("ip").is_some());
    }

    #[test]
    fn icmp_protocol_must_match_the_family() {
        let mut draft = RuleDraft::new();
        draft.protocol = "icmpv6".into();
        assert!(draft.validation_error("ip").is_some());
        assert!(draft.validation_error("ip6").is_none());
    }

    #[test]
    fn cidr_prefix_round_trips_from_nft_json() {
        let (draft, unsupported) = from_expr(&[serde_json::json!({
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                "right": {"prefix": {"addr": "10.0.0.0", "len": 8}}
            }
        })]);
        assert!(!unsupported);
        assert_eq!(draft.source, "10.0.0.0/8");
    }

    #[test]
    fn non_equality_matches_require_advanced_editing() {
        let (_, unsupported) = from_expr(&[serde_json::json!({
            "match": {
                "op": ">",
                "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                "right": 1024
            }
        })]);
        assert!(unsupported);
    }
}
