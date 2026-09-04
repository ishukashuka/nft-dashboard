use anyhow::{bail, Result};
use ratatui::style::Color;
use serde_json::Value;
use tokio::process::Command;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Verdict {
    Accept,
    Drop,
    Reject,
    Jump,
    Return,
    Continue,
    Other,
}

impl Verdict {
    pub(crate) fn color(&self) -> Color {
        match self {
            Verdict::Accept => Color::Green,
            Verdict::Drop | Verdict::Reject => Color::Red,
            Verdict::Jump | Verdict::Return | Verdict::Continue => Color::Blue,
            Verdict::Other => Color::Gray,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ParsedRuleExpr {
    pub(crate) src: String,
    pub(crate) dst: String,
    pub(crate) proto_port: String,
    pub(crate) counters: String,
    pub(crate) action: String,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum InspectorTab {
    Details,
    Counters,
    RawAst,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum SocketTab {
    Listening,
    Connections,
}

impl SocketTab {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Listening => Self::Connections,
            Self::Connections => Self::Listening,
        }
    }
    pub(crate) fn previous(self) -> Self {
        self.next()
    }
    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::Listening => "Listening",
            Self::Connections => "Connections",
        }
    }
}

impl InspectorTab {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Details => Self::Counters,
            Self::Counters => Self::RawAst,
            Self::RawAst => Self::Details,
        }
    }
    pub(crate) fn previous(self) -> Self {
        match self {
            Self::Details => Self::RawAst,
            Self::Counters => Self::Details,
            Self::RawAst => Self::Counters,
        }
    }
    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::Details => "Details",
            Self::Counters => "Counters",
            Self::RawAst => "Raw AST",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Rule {
    pub(crate) family: String,
    pub(crate) table: String,
    pub(crate) chain: String,
    pub(crate) handle: u64,
    pub(crate) parsed: ParsedRuleExpr,
    pub(crate) expression: String,
    pub(crate) verdict: Verdict,
    pub(crate) raw: Value,
    pub(crate) comment: Option<String>,
}

impl Rule {
    pub(crate) fn matches_filter(&self, q: &str) -> bool {
        self.family.to_lowercase().contains(q)
            || self.table.to_lowercase().contains(q)
            || self.chain.to_lowercase().contains(q)
            || self.expression.to_lowercase().contains(q)
            || self.parsed.src.to_lowercase().contains(q)
            || self.parsed.dst.to_lowercase().contains(q)
            || self.handle.to_string().contains(q)
    }

    pub(crate) fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Family: {}", self.family),
            format!("Table: {}", self.table),
            format!("Chain: {}", self.chain),
            format!("Handle: {}", self.handle),
        ];
        if let Some(expr) = self.raw.as_array() {
            for item in expr {
                let Some(m) = item.get("match") else {
                    continue;
                };
                let left = m.get("left").map(describe_operand).unwrap_or_default();
                let right = m.get("right").map(describe_operand).unwrap_or_default();
                let lower = left.to_lowercase();
                let label = if lower.contains("saddr") {
                    "Source"
                } else if lower.contains("daddr") {
                    "Destination"
                } else if lower.contains("iif") {
                    "Input interface"
                } else if lower.contains("oif") {
                    "Output interface"
                } else if lower.contains("sport") {
                    "Source port"
                } else if lower.contains("dport") {
                    "Destination port"
                } else if lower.contains("ct state") {
                    "Connection state"
                } else if lower.contains("l4proto") || lower.contains("protocol") {
                    "Protocol"
                } else {
                    "Match"
                };
                lines.push(
                    format!(
                        "{}: {} {}",
                        label,
                        left.replace("meta iifname", "iif")
                            .replace("meta oifname", "oif"),
                        right
                    )
                    .trim()
                    .to_string(),
                );
            }
        }
        lines.push(format!("Action/verdict: {}", self.parsed.action));
        if let Some(comment) = &self.comment {
            if !comment.is_empty() {
                lines.push(format!("Comment: {}", comment));
            }
        }
        lines.push(String::new());
        lines.push(format!("Reconstructed nft statement: {}", self.expression));
        lines.push(String::new());
        lines.push(format!("Explanation: {}", self.explanation()));
        lines
    }

    pub(crate) fn explanation(&self) -> String {
        let action = match self.parsed.action.as_str() {
            "accept" => "allow",
            "drop" => "drop",
            "reject" => "reject",
            other => other,
        };
        format!(
            "This rule will {} matching traffic: source {}, destination {}, and {}.",
            action, self.parsed.src, self.parsed.dst, self.parsed.proto_port
        )
    }
}

pub(crate) fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() > max_len {
        let mut truncated: String = s.chars().take(max_len.saturating_sub(1)).collect();
        truncated.push('…');
        truncated
    } else {
        s.to_string()
    }
}

fn describe_operand(op: &Value) -> String {
    if let Some(payload) = op.get("payload") {
        let proto = payload
            .get("protocol")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let field = payload.get("field").and_then(|v| v.as_str()).unwrap_or("");
        return format!("{} {}", proto, field).trim().to_string();
    }
    if let Some(meta) = op.get("meta") {
        let key = meta.get("key").and_then(|v| v.as_str()).unwrap_or("");
        return format!("meta {}", key);
    }
    if let Some(ct) = op.get("ct") {
        let key = ct.get("key").and_then(|v| v.as_str()).unwrap_or("");
        return format!("ct {}", key);
    }
    if let Some(prefix) = op.get("prefix") {
        let addr = prefix.get("addr").map(describe_operand).unwrap_or_default();
        let len = prefix.get("len").and_then(|v| v.as_u64()).unwrap_or(0);
        return format!("{}/{}", addr, len);
    }
    if let Some(s) = op.as_str() {
        return s.to_string();
    }
    if let Some(n) = op.as_u64() {
        return n.to_string();
    }
    if let Some(arr) = op.as_array() {
        let parts: Vec<String> = arr.iter().map(describe_operand).collect();
        return format!("{{{}}}", parts.join(", "));
    }
    serde_json::to_string(op).unwrap_or_default()
}

fn parse_expr_structured(expr: &[Value]) -> (ParsedRuleExpr, String, Verdict) {
    let mut src_parts = Vec::new();
    let mut dst_parts = Vec::new();
    let mut proto_parts = Vec::new();
    let mut raw_parts = Vec::new();
    let mut counters = String::new();
    let mut action = String::new();
    let mut verdict = Verdict::Other;

    for item in expr {
        if let Some(m) = item.get("match") {
            let left = m.get("left").map(describe_operand).unwrap_or_default();
            let right = m.get("right").map(describe_operand).unwrap_or_default();
            let op = m.get("op").and_then(|v| v.as_str()).unwrap_or("==");

            let clean_left = left
                .replace("meta iifname", "iif")
                .replace("meta oifname", "oif")
                .replace("meta iif", "iif")
                .replace("meta oif", "oif");

            let op_str = match op {
                "==" => "".to_string(),
                "!=" => "!= ".to_string(),
                _ => format!("{} ", op),
            };

            let match_str = format!("{} {}{}", clean_left, op_str, right)
                .trim()
                .to_string();
            raw_parts.push(match_str.clone());

            if clean_left.contains("saddr") || clean_left.contains("iif") {
                src_parts.push(match_str);
            } else if clean_left.contains("daddr") || clean_left.contains("oif") {
                dst_parts.push(match_str);
            } else {
                proto_parts.push(match_str);
            }
        } else if item.get("accept").is_some() {
            action = "accept".to_string();
            raw_parts.push("accept".to_string());
            verdict = Verdict::Accept;
        } else if item.get("drop").is_some() {
            action = "drop".to_string();
            raw_parts.push("drop".to_string());
            verdict = Verdict::Drop;
        } else if item.get("reject").is_some() {
            action = "reject".to_string();
            raw_parts.push("reject".to_string());
            verdict = Verdict::Reject;
        } else if item.get("return").is_some() {
            action = "return".to_string();
            raw_parts.push("return".to_string());
            verdict = Verdict::Return;
        } else if item.get("continue").is_some() {
            action = "continue".to_string();
            raw_parts.push("continue".to_string());
            verdict = Verdict::Continue;
        } else if let Some(j) = item.get("jump") {
            let target = j.get("target").and_then(|v| v.as_str()).unwrap_or("?");
            action = format!("jump {}", target);
            raw_parts.push(action.clone());
            verdict = Verdict::Jump;
        } else if let Some(g) = item.get("goto") {
            let target = g.get("target").and_then(|v| v.as_str()).unwrap_or("?");
            action = format!("goto {}", target);
            raw_parts.push(action.clone());
            verdict = Verdict::Jump;
        } else if item.get("log").is_some() {
            raw_parts.push("log".to_string());
        } else if let Some(c) = item.get("counter") {
            if let (Some(p), Some(b)) = (
                c.get("packets").and_then(|v| v.as_u64()),
                c.get("bytes").and_then(|v| v.as_u64()),
            ) {
                counters = format!("{}p / {}b", p, b);
                raw_parts.push(format!("counter packets {} bytes {}", p, b));
            }
        }
    }

    let parsed = ParsedRuleExpr {
        src: if src_parts.is_empty() {
            "ANY".to_string()
        } else {
            src_parts.join(" ")
        },
        dst: if dst_parts.is_empty() {
            "ANY".to_string()
        } else {
            dst_parts.join(" ")
        },
        proto_port: if proto_parts.is_empty() {
            "ANY".to_string()
        } else {
            proto_parts.join(" ")
        },
        counters: if counters.is_empty() {
            "-".to_string()
        } else {
            counters
        },
        action: if action.is_empty() {
            "other".to_string()
        } else {
            action
        },
    };

    let raw_str = if raw_parts.is_empty() {
        "(empty)".to_string()
    } else {
        raw_parts.join(" ")
    };
    (parsed, raw_str, verdict)
}

pub(crate) async fn fetch_ruleset() -> Result<Vec<Rule>> {
    let output = Command::new("nft")
        .args(["--json", "list", "ruleset"])
        .output()
        .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            bail!("nft exited with an error (are you running as root?)");
        }
        bail!(stderr);
    }

    let root: Value = serde_json::from_slice(&output.stdout)?;
    let mut rules = Vec::new();

    if let Some(nftables) = root.get("nftables").and_then(|v| v.as_array()) {
        for item in nftables {
            if let Some(rule) = item.get("rule") {
                let family = rule
                    .get("family")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let table = rule
                    .get("table")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let chain = rule
                    .get("chain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let handle = rule.get("handle").and_then(|v| v.as_u64()).unwrap_or(0);
                let expr_val = rule.get("expr").cloned().unwrap_or(Value::Array(vec![]));

                let (parsed, expression, verdict) = match expr_val.as_array() {
                    Some(arr) => parse_expr_structured(arr),
                    None => (
                        ParsedRuleExpr::default(),
                        "(none)".to_string(),
                        Verdict::Other,
                    ),
                };

                rules.push(Rule {
                    family,
                    table,
                    chain,
                    handle,
                    parsed,
                    expression,
                    verdict,
                    raw: expr_val,
                    comment: rule
                        .get("comment")
                        .and_then(|v| v.as_str())
                        .map(str::to_string),
                });
            }
        }
    }
    Ok(rules)
}
