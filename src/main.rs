use anyhow::{bail, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::text::Line;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{
        Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState, Wrap,
    },
    Terminal,
};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time;
mod network;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Verdict {
    Accept,
    Drop,
    Reject,
    Jump,
    Return,
    Continue,
    Other,
}

impl Verdict {
    fn color(&self) -> Color {
        match self {
            Verdict::Accept => Color::Green,
            Verdict::Drop | Verdict::Reject => Color::Red,
            Verdict::Jump | Verdict::Return | Verdict::Continue => Color::Blue,
            Verdict::Other => Color::Gray,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ParsedRuleExpr {
    src: String,
    dst: String,
    proto_port: String,
    counters: String,
    action: String,
}

#[derive(Debug, Clone)]
struct Rule {
    family: String,
    table: String,
    chain: String,
    handle: u64,
    parsed: ParsedRuleExpr,
    expression: String,
    verdict: Verdict,
    raw: Value,
}

impl Rule {
    fn matches_filter(&self, q: &str) -> bool {
        self.family.to_lowercase().contains(q)
            || self.table.to_lowercase().contains(q)
            || self.chain.to_lowercase().contains(q)
            || self.expression.to_lowercase().contains(q)
            || self.parsed.src.to_lowercase().contains(q)
            || self.parsed.dst.to_lowercase().contains(q)
            || self.handle.to_string().contains(q)
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
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

#[derive(Debug, Default)]
struct TextField {
    value: String,
    cursor: usize,
}

impl TextField {
    fn from(s: &str) -> Self {
        Self {
            value: s.to_string(),
            cursor: s.chars().count(),
        }
    }
    fn byte_index(&self) -> usize {
        self.value
            .char_indices()
            .nth(self.cursor)
            .map(|(i, _)| i)
            .unwrap_or(self.value.len())
    }
    fn insert(&mut self, c: char) {
        let idx = self.byte_index();
        self.value.insert(idx, c);
        self.cursor += 1;
    }
    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let idx = self.byte_index();
        if let Some(prev) = self.value[..idx].chars().next_back() {
            let new_idx = idx - prev.len_utf8();
            self.value.remove(new_idx);
            self.cursor -= 1;
        }
    }
    fn delete(&mut self) {
        let idx = self.byte_index();
        if idx < self.value.len() {
            self.value.remove(idx);
        }
    }
    fn left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }
    fn right(&mut self) {
        if self.cursor < self.value.chars().count() {
            self.cursor += 1;
        }
    }
    fn home(&mut self) {
        self.cursor = 0;
    }
    fn end(&mut self) {
        self.cursor = self.value.chars().count();
    }
    fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }
}

#[derive(Debug, PartialEq)]
enum Focus {
    Sidebar,
    Table,
}

#[derive(Debug, PartialEq)]
enum Section {
    Firewall,
    Network,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum NetworkTab {
    General,
    Ipv4,
    Routes,
    Dns,
}

impl NetworkTab {
    fn next(self) -> Self {
        match self {
            Self::General => Self::Ipv4,
            Self::Ipv4 => Self::Routes,
            Self::Routes => Self::Dns,
            Self::Dns => Self::General,
        }
    }
    fn previous(self) -> Self {
        match self {
            Self::General => Self::Dns,
            Self::Ipv4 => Self::General,
            Self::Routes => Self::Ipv4,
            Self::Dns => Self::Routes,
        }
    }
    fn title(self) -> &'static str {
        match self {
            Self::General => "General",
            Self::Ipv4 => "IPv4",
            Self::Routes => "Routes",
            Self::Dns => "DNS",
        }
    }
}

#[derive(Debug, PartialEq)]
enum Mode {
    Normal,
    Add,
    Insert,
    Edit,
    Filter,
    Detail,
    ConfirmDelete,
    Error,
    FatalError,
    NetworkEdit,
    NetworkConfirm,
}

struct RuleForm {
    field_idx: usize,
    family: TextField,
    table: TextField,
    chain: TextField,
    statement: TextField,
    location_locked: bool,
}

struct NetworkForm {
    field_idx: usize,
    fields: Vec<TextField>,
    title: String,
}

impl RuleForm {
    fn new() -> Self {
        Self {
            field_idx: 0,
            family: TextField::from("ip"),
            table: TextField::from("filter"),
            chain: TextField::from("INPUT"),
            statement: TextField::from(""),
            location_locked: false,
        }
    }
    fn from_rule(rule: &Rule) -> Self {
        Self {
            field_idx: 3,
            family: TextField::from(&rule.family),
            table: TextField::from(&rule.table),
            chain: TextField::from(&rule.chain),
            statement: TextField::from(&rule.expression),
            location_locked: true,
        }
    }
    fn next_field(&mut self) {
        self.field_idx = (self.field_idx + 1) % 4;
    }
    fn prev_field(&mut self) {
        self.field_idx = if self.field_idx == 0 {
            3
        } else {
            self.field_idx - 1
        };
    }
    fn active_field_mut(&mut self) -> &mut TextField {
        match self.field_idx {
            0 => &mut self.family,
            1 => &mut self.table,
            2 => &mut self.chain,
            _ => &mut self.statement,
        }
    }
}

struct App {
    rules: Vec<Rule>,
    sidebar_items: Vec<String>,
    sidebar_state: ListState,
    visible: Vec<usize>,
    table_state: TableState,
    focus: Focus,
    mode: Mode,
    form: RuleForm,
    filter: TextField,
    status_msg: String,
    error_msg: String,
    detail_scroll: u16,
    section: Section,
    profiles: Vec<network::Profile>,
    network_selected: usize,
    network_route_selected: usize,
    network_tab: NetworkTab,
    network_focus: bool,
    network_form: Option<NetworkForm>,
    network_action: String,
}

impl App {
    fn new() -> Self {
        Self {
            rules: Vec::new(),
            sidebar_items: vec!["ALL".to_string()],
            sidebar_state: ListState::default(),
            visible: Vec::new(),
            table_state: TableState::default(),
            focus: Focus::Sidebar,
            mode: Mode::Normal,
            form: RuleForm::new(),
            filter: TextField::default(),
            status_msg: "Ready".to_string(),
            error_msg: String::new(),
            detail_scroll: 0,
            section: Section::Firewall,
            profiles: Vec::new(),
            network_selected: 0,
            network_route_selected: 0,
            network_tab: NetworkTab::General,
            network_focus: false,
            network_form: None,
            network_action: String::new(),
        }
    }

    fn update_sidebar(&mut self) {
        let mut set = HashSet::new();
        set.insert("ALL".to_string());
        for r in &self.rules {
            set.insert(format!("{}/{}", r.family, r.table));
        }
        let mut list: Vec<String> = set.into_iter().collect();
        list.sort();
        self.sidebar_items = list;
        if self.sidebar_state.selected().is_none() {
            self.sidebar_state.select(Some(0));
        }
        self.repair_selection();
    }

    fn recompute_visible(&mut self) {
        let selected_identity = self
            .selected_rule()
            .map(|r| (r.family.clone(), r.table.clone(), r.chain.clone(), r.handle));
        let q = self.filter.value.trim().to_lowercase();
        let selected_tree = self
            .sidebar_state
            .selected()
            .and_then(|i| self.sidebar_items.get(i))
            .cloned()
            .unwrap_or_else(|| "ALL".to_string());

        self.visible = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let matches_tree = if selected_tree == "ALL" {
                    true
                } else {
                    format!("{}/{}", r.family, r.table) == selected_tree
                };
                let matches_q = q.is_empty() || r.matches_filter(&q);
                matches_tree && matches_q
            })
            .map(|(i, _)| i)
            .collect();

        if self.visible.is_empty() {
            self.table_state.select(None);
        } else {
            let sel = selected_identity
                .and_then(|id| {
                    self.visible.iter().position(|&idx| {
                        let r = &self.rules[idx];
                        (r.family.clone(), r.table.clone(), r.chain.clone(), r.handle) == id
                    })
                })
                .unwrap_or_else(|| {
                    self.table_state
                        .selected()
                        .unwrap_or(0)
                        .min(self.visible.len() - 1)
                });
            self.table_state.select(Some(sel));
        }
    }

    fn next(&mut self) {
        match self.focus {
            Focus::Sidebar => {
                if !self.sidebar_items.is_empty() {
                    let i = match self.sidebar_state.selected() {
                        Some(i) => (i + 1) % self.sidebar_items.len(),
                        None => 0,
                    };
                    self.sidebar_state.select(Some(i));
                    self.recompute_visible();
                }
            }
            Focus::Table => {
                if !self.visible.is_empty() {
                    let i = match self.table_state.selected() {
                        Some(i) => std::cmp::min(i + 1, self.visible.len().saturating_sub(1)),
                        None => 0,
                    };
                    self.table_state.select(Some(i));
                }
            }
        }
    }

    fn previous(&mut self) {
        match self.focus {
            Focus::Sidebar => {
                if !self.sidebar_items.is_empty() {
                    let i = match self.sidebar_state.selected() {
                        Some(i) => {
                            if i == 0 {
                                self.sidebar_items.len() - 1
                            } else {
                                i - 1
                            }
                        }
                        None => 0,
                    };
                    self.sidebar_state.select(Some(i));
                    self.recompute_visible();
                }
            }
            Focus::Table => {
                if !self.visible.is_empty() {
                    let i = match self.table_state.selected() {
                        Some(i) => i.saturating_sub(1),
                        None => 0,
                    };
                    self.table_state.select(Some(i));
                }
            }
        }
    }

    fn selected_rule(&self) -> Option<&Rule> {
        self.table_state
            .selected()
            .and_then(|i| self.visible.get(i))
            .and_then(|&idx| self.rules.get(idx))
    }

    fn repair_selection(&mut self) {
        if self.sidebar_items.is_empty() {
            self.sidebar_state.select(None);
        } else {
            self.sidebar_state.select(Some(
                self.sidebar_state
                    .selected()
                    .unwrap_or(0)
                    .min(self.sidebar_items.len() - 1),
            ));
        }
    }
}

fn draw_network(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.size());
    let head =
        Paragraph::new(" Network  |  persistent NetworkManager profiles + current kernel state ")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" NFTables Firewall Dashboard ")
                    .border_style(Style::default().fg(Color::Cyan)),
            );
    f.render_widget(head, chunks[0]);
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(chunks[1]);
    let items = app
        .profiles
        .iter()
        .map(|p| {
            ListItem::new(format!(
                "{}  {} {}",
                p.name,
                if p.state.contains("activated") {
                    "●"
                } else {
                    "○"
                },
                if p.device.is_empty() { "--" } else { &p.device }
            ))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default();
    if !app.profiles.is_empty() {
        state.select(Some(app.network_selected.min(app.profiles.len() - 1)));
    }
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Connections ")
                .border_style(Style::default().fg(if app.network_focus {
                    Color::Yellow
                } else {
                    Color::DarkGray
                })),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(40, 50, 75))
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, panes[0], &mut state);
    if let Some(p) = app.profiles.get(app.network_selected) {
        let tabs = [
            NetworkTab::General,
            NetworkTab::Ipv4,
            NetworkTab::Routes,
            NetworkTab::Dns,
        ]
        .iter()
        .map(|t| {
            if *t == app.network_tab {
                format!("[ {} ]", t.title())
            } else {
                format!("  {}  ", t.title())
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
        let mut lines = vec![Line::from(tabs), Line::from("")];
        match app.network_tab {
            NetworkTab::General => {
                lines.extend([
                    Line::from(format!("Profile:      {}", p.name)),
                    Line::from(format!(
                        "Device:       {}",
                        if p.device.is_empty() { "--" } else { &p.device }
                    )),
                    Line::from(format!("State:        {}", p.state)),
                    Line::from(format!("Type:         {}", p.kind)),
                    Line::from(format!("Autoconnect:  {}", p.autoconnect)),
                    Line::from(""),
                    Line::from(format!(
                        "Runtime IPv4: {}",
                        if p.runtime_addresses.is_empty() {
                            "none".to_string()
                        } else {
                            p.runtime_addresses.join(", ")
                        }
                    )),
                ]);
            }
            NetworkTab::Ipv4 => {
                lines.extend([
                    Line::from(format!("Method:       {}", p.ipv4_method)),
                    Line::from(format!(
                        "Addresses:    {}",
                        if p.addresses.is_empty() {
                            "none".to_string()
                        } else {
                            p.addresses.join(", ")
                        }
                    )),
                    Line::from(format!(
                        "Gateway:      {}",
                        if p.gateway.is_empty() {
                            "--"
                        } else {
                            &p.gateway
                        }
                    )),
                    Line::from(format!(
                        "Metric:       {}",
                        if p.metric.is_empty() { "--" } else { &p.metric }
                    )),
                ]);
            }
            NetworkTab::Routes => {
                lines.push(Line::from(
                    "Destination/prefix       Gateway             Metric",
                ));
                for r in &p.routes {
                    lines.push(Line::from(format!(
                        "{:<25} {:<19} {}",
                        r.destination, r.gateway, r.metric
                    )));
                }
                if p.routes.is_empty() {
                    lines.push(Line::from("No persistent routes"));
                }
            }
            NetworkTab::Dns => {
                lines.push(Line::from(format!(
                    "DNS:     {}",
                    if p.dns.is_empty() {
                        "none".to_string()
                    } else {
                        p.dns.join(", ")
                    }
                )));
                lines.push(Line::from(format!(
                    "Search:  {}",
                    if p.search.is_empty() {
                        "none".to_string()
                    } else {
                        p.search.join(", ")
                    }
                )));
            }
        }
        f.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", p.name))
                    .border_style(Style::default().fg(Color::DarkGray)),
            ),
            panes[1],
        );
    } else {
        f.render_widget(
            Paragraph::new("No NetworkManager profiles found\n\nPress r to refresh.")
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).title(" Details ")),
            panes[1],
        );
    }
    f.render_widget(Paragraph::new(" [Tab] Pane  [h/l] Tab  [j/k] Select  [e] Edit  [a] Add route  [d] Delete route  [r] Refresh  [?] Help  [q] Quit ").block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan))), chunks[2]);
}

fn draw_network_modal(f: &mut ratatui::Frame, app: &App) {
    let Some(form) = &app.network_form else {
        return;
    };
    let area = centered_rect(sixty_percent(form.fields.len()), 45, f.size());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", form.title))
        .border_style(Style::default().fg(Color::Yellow));
    f.render_widget(block, area);
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(vec![Constraint::Length(3); form.fields.len()])
        .split(area);
    for (i, field) in form.fields.iter().enumerate() {
        f.render_widget(
            Paragraph::new(field.value.as_str()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Field {} ", i + 1))
                    .border_style(Style::default().fg(if i == form.field_idx {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    })),
            ),
            inner[i],
        );
    }
    if app.mode == Mode::NetworkConfirm {
        let confirm = centered_rect(60, 30, f.size());
        f.render_widget(Clear, confirm);
        let summary = format!("\n{}\n\nThis changes persistent NetworkManager configuration.\nThe active connection will not be reactivated automatically.\n\nPress y to apply or Esc to cancel.", app.network_action);
        f.render_widget(
            Paragraph::new(summary)
                .alignment(Alignment::Center)
                .wrap(Wrap { trim: true })
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Confirm network change ")
                        .border_style(Style::default().fg(Color::Red)),
                ),
            confirm,
        );
    }
}

fn sixty_percent(fields: usize) -> u16 {
    if fields >= 4 {
        70
    } else {
        60
    }
}

async fn fetch_ruleset() -> Result<Vec<Rule>> {
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
                });
            }
        }
    }
    Ok(rules)
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));
}

#[tokio::main]
async fn main() -> Result<()> {
    install_panic_hook();
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    match fetch_ruleset().await {
        Ok(rules) => {
            app.rules = rules;
            app.update_sidebar();
            app.recompute_visible();
        }
        Err(e) => {
            app.error_msg = e.to_string();
            app.mode = Mode::FatalError;
        }
    }

    let (tx, mut rx) = mpsc::channel::<KeyEvent>(100);
    let input_running = Arc::new(AtomicBool::new(true));
    let input_running_thread = Arc::clone(&input_running);
    std::thread::spawn(move || loop {
        if !input_running_thread.load(Ordering::Relaxed) {
            break;
        }
        if crossterm::event::poll(Duration::from_millis(50)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                if tx.blocking_send(key).is_err() {
                    break;
                }
            }
        }
    });

    let mut refresh_interval = time::interval(Duration::from_secs(5));

    loop {
        terminal.draw(|f| {
            if app.mode == Mode::FatalError {
                let area = f.size();
                let text = format!("\nFailed to load the nftables ruleset:\n\n{}\n\nPress 'r' to retry, 'q' to quit.", app.error_msg);
                let p = Paragraph::new(text)
                    .alignment(Alignment::Center)
                    .wrap(Wrap { trim: true })
                    .block(Block::default().title(" Error ").borders(Borders::ALL).border_style(Style::default().fg(Color::Red)));
                f.render_widget(p, area);
                return;
            }
            if app.section == Section::Network {
                draw_network(f, &app);
                if matches!(app.mode, Mode::NetworkEdit | Mode::NetworkConfirm) { draw_network_modal(f, &app); }
                return;
            }

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
                .split(f.size());

            let header_info = Paragraph::new(format!(
                " Total: {}   Showing: {}   Filter: {} ",
                app.rules.len(),
                app.visible.len(),
                if app.filter.value.is_empty() { "none" } else { &app.filter.value }
            ))
            .style(Style::default().fg(Color::Yellow))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)).title(" NFTables Firewall Dashboard "));
            f.render_widget(header_info, chunks[0]);

            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(20), Constraint::Percentage(80)])
                .split(chunks[1]);

            let sidebar_border = if app.focus == Focus::Sidebar { Color::Yellow } else { Color::DarkGray };
            let sidebar_items: Vec<ListItem> = app.sidebar_items.iter().map(|s| ListItem::new(s.as_str())).collect();
            let sidebar = List::new(sidebar_items)
                .block(Block::default().borders(Borders::ALL).title(" Tables ").border_style(Style::default().fg(sidebar_border)))
                .highlight_style(Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD));
            f.render_stateful_widget(sidebar, main_chunks[0], &mut app.sidebar_state);

            let table_border = if app.focus == Focus::Table { Color::Yellow } else { Color::DarkGray };
            let header = Row::new(vec!["Hndl", "Chain", "Source / Iface", "Dest / Iface", "Proto / Match", "Action", "Counters"])
                .style(Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan));

            let rows = app.visible.iter().map(|&idx| {
                let r = &app.rules[idx];
                Row::new(vec![
                    r.handle.to_string(),
                    truncate_str(&r.chain, 16),
                    truncate_str(&r.parsed.src, 20),
                    truncate_str(&r.parsed.dst, 20),
                    truncate_str(&r.parsed.proto_port, 18),
                    truncate_str(&r.parsed.action, 18),
                    truncate_str(&r.parsed.counters, 16),
                ]).style(Style::default().fg(r.verdict.color()))
            });

            let table = Table::new(
                rows,
                [
                    Constraint::Length(6),       // Hndl
                    Constraint::Percentage(14),  // Chain
                    Constraint::Percentage(18),  // Source / Iface
                    Constraint::Percentage(18),  // Dest / Iface
                    Constraint::Percentage(16),  // Proto / Match
                    Constraint::Percentage(18),  // Action
                    Constraint::Percentage(16),  // Counters
                ],
            )
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(" Rules ").border_style(Style::default().fg(table_border)))
            .highlight_style(Style::default().bg(Color::Rgb(40, 50, 75)).fg(Color::Yellow).add_modifier(Modifier::BOLD))
            .highlight_symbol("▶ ");

            if app.visible.is_empty() && !app.filter.value.trim().is_empty() {
                let msg = format!("No rules match \"{}\".", app.filter.value);
                f.render_widget(Paragraph::new(msg).alignment(Alignment::Center).block(Block::default().borders(Borders::ALL).title(" Rules ").border_style(Style::default().fg(table_border))), main_chunks[1]);
            } else {
                f.render_stateful_widget(table, main_chunks[1], &mut app.table_state);
            }

            let footer_text = match app.mode {
                Mode::Normal => " [Tab] Pane | [j/k] Navigate | [a] Add | [i] Insert | [e] Edit | [x] Delete | [v] Detail | [/] Filter | [n] Network | [?] Help | [q] Quit ",
                Mode::Add | Mode::Insert | Mode::Edit => " [Tab] Switch Field | [Enter] Submit | [Esc] Cancel ",
                Mode::ConfirmDelete => " [y] Confirm Delete | [n/Esc] Cancel ",
                Mode::Filter => " Filter: ",
                Mode::Error => " [Esc/Enter] Dismiss Error ",
                Mode::Detail => " [j/k] Scroll | [Esc/Enter/v] Close ",
                Mode::FatalError => " [r] Retry | [q] Quit ",
                Mode::NetworkEdit => " [Tab] Field | [Enter] Review | [Esc] Cancel ",
                Mode::NetworkConfirm => " [y] Apply | [n/Esc] Cancel ",
            };

            let footer_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(chunks[2]);

            let footer_block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan));
            if app.mode == Mode::Filter {
                let inner = footer_block.inner(footer_layout[0]);
                f.render_widget(footer_block.clone().title(" Filter (live) "), footer_layout[0]);
                f.render_widget(Paragraph::new(app.filter.value.as_str()), inner);
                f.set_cursor((inner.x + app.filter.cursor as u16).min(inner.right().saturating_sub(1)), inner.y);
            } else {
                f.render_widget(Paragraph::new(footer_text).block(footer_block.clone()), footer_layout[0]);
            }
            f.render_widget(
                Paragraph::new(format!(" Status: {}", app.status_msg))
                    .style(Style::default().fg(Color::LightBlue))
                    .alignment(Alignment::Right)
                    .block(footer_block),
                footer_layout[1],
            );

            match app.mode {
                Mode::Add | Mode::Insert | Mode::Edit => {
                    let area = centered_rect(60, 45, f.size());
                    f.render_widget(Clear, area);

                    let title = match app.mode {
                        Mode::Add => " Add Rule (Append) ",
                        Mode::Insert => " Insert Rule (Before Selected) ",
                        _ => " Edit/Replace Rule ",
                    };

                    let modal_block = Block::default()
                        .title(title)
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Yellow));
                    f.render_widget(modal_block, area);

                    let inner_layout = Layout::default()
                        .direction(Direction::Vertical)
                        .margin(2)
                        .constraints([
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(3),
                        ])
                        .split(area);

                    let fields = [
                        ("Family", &app.form.family),
                        ("Table", &app.form.table),
                        ("Chain", &app.form.chain),
                        ("Rule Expression (e.g., 'tcp dport 80 accept')", &app.form.statement),
                    ];

                    for (idx, (label, field)) in fields.iter().enumerate() {
                        let border_color = if app.form.field_idx == idx { Color::Yellow } else { Color::DarkGray };
                        let field_block = Block::default()
                            .borders(Borders::ALL)
                            .title(format!(" {} ", label))
                            .border_style(Style::default().fg(border_color));

                        f.render_widget(Paragraph::new(field.value.as_str()).block(field_block), inner_layout[idx]);
                    }

                    let active_area = inner_layout[app.form.field_idx];
                    let active_field = match app.form.field_idx {
                        0 => &app.form.family,
                        1 => &app.form.table,
                        2 => &app.form.chain,
                        _ => &app.form.statement,
                    };
                    let max_x = active_area.x + active_area.width.saturating_sub(2);
                    let cursor_x = (active_area.x + 1 + active_field.cursor as u16).min(max_x);
                    f.set_cursor(cursor_x, active_area.y + 1);
                }
                Mode::ConfirmDelete => {
                    let area = centered_rect(40, 20, f.size());
                    f.render_widget(Clear, area);

                    if let Some(rule) = app.selected_rule() {
                        let text = format!(
                            "\nAre you sure you want to delete handle {}?\n\nTable: {}\nChain: {}\nRule: {}",
                            rule.handle, rule.table, rule.chain, rule.expression
                        );
                        let p = Paragraph::new(text).alignment(Alignment::Center).wrap(Wrap { trim: true }).block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title(" Warning ")
                                .border_style(Style::default().fg(Color::Red)),
                        );
                        f.render_widget(p, area);
                    }
                }
                Mode::Error => {
                    let area = centered_rect(60, 40, f.size());
                    f.render_widget(Clear, area);
                    let p = Paragraph::new(app.error_msg.as_str()).wrap(Wrap { trim: true }).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(" Command Error ")
                            .border_style(Style::default().fg(Color::Red)),
                    );
                    f.render_widget(p, area);
                }
                Mode::Filter => {}
                Mode::Detail => {
                    if let Some(rule) = app.selected_rule() {
                        let area = centered_rect(80, 70, f.size());
                        f.render_widget(Clear, area);
                        let pretty = serde_json::to_string_pretty(&rule.raw).unwrap_or_default();
                        let text = format!("Family: {}\nTable: {}\nChain: {}\nHandle: {}\n\nFull Statement:\n{}\n\nRaw AST:\n{}", rule.family, rule.table, rule.chain, rule.handle, rule.expression, pretty);
                        let p = Paragraph::new(text)
                            .scroll((app.detail_scroll, 0))
                            .wrap(Wrap { trim: false })
                            .block(Block::default().title(" Rule Inspector (j/k: Scroll) ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)));
                        f.render_widget(p, area);
                    }
                }
                _ => {}
            }
        })?;

        tokio::select! {
            Some(key) = rx.recv() => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') { break; }
                if app.section == Section::Network && app.mode != Mode::Normal {
                    match app.mode {
                        Mode::NetworkEdit => match key.code {
                            KeyCode::Esc => { app.network_form = None; app.mode = Mode::Normal; }
                            KeyCode::Tab => if let Some(form) = app.network_form.as_mut() { form.field_idx = (form.field_idx + 1) % form.fields.len(); },
                            KeyCode::BackTab => if let Some(form) = app.network_form.as_mut() { form.field_idx = if form.field_idx == 0 { form.fields.len() - 1 } else { form.field_idx - 1 }; },
                            KeyCode::Left => if let Some(form) = app.network_form.as_mut() { form.fields[form.field_idx].left(); },
                            KeyCode::Right => if let Some(form) = app.network_form.as_mut() { form.fields[form.field_idx].right(); },
                            KeyCode::Home => if let Some(form) = app.network_form.as_mut() { form.fields[form.field_idx].home(); },
                            KeyCode::End => if let Some(form) = app.network_form.as_mut() { form.fields[form.field_idx].end(); },
                            KeyCode::Backspace => if let Some(form) = app.network_form.as_mut() { form.fields[form.field_idx].backspace(); },
                            KeyCode::Delete => if let Some(form) = app.network_form.as_mut() { form.fields[form.field_idx].delete(); },
                            KeyCode::Char(c) => if let Some(form) = app.network_form.as_mut() { form.fields[form.field_idx].insert(c); },
                            KeyCode::Enter => { app.network_action = "Review the values below before applying.".into(); app.mode = Mode::NetworkConfirm; },
                            _ => {}
                        },
                        Mode::NetworkConfirm => match key.code {
                            KeyCode::Esc | KeyCode::Char('n') => { app.network_form = None; app.mode = Mode::Normal; }
                            KeyCode::Char('y') => {
                                let result = if let (Some(profile), Some(form)) = (app.profiles.get(app.network_selected).cloned(), app.network_form.as_ref()) {
                                    let values: Vec<String> = form.fields.iter().map(|f| f.value.trim().to_string()).collect();
                                    if app.network_action.starts_with("delete") { if let Some(route) = profile.routes.get(app.network_route_selected) { network::remove_route(&profile, route).await } else { Ok(()) } }
                                    else if form.title == "IPv4 configuration" { network::save_ipv4(&profile, &values[0], &values[1], &values[2], &values[3]).await }
                                    else if form.title == "DNS configuration" { network::save_dns(&profile, &values[0], &values[1]).await }
                                    else { let route = network::Route { destination: values[0].clone(), gateway: values[1].clone(), metric: values[2].clone() }; let old = if app.network_action.starts_with("edit") { profile.routes.get(app.network_route_selected) } else { None }; network::save_route(&profile, old, &route).await }
                                } else { Ok(()) };
                                match result { Ok(()) => match network::load_profiles().await { Ok(p) => { app.profiles = p; app.network_selected = app.network_selected.min(app.profiles.len().saturating_sub(1)); app.status_msg = "Persistent network configuration updated".into(); app.network_form = None; app.mode = Mode::Normal; }, Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; } }, Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; } }
                            }
                            _ => {}
                        },
                        Mode::Error => if matches!(key.code, KeyCode::Esc | KeyCode::Enter) { app.mode = Mode::Normal; },
                        _ => {}
                    }
                    continue;
                }
                if app.section == Section::Network && app.mode == Mode::Normal {
                    match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Tab => app.network_focus = !app.network_focus,
                            KeyCode::Char('j') | KeyCode::Down if app.network_focus => { if !app.profiles.is_empty() { app.network_selected = (app.network_selected + 1).min(app.profiles.len() - 1); app.network_route_selected = 0; } },
                            KeyCode::Char('k') | KeyCode::Up if app.network_focus => { app.network_selected = app.network_selected.saturating_sub(1); app.network_route_selected = 0; },
                            KeyCode::Char('j') | KeyCode::Down if app.network_tab == NetworkTab::Routes => if let Some(p) = app.profiles.get(app.network_selected) { app.network_route_selected = (app.network_route_selected + 1).min(p.routes.len().saturating_sub(1)); },
                            KeyCode::Char('k') | KeyCode::Up if app.network_tab == NetworkTab::Routes => app.network_route_selected = app.network_route_selected.saturating_sub(1),
                        KeyCode::Char('h') | KeyCode::Left if !app.network_focus => app.network_tab = app.network_tab.previous(),
                        KeyCode::Char('l') | KeyCode::Right if !app.network_focus => app.network_tab = app.network_tab.next(),
                        KeyCode::Char('r') => match network::load_profiles().await { Ok(p) => { app.profiles = p; app.network_selected = app.network_selected.min(app.profiles.len().saturating_sub(1)); app.status_msg = "Network refreshed".into(); }, Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; } },
                        KeyCode::Char('f') => { app.section = Section::Firewall; app.network_focus = false; },
                        KeyCode::Char('e') => if let Some(p) = app.profiles.get(app.network_selected) { app.network_form = Some(match app.network_tab { NetworkTab::Ipv4 => NetworkForm { field_idx: 0, fields: vec![TextField::from(&p.ipv4_method), TextField::from(&p.addresses.join(", ")), TextField::from(&p.gateway), TextField::from(&p.metric)], title: "IPv4 configuration".into() }, NetworkTab::Dns => NetworkForm { field_idx: 0, fields: vec![TextField::from(&p.dns.join(", ")), TextField::from(&p.search.join(", "))], title: "DNS configuration".into() }, NetworkTab::Routes => if let Some(route) = p.routes.get(app.network_route_selected) { NetworkForm { field_idx: 0, fields: vec![TextField::from(&route.destination), TextField::from(&route.gateway), TextField::from(&route.metric)], title: "Edit persistent route".into() } } else { NetworkForm { field_idx: 0, fields: vec![TextField::default(), TextField::default(), TextField::from("100")], title: "Add persistent route".into() } }, NetworkTab::General => { app.status_msg = "General profile fields are read-only in this version".into(); continue; } }); app.network_action = if app.network_tab == NetworkTab::Routes { "edit persistent route".into() } else { "Review the persistent change".into() }; app.mode = Mode::NetworkEdit; },
                        KeyCode::Char('a') if app.network_tab == NetworkTab::Routes => if app.profiles.get(app.network_selected).is_some() { app.network_form = Some(NetworkForm { field_idx: 0, fields: vec![TextField::default(), TextField::default(), TextField::from("100")], title: "Add persistent route".into() }); app.network_action = "Review adding this persistent route".into(); app.mode = Mode::NetworkEdit; },
                        KeyCode::Char('d') if app.network_tab == NetworkTab::Routes => if let Some(p) = app.profiles.get(app.network_selected) { if let Some(route) = p.routes.get(app.network_route_selected) { app.network_action = format!("delete route {} via {}", route.destination, route.gateway); app.network_form = Some(NetworkForm { field_idx: 0, fields: vec![TextField::default()], title: "Delete persistent route".into() }); app.mode = Mode::NetworkConfirm; } },
                        KeyCode::Char('?') => { app.error_msg = "Network: Tab switches pane; h/l switches tabs; j/k selects profiles or routes; e edits IPv4/DNS/routes; a adds a route; d removes a route; r refreshes; f returns to Firewall; q quits.".into(); app.mode = Mode::Error; },
                        _ => {}
                    }
                    continue;
                }
                match app.mode {
                    Mode::Normal => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Tab => {
                            app.focus = match app.focus {
                                Focus::Sidebar => Focus::Table,
                                Focus::Table => Focus::Sidebar,
                            };
                        }
                        KeyCode::Char('j') | KeyCode::Down => app.next(),
                        KeyCode::Char('k') | KeyCode::Up => app.previous(),
                        KeyCode::Char('a') => {
                            app.form = RuleForm::new();
                            app.mode = Mode::Add;
                        }
                        KeyCode::Char('i') => {
                            if let Some(rule) = app.selected_rule() {
                                let mut form = RuleForm::from_rule(rule);
                                form.statement.clear();
                                app.form = form;
                                app.mode = Mode::Insert;
                            }
                        }
                        KeyCode::Char('e') => {
                            if let Some(rule) = app.selected_rule() {
                                app.form = RuleForm::from_rule(rule);
                                app.mode = Mode::Edit;
                            }
                        }
                        KeyCode::Char('x') => { if app.selected_rule().is_some() { app.mode = Mode::ConfirmDelete; } }
                        KeyCode::Char('v') | KeyCode::Enter => {
                            if app.selected_rule().is_some() {
                                app.detail_scroll = 0;
                                app.mode = Mode::Detail;
                            }
                        }
                        KeyCode::Char('/') => app.mode = Mode::Filter,
                        KeyCode::Char('?') => { app.error_msg = "Firewall: Tab switches pane; j/k navigates; a adds; i inserts; e edits; x deletes; v opens details; / filters live; r refreshes; n opens Network; q quits.".into(); app.mode = Mode::Error; },
                        KeyCode::Char('r') => match fetch_ruleset().await {
                            Ok(r) => { app.rules = r; app.update_sidebar(); app.recompute_visible(); app.status_msg = "Refreshed".to_string(); }
                            Err(e) => app.status_msg = format!("Refresh failed: {}", e),
                        },
                        KeyCode::Char('n') => match network::load_profiles().await {
                            Ok(p) => { app.profiles = p; app.network_selected = 0; app.section = Section::Network; app.network_focus = true; app.status_msg = "Network loaded".into(); }
                            Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; }
                        },
                        _ => {}
                    },
                    Mode::Detail => match key.code {
                        KeyCode::Char('j') | KeyCode::Down => app.detail_scroll = app.detail_scroll.saturating_add(1),
                        KeyCode::Char('k') | KeyCode::Up => app.detail_scroll = app.detail_scroll.saturating_sub(1),
                        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('v') => app.mode = Mode::Normal,
                        _ => {}
                    },
                    Mode::Add | Mode::Insert | Mode::Edit => match key.code {
                        KeyCode::Esc => app.mode = Mode::Normal,
                        KeyCode::Tab => app.form.next_field(),
                        KeyCode::BackTab => app.form.prev_field(),
                        KeyCode::Left if !app.form.location_locked || app.form.field_idx == 3 => app.form.active_field_mut().left(),
                        KeyCode::Right if !app.form.location_locked || app.form.field_idx == 3 => app.form.active_field_mut().right(),
                        KeyCode::Home if !app.form.location_locked || app.form.field_idx == 3 => app.form.active_field_mut().home(),
                        KeyCode::End if !app.form.location_locked || app.form.field_idx == 3 => app.form.active_field_mut().end(),
                        KeyCode::Delete if !app.form.location_locked || app.form.field_idx == 3 => app.form.active_field_mut().delete(),
                        KeyCode::Backspace if !app.form.location_locked || app.form.field_idx == 3 => app.form.active_field_mut().backspace(),
                        KeyCode::Char(c) if !app.form.location_locked || app.form.field_idx == 3 => app.form.active_field_mut().insert(c),
                        KeyCode::Enter => {
                            let family = app.form.family.value.clone();
                            let table = app.form.table.value.clone();
                            let chain = app.form.chain.value.clone();
                            let statement = app.form.statement.value.trim().to_string();

                            if statement.is_empty() {
                                app.status_msg = "Rule expression cannot be empty".to_string();
                            } else {
                                let mut args: Vec<String> = vec![];
                                match app.mode {
                                    Mode::Add => {
                                        args = vec!["add".into(), "rule".into(), family, table, chain, statement];
                                    }
                                    Mode::Insert => {
                                        if let Some(rule) = app.selected_rule() {
                                            args = vec![
                                                "insert".into(),
                                                "rule".into(),
                                                family,
                                                table,
                                                chain,
                                                "handle".into(),
                                                rule.handle.to_string(),
                                                statement,
                                            ];
                                        }
                                    }
                                    Mode::Edit => {
                                        if let Some(rule) = app.selected_rule() {
                                            args = vec![
                                                "replace".into(),
                                                "rule".into(),
                                                family,
                                                table,
                                                chain,
                                                "handle".into(),
                                                rule.handle.to_string(),
                                                statement,
                                            ];
                                        }
                                    }
                                    _ => {}
                                }

                                if !args.is_empty() {
                                    let output = Command::new("nft").args(&args).output().await;
                                    match output {
                                        Ok(out) if out.status.success() => {
                                            app.status_msg = "Command executed successfully".to_string();
                                            app.mode = Mode::Normal;
                                        }
                                        Ok(out) => {
                                            app.error_msg = String::from_utf8_lossy(&out.stderr).into_owned();
                                            app.mode = Mode::Error;
                                        }
                                        Err(e) => {
                                            app.error_msg = format!("Failed to run nft: {}", e);
                                            app.mode = Mode::Error;
                                        }
                                    }
                                }

                                if let Ok(r) = fetch_ruleset().await {
                                    app.rules = r;
                                    app.update_sidebar();
                                    app.recompute_visible();
                                }
                            }
                        }
                        _ => {}
                    },
                    Mode::ConfirmDelete => match key.code {
                        KeyCode::Char('y') => {
                            if let Some(rule) = app.selected_rule() {
                                let output = Command::new("nft")
                                    .args(["delete", "rule", &rule.family, &rule.table, &rule.chain, "handle", &rule.handle.to_string()])
                                    .output()
                                    .await;

                                match output {
                                    Ok(out) if out.status.success() => {
                                        app.status_msg = format!("Deleted handle {}", rule.handle);
                                        app.mode = Mode::Normal;
                                    }
                                    Ok(out) => {
                                        app.error_msg = String::from_utf8_lossy(&out.stderr).into_owned();
                                        app.mode = Mode::Error;
                                    }
                                    Err(e) => {
                                        app.error_msg = format!("Failed to run nft: {}", e);
                                        app.mode = Mode::Error;
                                    }
                                }
                            }
                            if let Ok(r) = fetch_ruleset().await {
                                app.rules = r;
                                app.update_sidebar();
                                app.recompute_visible();
                            }
                        }
                        KeyCode::Char('n') | KeyCode::Esc => app.mode = Mode::Normal,
                        _ => {}
                    },
                    Mode::Filter => match key.code {
                        KeyCode::Esc => {
                            app.filter.clear();
                            app.recompute_visible();
                            app.mode = Mode::Normal;
                        }
                        KeyCode::Enter => app.mode = Mode::Normal,
                        KeyCode::Left => app.filter.left(),
                        KeyCode::Right => app.filter.right(),
                        KeyCode::Home => app.filter.home(),
                        KeyCode::End => app.filter.end(),
                        KeyCode::Delete => {
                            app.filter.delete();
                            app.recompute_visible();
                        }
                        KeyCode::Backspace => {
                            app.filter.backspace();
                            app.recompute_visible();
                        }
                        KeyCode::Char(c) => {
                            app.filter.insert(c);
                            app.recompute_visible();
                        }
                        _ => {}
                    },
                    Mode::Error => match key.code {
                        KeyCode::Esc | KeyCode::Enter => app.mode = Mode::Normal,
                        _ => {}
                    },
                    Mode::FatalError => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('r') => match fetch_ruleset().await {
                            Ok(r) => {
                                app.rules = r;
                                app.update_sidebar();
                                app.recompute_visible();
                                app.status_msg = "Ready".to_string();
                                app.mode = Mode::Normal;
                            }
                            Err(e) => app.error_msg = e.to_string(),
                        },
                        _ => {}
                    },
                    Mode::NetworkEdit | Mode::NetworkConfirm => {}
                }
            }
            _ = refresh_interval.tick() => {
                if app.mode == Mode::Normal {
                    if let Ok(r) = fetch_ruleset().await {
                        app.rules = r;
                        app.update_sidebar();
                        app.recompute_visible();
                    }
                }
            }
        }
    }

    input_running.store(false, Ordering::Relaxed);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
