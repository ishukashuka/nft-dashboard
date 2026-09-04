use crate::{
    chains::{ChainDestructiveAction, ChainForm},
    filter::FilterQuery,
    firewall, network, sockets, FirewallChain, FirewallTable, InspectorTab, Rule, RuleMovePlan,
    RulesetSnapshot, SocketTab,
};
use ratatui::widgets::{ListState, TableState};

#[derive(Debug, Default)]
pub(crate) struct TextField {
    pub(crate) value: String,
    pub(crate) cursor: usize,
}

impl TextField {
    pub(crate) fn from(s: &str) -> Self {
        Self {
            value: s.to_string(),
            cursor: s.chars().count(),
        }
    }
    pub(crate) fn byte_index(&self) -> usize {
        self.value
            .char_indices()
            .nth(self.cursor)
            .map(|(i, _)| i)
            .unwrap_or(self.value.len())
    }
    pub(crate) fn insert(&mut self, c: char) {
        let idx = self.byte_index();
        self.value.insert(idx, c);
        self.cursor += 1;
    }
    pub(crate) fn backspace(&mut self) {
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
    pub(crate) fn delete(&mut self) {
        let idx = self.byte_index();
        if idx < self.value.len() {
            self.value.remove(idx);
        }
    }
    pub(crate) fn left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }
    pub(crate) fn right(&mut self) {
        if self.cursor < self.value.chars().count() {
            self.cursor += 1;
        }
    }
    pub(crate) fn home(&mut self) {
        self.cursor = 0;
    }
    pub(crate) fn end(&mut self) {
        self.cursor = self.value.chars().count();
    }
    pub(crate) fn clear(&mut self) {
        self.value.clear();
        self.cursor = 0;
    }
    pub(crate) fn word_forward(&mut self) {
        let chars = self.value.chars().collect::<Vec<_>>();
        while self.cursor < chars.len() && chars[self.cursor].is_alphanumeric() {
            self.cursor += 1;
        }
        while self.cursor < chars.len() && !chars[self.cursor].is_alphanumeric() {
            self.cursor += 1;
        }
    }
    pub(crate) fn word_backward(&mut self) {
        let chars = self.value.chars().collect::<Vec<_>>();
        while self.cursor > 0 && !chars[self.cursor - 1].is_alphanumeric() {
            self.cursor -= 1;
        }
        while self.cursor > 0 && chars[self.cursor - 1].is_alphanumeric() {
            self.cursor -= 1;
        }
    }
    pub(crate) fn remove_chars(&mut self, start: usize, end: usize) {
        let start_byte = self
            .value
            .char_indices()
            .nth(start)
            .map(|(index, _)| index)
            .unwrap_or(self.value.len());
        let end_byte = self
            .value
            .char_indices()
            .nth(end)
            .map(|(index, _)| index)
            .unwrap_or(self.value.len());
        if start_byte < end_byte {
            self.value.replace_range(start_byte..end_byte, "");
        }
        self.cursor = start.min(self.value.chars().count());
    }
}

#[derive(Debug, PartialEq)]
pub(crate) enum Focus {
    Sidebar,
    Chains,
    Table,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum Section {
    Firewall,
    Network,
    Ports,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum NetworkTab {
    General,
    Ipv4,
    Routes,
    Dns,
}

impl NetworkTab {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::General => Self::Ipv4,
            Self::Ipv4 => Self::Routes,
            Self::Routes => Self::Dns,
            Self::Dns => Self::General,
        }
    }
    pub(crate) fn previous(self) -> Self {
        match self {
            Self::General => Self::Dns,
            Self::Ipv4 => Self::General,
            Self::Routes => Self::Ipv4,
            Self::Dns => Self::Routes,
        }
    }
    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::General => "General",
            Self::Ipv4 => "IPv4",
            Self::Routes => "Routes",
            Self::Dns => "DNS",
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum Mode {
    Normal,
    Add,
    Insert,
    Edit,
    Filter,
    Detail,
    ConfirmDelete,
    Error,
    Help,
    FatalError,
    NetworkEdit,
    NetworkConfirm,
    RuleReview,
    Sort,
    Command,
    CommandOutput,
    ChainEdit,
    ChainReview,
    ChainConfirm,
    RuleMoveReview,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum RuleOperation {
    Add,
    Insert,
    Replace,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum VimMode {
    Normal,
    Insert,
    Visual,
}

impl VimMode {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Insert => "INSERT",
            Self::Visual => "VISUAL",
        }
    }
}

impl RuleOperation {
    pub(crate) fn command(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Insert => "insert",
            Self::Replace => "replace",
        }
    }

    pub(crate) fn editor_mode(self) -> Mode {
        match self {
            Self::Add => Mode::Add,
            Self::Insert => Mode::Insert,
            Self::Replace => Mode::Edit,
        }
    }

    pub(crate) fn needs_handle(self) -> bool {
        self != Self::Add
    }
}

pub(crate) struct RuleForm {
    pub(crate) field_idx: usize,
    pub(crate) family: TextField,
    pub(crate) table: TextField,
    pub(crate) chain: TextField,
    pub(crate) statement: TextField,
    pub(crate) location_locked: bool,
    pub(crate) structured: Vec<TextField>,
    pub(crate) counter: bool,
    pub(crate) log: bool,
    pub(crate) advanced: bool,
    pub(crate) unsupported: bool,
    pub(crate) vim_mode: VimMode,
    pub(crate) visual_anchor: Option<usize>,
}

pub(crate) struct NetworkForm {
    pub(crate) field_idx: usize,
    pub(crate) fields: Vec<TextField>,
    pub(crate) title: String,
}

impl RuleForm {
    pub(crate) fn new() -> Self {
        Self {
            field_idx: 0,
            family: TextField::from("ip"),
            table: TextField::from("filter"),
            chain: TextField::from("INPUT"),
            statement: TextField::from(""),
            location_locked: false,
            structured: vec![
                TextField::from("ip"),
                TextField::from("filter"),
                TextField::from("INPUT"),
                TextField::from("any"),
                TextField::default(),
                TextField::default(),
                TextField::default(),
                TextField::default(),
                TextField::default(),
                TextField::default(),
                TextField::default(),
                TextField::from("accept"),
                TextField::default(),
                TextField::default(),
                TextField::default(),
                TextField::default(),
            ],
            counter: false,
            log: false,
            advanced: false,
            unsupported: false,
            vim_mode: VimMode::Normal,
            visual_anchor: None,
        }
    }
    pub(crate) fn from_rule(rule: &Rule) -> Self {
        let (draft, unsupported) =
            firewall::from_expr(rule.raw.as_array().map(Vec::as_slice).unwrap_or(&[]));
        let mut form = Self::new();
        form.field_idx = if unsupported { 3 } else { 0 };
        form.family = TextField::from(&rule.family);
        form.table = TextField::from(&rule.table);
        form.chain = TextField::from(&rule.chain);
        form.statement = TextField::from(&crate::rules::editable_expression(
            rule.exact_expression.as_deref().unwrap_or(""),
        ));
        form.location_locked = true;
        form.structured = vec![
            TextField::from(&rule.family),
            TextField::from(&rule.table),
            TextField::from(&rule.chain),
            TextField::from(&draft.protocol),
            TextField::from(&draft.source),
            TextField::from(&draft.destination),
            TextField::from(&draft.input),
            TextField::from(&draft.output),
            TextField::from(&draft.source_port),
            TextField::from(&draft.destination_port),
            TextField::from(&draft.ct_state),
            TextField::from(&draft.verdict),
            TextField::from(&draft.target_chain),
            TextField::from(rule.comment.as_deref().unwrap_or("")),
            TextField::default(),
            TextField::default(),
        ];
        form.counter = draft.counter;
        form.log = draft.log;
        form.advanced = unsupported;
        form.unsupported = unsupported;
        form
    }
    pub(crate) fn next_field(&mut self) {
        self.leave_visual();
        if self.advanced && self.location_locked {
            self.field_idx = 3;
            return;
        }
        let max = if self.advanced { 4 } else { 16 };
        self.field_idx = (self.field_idx + 1) % max;
    }
    pub(crate) fn prev_field(&mut self) {
        self.leave_visual();
        if self.advanced && self.location_locked {
            self.field_idx = 3;
            return;
        }
        let max = if self.advanced { 4 } else { 16 };
        self.field_idx = if self.field_idx == 0 {
            max - 1
        } else {
            self.field_idx - 1
        };
    }
    pub(crate) fn active_field_mut(&mut self) -> &mut TextField {
        match self.field_idx {
            0 => &mut self.family,
            1 => &mut self.table,
            2 => &mut self.chain,
            _ => &mut self.statement,
        }
    }

    pub(crate) fn active_text_field_mut(&mut self) -> Option<&mut TextField> {
        if self.advanced {
            if self.location_locked && self.field_idx != 3 {
                return None;
            }
            return Some(self.active_field_mut());
        }
        if self.field_idx >= 14
            || matches!(self.field_idx, 3 | 11)
            || (self.location_locked && self.field_idx <= 2)
        {
            return None;
        }
        Some(self.structured_field_mut())
    }

    pub(crate) fn enter_insert(&mut self) {
        if self.active_text_field_mut().is_some() {
            self.vim_mode = VimMode::Insert;
            self.visual_anchor = None;
        }
    }

    pub(crate) fn enter_visual(&mut self) {
        let Some(field) = self.active_text_field_mut() else {
            return;
        };
        let len = field.value.chars().count();
        if len == 0 {
            return;
        }
        if field.cursor == len {
            field.cursor = len - 1;
        }
        self.visual_anchor = Some(field.cursor);
        self.vim_mode = VimMode::Visual;
    }

    pub(crate) fn leave_visual(&mut self) {
        if self.vim_mode == VimMode::Visual {
            self.vim_mode = VimMode::Normal;
        }
        self.visual_anchor = None;
    }

    pub(crate) fn visual_range(&self, field_index: usize) -> Option<(usize, usize)> {
        if self.vim_mode != VimMode::Visual || self.field_idx != field_index {
            return None;
        }
        let anchor = self.visual_anchor?;
        let field = if self.advanced {
            match field_index {
                0 => &self.family,
                1 => &self.table,
                2 => &self.chain,
                _ => &self.statement,
            }
        } else {
            self.structured.get(field_index)?
        };
        let len = field.value.chars().count();
        if len == 0 {
            return None;
        }
        let cursor = field.cursor.min(len - 1);
        Some((anchor.min(cursor), (anchor.max(cursor) + 1).min(len)))
    }

    pub(crate) fn delete_visual_selection(&mut self, enter_insert: bool) {
        let Some((start, end)) = self.visual_range(self.field_idx) else {
            return;
        };
        if let Some(field) = self.active_text_field_mut() {
            field.remove_chars(start, end);
        }
        self.visual_anchor = None;
        self.vim_mode = if enter_insert {
            VimMode::Insert
        } else {
            VimMode::Normal
        };
    }

    pub(crate) fn first_field(&mut self) {
        self.leave_visual();
        self.field_idx = if self.advanced && self.location_locked {
            3
        } else {
            0
        };
    }

    pub(crate) fn last_field(&mut self) {
        self.leave_visual();
        self.field_idx = if self.advanced { 3 } else { 15 };
    }

    pub(crate) fn structured_field_mut(&mut self) -> &mut TextField {
        let index = self.field_idx.min(self.structured.len() - 1);
        &mut self.structured[index]
    }
    pub(crate) fn cycle_selector(&mut self, delta: i32) {
        let options: &[&str] = if self.field_idx == 3 {
            firewall::RuleDraft::protocols()
        } else if self.field_idx == 11 {
            firewall::RuleDraft::verdicts()
        } else {
            return;
        };
        let current = self.structured[self.field_idx].value.as_str();
        let index = options.iter().position(|v| *v == current).unwrap_or(0) as i32;
        self.structured[self.field_idx].value =
            options[((index + delta).rem_euclid(options.len() as i32)) as usize].into();
        self.structured[self.field_idx].cursor =
            self.structured[self.field_idx].value.chars().count();
    }
    pub(crate) fn toggle_bool(&mut self) {
        if self.field_idx == 14 {
            self.counter = !self.counter;
        }
        if self.field_idx == 15 {
            self.log = !self.log;
        }
    }
    pub(crate) fn structured_draft(&self) -> firewall::RuleDraft {
        let v = |i: usize| {
            self.structured
                .get(i)
                .map(|f| f.value.trim().to_string())
                .unwrap_or_default()
        };
        firewall::RuleDraft {
            protocol: v(3),
            source: v(4),
            destination: v(5),
            input: v(6),
            output: v(7),
            source_port: v(8),
            destination_port: v(9),
            ct_state: v(10),
            verdict: v(11),
            target_chain: v(12),
            counter: self.counter,
            log: self.log,
            comment: v(13),
        }
    }
}

pub(crate) struct App {
    pub(crate) tables: Vec<FirewallTable>,
    pub(crate) chains: Vec<FirewallChain>,
    pub(crate) rules: Vec<Rule>,
    pub(crate) sidebar_items: Vec<String>,
    pub(crate) sidebar_state: ListState,
    pub(crate) visible_chains: Vec<usize>,
    pub(crate) chain_state: ListState,
    pub(crate) visible: Vec<usize>,
    pub(crate) table_state: TableState,
    pub(crate) focus: Focus,
    pub(crate) mode: Mode,
    pub(crate) form: RuleForm,
    pub(crate) filter: TextField,
    pub(crate) filter_error: String,
    firewall_query: FilterQuery,
    pub(crate) network_filter: TextField,
    pub(crate) network_filter_error: String,
    network_query: FilterQuery,
    pub(crate) socket_filter: TextField,
    pub(crate) socket_filter_error: String,
    socket_query: FilterQuery,
    pub(crate) pending_g: bool,
    pub(crate) command: TextField,
    pub(crate) command_output: String,
    pub(crate) command_return_mode: Mode,
    pub(crate) status_msg: String,
    pub(crate) error_msg: String,
    pub(crate) detail_scroll: u16,
    pub(crate) section: Section,
    pub(crate) previous_section: Section,
    pub(crate) profiles: Vec<network::Profile>,
    pub(crate) network_selected: usize,
    pub(crate) network_route_selected: usize,
    pub(crate) network_tab: NetworkTab,
    pub(crate) network_focus: bool,
    pub(crate) network_form: Option<NetworkForm>,
    pub(crate) network_action: String,
    pub(crate) chain_form: Option<ChainForm>,
    pub(crate) chain_destructive_action: ChainDestructiveAction,
    pub(crate) pending_rule_move: Option<RuleMovePlan>,
    pub(crate) sort_key: firewall::SortKey,
    pub(crate) sort_reverse: bool,
    pub(crate) sort_index: usize,
    pub(crate) pending_statement: String,
    pub(crate) pending_operation: RuleOperation,
    pub(crate) inspector_tab: InspectorTab,
    pub(crate) socket_tab: SocketTab,
    pub(crate) sockets: Vec<sockets::model::SocketEntry>,
    pub(crate) socket_visible: Vec<usize>,
    pub(crate) socket_selected: usize,
    pub(crate) socket_inspector_tab: SocketInspectorTab,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub(crate) enum SocketInspectorTab {
    Details,
    Process,
    Raw,
}

impl SocketInspectorTab {
    pub(crate) fn next(self) -> Self {
        match self {
            Self::Details => Self::Process,
            Self::Process => Self::Raw,
            Self::Raw => Self::Details,
        }
    }
    pub(crate) fn previous(self) -> Self {
        match self {
            Self::Details => Self::Raw,
            Self::Process => Self::Details,
            Self::Raw => Self::Process,
        }
    }
    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::Details => "Details",
            Self::Process => "Process",
            Self::Raw => "Raw",
        }
    }
}

impl App {
    pub(crate) fn new() -> Self {
        Self {
            tables: Vec::new(),
            chains: Vec::new(),
            rules: Vec::new(),
            sidebar_items: vec!["ALL".to_string()],
            sidebar_state: ListState::default(),
            visible_chains: Vec::new(),
            chain_state: ListState::default(),
            visible: Vec::new(),
            table_state: TableState::default(),
            focus: Focus::Sidebar,
            mode: Mode::Normal,
            form: RuleForm::new(),
            filter: TextField::default(),
            filter_error: String::new(),
            firewall_query: FilterQuery::default(),
            network_filter: TextField::default(),
            network_filter_error: String::new(),
            network_query: FilterQuery::default(),
            socket_filter: TextField::default(),
            socket_filter_error: String::new(),
            socket_query: FilterQuery::default(),
            pending_g: false,
            command: TextField::default(),
            command_output: String::new(),
            command_return_mode: Mode::Normal,
            status_msg: "Ready".to_string(),
            error_msg: String::new(),
            detail_scroll: 0,
            section: Section::Firewall,
            previous_section: Section::Firewall,
            profiles: Vec::new(),
            network_selected: 0,
            network_route_selected: 0,
            network_tab: NetworkTab::General,
            network_focus: false,
            network_form: None,
            network_action: String::new(),
            chain_form: None,
            chain_destructive_action: ChainDestructiveAction::Delete,
            pending_rule_move: None,
            sort_key: firewall::SortKey::ChainOrder,
            sort_reverse: false,
            sort_index: 0,
            pending_statement: String::new(),
            pending_operation: RuleOperation::Add,
            inspector_tab: InspectorTab::Details,
            socket_tab: SocketTab::Listening,
            sockets: Vec::new(),
            socket_visible: Vec::new(),
            socket_selected: 0,
            socket_inspector_tab: SocketInspectorTab::Details,
        }
    }

    pub(crate) fn update_sidebar(&mut self) {
        let selected = self
            .sidebar_state
            .selected()
            .and_then(|index| self.sidebar_items.get(index))
            .cloned();
        self.tables
            .sort_by(|a, b| (&a.family, &a.name).cmp(&(&b.family, &b.name)));
        self.sidebar_items = std::iter::once("ALL".to_string())
            .chain(
                self.tables
                    .iter()
                    .map(|table| format!("{}/{}", table.family, table.name)),
            )
            .collect();
        let selected_index = selected
            .and_then(|label| self.sidebar_items.iter().position(|item| item == &label))
            .unwrap_or(0);
        self.sidebar_state.select(Some(selected_index));
        self.repair_selection();
        self.recompute_chains();
    }

    pub(crate) fn apply_firewall_snapshot(&mut self, snapshot: RulesetSnapshot) {
        let selected_chain = self.selected_firewall_chain().map(|chain| {
            (
                chain.family.clone(),
                chain.table.clone(),
                chain.name.clone(),
            )
        });
        self.tables = snapshot.tables;
        self.chains = snapshot.chains;
        self.rules = snapshot.rules;
        self.visible_chains.clear();
        self.chain_state.select(Some(0));
        self.update_sidebar();
        if let Some(identity) = selected_chain {
            if let Some(position) = self.visible_chains.iter().position(|index| {
                let chain = &self.chains[*index];
                (
                    chain.family.clone(),
                    chain.table.clone(),
                    chain.name.clone(),
                ) == identity
            }) {
                self.chain_state.select(Some(position + 1));
            }
        }
        self.recompute_visible();
    }

    pub(crate) fn selected_firewall_table(&self) -> Option<&FirewallTable> {
        self.sidebar_state
            .selected()
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| self.tables.get(index))
    }

    pub(crate) fn selected_firewall_chain(&self) -> Option<&FirewallChain> {
        self.chain_state
            .selected()
            .and_then(|index| index.checked_sub(1))
            .and_then(|index| self.visible_chains.get(index))
            .and_then(|index| self.chains.get(*index))
    }

    pub(crate) fn select_firewall_chain(&mut self, family: &str, table: &str, name: &str) {
        if let Some(index) = self
            .tables
            .iter()
            .position(|entry| entry.family == family && entry.name == table)
        {
            self.sidebar_state.select(Some(index + 1));
            self.recompute_chains();
            if let Some(index) = self.visible_chains.iter().position(|index| {
                let chain = &self.chains[*index];
                chain.family == family && chain.table == table && chain.name == name
            }) {
                self.chain_state.select(Some(index + 1));
            }
            self.recompute_visible();
        }
    }

    pub(crate) fn new_rule_form_for_selection(&self) -> RuleForm {
        let mut form = RuleForm::new();
        if let Some(table) = self.selected_firewall_table() {
            form.family = TextField::from(&table.family);
            form.table = TextField::from(&table.name);
            form.structured[0] = TextField::from(&table.family);
            form.structured[1] = TextField::from(&table.name);
            form.chain.clear();
            form.structured[2].clear();
        }
        if let Some(chain) = self.selected_firewall_chain() {
            form.chain = TextField::from(&chain.name);
            form.structured[2] = TextField::from(&chain.name);
        }
        form
    }

    pub(crate) fn recompute_chains(&mut self) {
        let selected_identity = self.selected_firewall_chain().map(|chain| {
            (
                chain.family.clone(),
                chain.table.clone(),
                chain.name.clone(),
            )
        });
        let selected_table = self
            .selected_firewall_table()
            .map(|table| (table.family.clone(), table.name.clone()));
        self.visible_chains = self
            .chains
            .iter()
            .enumerate()
            .filter(|(_, chain)| {
                selected_table
                    .as_ref()
                    .is_none_or(|(family, table)| chain.family == *family && chain.table == *table)
            })
            .map(|(index, _)| index)
            .collect();
        self.visible_chains.sort_by(|left, right| {
            let left = &self.chains[*left];
            let right = &self.chains[*right];
            (&left.family, &left.table, &left.name).cmp(&(&right.family, &right.table, &right.name))
        });
        let selection = selected_identity
            .and_then(|identity| {
                self.visible_chains.iter().position(|index| {
                    let chain = &self.chains[*index];
                    (
                        chain.family.clone(),
                        chain.table.clone(),
                        chain.name.clone(),
                    ) == identity
                })
            })
            .map(|index| index + 1)
            .unwrap_or(0);
        self.chain_state.select(Some(selection));
    }

    pub(crate) fn recompute_visible(&mut self) {
        let selected_identity = self
            .selected_rule()
            .map(|r| (r.family.clone(), r.table.clone(), r.chain.clone(), r.handle));
        match FilterQuery::parse(
            self.filter.value.trim(),
            &[
                "family",
                "table",
                "chain",
                "handle",
                "src",
                "dst",
                "iface",
                "proto",
                "port",
                "action",
                "comment",
                "packets",
                "bytes",
                "counter",
                "expression",
            ],
            &["handle", "packets", "bytes", "port"],
        ) {
            Ok(query) => {
                self.firewall_query = query;
                self.filter_error.clear();
            }
            Err(error) => self.filter_error = error,
        }
        let all_scope = self.firewall_query.all_scope;
        let selected_table = self
            .selected_firewall_table()
            .map(|table| (table.family.clone(), table.name.clone()));
        let selected_chain = self.selected_firewall_chain().map(|chain| {
            (
                chain.family.clone(),
                chain.table.clone(),
                chain.name.clone(),
            )
        });

        self.visible = self
            .rules
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let matches_tree = all_scope
                    || selected_table
                        .as_ref()
                        .is_none_or(|(family, table)| r.family == *family && r.table == *table);
                let matches_chain = all_scope
                    || selected_chain
                        .as_ref()
                        .is_none_or(|(family, table, chain)| {
                            r.family == *family && r.table == *table && r.chain == *chain
                        });
                let (packets, bytes) = parse_counter(&r.parsed.counters);
                let mut fields = vec![
                    ("family", r.family.clone()),
                    ("table", r.table.clone()),
                    ("chain", r.chain.clone()),
                    ("handle", r.handle.to_string()),
                    ("src", r.parsed.src.clone()),
                    ("dst", r.parsed.dst.clone()),
                    ("iface", format!("{} {}", r.parsed.src, r.parsed.dst)),
                    ("proto", r.parsed.proto_port.clone()),
                    ("port", r.parsed.proto_port.clone()),
                    ("action", r.parsed.action.clone()),
                    ("comment", r.comment.clone().unwrap_or_default()),
                    ("packets", packets.to_string()),
                    ("bytes", bytes.to_string()),
                    ("counter", r.parsed.counters.clone()),
                    ("expression", r.expression.clone()),
                ];
                fields.extend(
                    r.filter_port_values()
                        .into_iter()
                        .map(|port| ("port", port)),
                );
                let matches_q = self.firewall_query.matches(&fields);
                matches_tree && matches_chain && matches_q
            })
            .map(|(i, _)| i)
            .collect();
        let key = self.sort_key;
        self.visible.sort_by(|a, b| {
            let ra = &self.rules[*a];
            let rb = &self.rules[*b];
            let result = firewall::compare(&rule_sort_data(ra, *a), &rule_sort_data(rb, *b), key);
            if self.sort_reverse {
                result.reverse()
            } else {
                result
            }
        });

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

    pub(crate) fn next(&mut self) {
        match self.focus {
            Focus::Sidebar => {
                if !self.sidebar_items.is_empty() {
                    let i = match self.sidebar_state.selected() {
                        Some(i) => (i + 1) % self.sidebar_items.len(),
                        None => 0,
                    };
                    self.sidebar_state.select(Some(i));
                    self.recompute_chains();
                    self.recompute_visible();
                }
            }
            Focus::Chains => {
                let count = self.visible_chains.len() + 1;
                let index = (self.chain_state.selected().unwrap_or(0) + 1) % count;
                self.chain_state.select(Some(index));
                self.recompute_visible();
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

    pub(crate) fn previous(&mut self) {
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
                    self.recompute_chains();
                    self.recompute_visible();
                }
            }
            Focus::Chains => {
                let count = self.visible_chains.len() + 1;
                let current = self.chain_state.selected().unwrap_or(0);
                self.chain_state
                    .select(Some(if current == 0 { count - 1 } else { current - 1 }));
                self.recompute_visible();
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

    pub(crate) fn go_first(&mut self) {
        match self.focus {
            Focus::Sidebar => {
                if !self.sidebar_items.is_empty() {
                    self.sidebar_state.select(Some(0));
                    self.recompute_chains();
                    self.recompute_visible();
                }
            }
            Focus::Chains => {
                self.chain_state.select(Some(0));
                self.recompute_visible();
            }
            Focus::Table => {
                if !self.visible.is_empty() {
                    self.table_state.select(Some(0));
                }
            }
        }
    }

    pub(crate) fn go_last(&mut self) {
        match self.focus {
            Focus::Sidebar => {
                if !self.sidebar_items.is_empty() {
                    self.sidebar_state
                        .select(Some(self.sidebar_items.len().saturating_sub(1)));
                    self.recompute_chains();
                    self.recompute_visible();
                }
            }
            Focus::Chains => {
                self.chain_state.select(Some(self.visible_chains.len()));
                self.recompute_visible();
            }
            Focus::Table => {
                if !self.visible.is_empty() {
                    self.table_state
                        .select(Some(self.visible.len().saturating_sub(1)));
                }
            }
        }
    }

    pub(crate) fn selected_rule(&self) -> Option<&Rule> {
        self.table_state
            .selected()
            .and_then(|i| self.visible.get(i))
            .and_then(|&idx| self.rules.get(idx))
    }

    pub(crate) fn repair_selection(&mut self) {
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

    pub(crate) fn recompute_socket_visible(&mut self) {
        match FilterQuery::parse(
            self.socket_filter.value.trim(),
            &[
                "proto", "local", "remote", "address", "port", "process", "pid", "state", "family",
                "user",
            ],
            &["port", "pid"],
        ) {
            Ok(query) => {
                self.socket_query = query;
                self.socket_filter_error.clear();
            }
            Err(error) => self.socket_filter_error = error,
        }
        self.socket_visible = self
            .sockets
            .iter()
            .enumerate()
            .filter(|(_, socket)| {
                let remote_address = socket
                    .remote
                    .as_ref()
                    .map(|endpoint| endpoint.address.clone())
                    .unwrap_or_default();
                let remote_port = socket
                    .remote
                    .as_ref()
                    .map(|endpoint| endpoint.port.clone())
                    .unwrap_or_default();
                let users = socket
                    .owners
                    .iter()
                    .filter_map(|owner| owner.user.clone())
                    .collect::<Vec<_>>()
                    .join(" ");
                self.socket_query.matches(&[
                    ("proto", socket.protocol.clone()),
                    ("local", socket.local.display()),
                    ("remote", format!("{} {}", remote_address, remote_port)),
                    (
                        "address",
                        format!("{} {}", socket.local.address, remote_address),
                    ),
                    ("port", socket.local.port.clone()),
                    ("port", remote_port),
                    ("process", socket.process_name()),
                    ("pid", socket.pid()),
                    ("state", socket.state.clone()),
                    ("family", socket.local.family.clone()),
                    ("user", users),
                ])
            })
            .map(|(i, _)| i)
            .collect();
        self.socket_selected = self
            .socket_selected
            .min(self.socket_visible.len().saturating_sub(1));
    }

    pub(crate) fn network_visible_indices(&self) -> Vec<usize> {
        self.profiles
            .iter()
            .enumerate()
            .filter(|(_, profile)| {
                let routes = profile
                    .routes
                    .iter()
                    .map(|route| {
                        format!("{} {} {}", route.destination, route.gateway, route.metric)
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                self.network_query.matches(&[
                    ("name", profile.name.clone()),
                    ("type", profile.kind.clone()),
                    ("device", profile.device.clone()),
                    ("state", profile.state.clone()),
                    ("autoconnect", profile.autoconnect.clone()),
                    ("method", profile.ipv4_method.clone()),
                    ("address", profile.addresses.join(" ")),
                    ("address", profile.runtime_addresses.join(" ")),
                    ("gateway", profile.gateway.clone()),
                    ("metric", profile.metric.clone()),
                    ("dns", profile.dns.join(" ")),
                    ("search", profile.search.join(" ")),
                    ("route", routes),
                ])
            })
            .map(|(index, _)| index)
            .collect()
    }

    pub(crate) fn update_network_filter(&mut self) {
        match FilterQuery::parse(
            self.network_filter.value.trim(),
            &[
                "name",
                "type",
                "device",
                "state",
                "autoconnect",
                "method",
                "address",
                "gateway",
                "metric",
                "dns",
                "search",
                "route",
            ],
            &["metric"],
        ) {
            Ok(query) => {
                self.network_query = query;
                self.network_filter_error.clear();
            }
            Err(error) => self.network_filter_error = error,
        }
        self.repair_network_selection();
    }

    pub(crate) fn repair_network_selection(&mut self) {
        let visible = self.network_visible_indices();
        if !visible.is_empty() && !visible.contains(&self.network_selected) {
            self.network_selected = visible[0];
            self.network_route_selected = 0;
        }
    }

    pub(crate) fn move_network_selection(&mut self, delta: isize) {
        let visible = self.network_visible_indices();
        if visible.is_empty() {
            return;
        }
        let current = visible
            .iter()
            .position(|index| *index == self.network_selected)
            .unwrap_or(0);
        let next = (current as isize + delta).clamp(0, visible.len() as isize - 1) as usize;
        self.network_selected = visible[next];
        self.network_route_selected = 0;
    }

    pub(crate) fn go_first_network_profile(&mut self) {
        if let Some(index) = self.network_visible_indices().first() {
            self.network_selected = *index;
            self.network_route_selected = 0;
        }
    }

    pub(crate) fn go_last_network_profile(&mut self) {
        if let Some(index) = self.network_visible_indices().last() {
            self.network_selected = *index;
            self.network_route_selected = 0;
        }
    }

    pub(crate) fn selected_network_profile(&self) -> Option<&network::Profile> {
        self.network_visible_indices()
            .contains(&self.network_selected)
            .then(|| self.profiles.get(self.network_selected))
            .flatten()
    }

    pub(crate) fn replace_sockets(&mut self, entries: Vec<sockets::model::SocketEntry>) {
        let identity = self.selected_socket().map(|s| s.identity());
        self.sockets = entries;
        self.recompute_socket_visible();
        if let Some(identity) = identity {
            if let Some(position) = self
                .socket_visible
                .iter()
                .position(|i| self.sockets[*i].identity() == identity)
            {
                self.socket_selected = position;
            }
        }
    }

    pub(crate) fn selected_socket(&self) -> Option<&sockets::model::SocketEntry> {
        self.socket_visible
            .get(self.socket_selected)
            .and_then(|i| self.sockets.get(*i))
    }
}

pub(crate) fn parse_counter(value: &str) -> (u64, u64) {
    let mut packets = 0;
    let mut bytes = 0;
    for part in value.split_whitespace() {
        if let Some(value) = part.strip_suffix('p') {
            packets = value.parse().unwrap_or(0);
        } else if let Some(value) = part.strip_suffix('b') {
            bytes = value.parse().unwrap_or(0);
        }
    }
    (packets, bytes)
}

pub(crate) fn rule_sort_data<'a>(rule: &'a Rule, order: usize) -> firewall::SortData<'a> {
    let (packets, bytes) = parse_counter(&rule.parsed.counters);
    firewall::SortData {
        order,
        handle: rule.handle,
        protocol: &rule.parsed.proto_port,
        source: &rule.parsed.src,
        destination: &rule.parsed.dst,
        action: &rule.parsed.action,
        packets,
        bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_cursor_moves_one_character_at_a_time() {
        let mut field = TextField::from("aéz");
        field.home();
        field.right();
        assert_eq!(field.cursor, 1);
        field.right();
        assert_eq!(field.cursor, 2);
        field.insert('!');
        assert_eq!(field.value, "aé!z");
    }

    #[test]
    fn backspace_removes_a_full_unicode_character() {
        let mut field = TextField::from("aé");
        field.backspace();
        assert_eq!(field.value, "a");
        assert_eq!(field.cursor, 1);
    }

    #[test]
    fn counter_parser_handles_the_display_separator() {
        assert_eq!(parse_counter("12p / 4096b"), (12, 4096));
        assert_eq!(parse_counter("-"), (0, 0));
    }

    #[test]
    fn network_filter_matches_details_and_repairs_selection() {
        let mut app = App::new();
        app.profiles = vec![
            network::Profile {
                name: "lan".into(),
                device: "eth0".into(),
                ..Default::default()
            },
            network::Profile {
                name: "uplink".into(),
                device: "wan0".into(),
                dns: vec!["1.1.1.1".into()],
                ..Default::default()
            },
        ];
        app.network_filter = TextField::from("1.1.1.1");
        app.update_network_filter();
        assert_eq!(app.network_visible_indices(), vec![1]);
        assert_eq!(app.network_selected, 1);
        assert_eq!(app.selected_network_profile().unwrap().name, "uplink");
    }

    #[test]
    fn network_filter_combines_fields_and_keeps_last_valid_query() {
        let mut app = App::new();
        app.profiles = vec![
            network::Profile {
                name: "office-lan".into(),
                device: "eth0".into(),
                state: "activated".into(),
                metric: "100".into(),
                ..Default::default()
            },
            network::Profile {
                name: "backup-wan".into(),
                device: "eth1".into(),
                state: "deactivated".into(),
                metric: "500".into(),
                ..Default::default()
            },
        ];

        app.network_filter = TextField::from("state:activated metric:<200 !device:eth1");
        app.update_network_filter();
        assert_eq!(app.network_visible_indices(), vec![0]);

        app.network_filter = TextField::from("unknown:value");
        app.update_network_filter();
        assert!(!app.network_filter_error.is_empty());
        assert_eq!(app.network_visible_indices(), vec![0]);
    }

    #[test]
    fn socket_filter_combines_protocol_port_process_and_negation() {
        let mut app = App::new();
        app.sockets = vec![
            sockets::model::SocketEntry {
                protocol: "tcp".into(),
                state: "ESTAB".into(),
                local: sockets::model::Endpoint {
                    address: "10.0.0.2".into(),
                    port: "443".into(),
                    family: "inet".into(),
                },
                owners: vec![sockets::model::ProcessOwner {
                    name: "nginx".into(),
                    pid: Some(42),
                    ..Default::default()
                }],
                ..Default::default()
            },
            sockets::model::SocketEntry {
                protocol: "udp".into(),
                state: "UNCONN".into(),
                local: sockets::model::Endpoint {
                    address: "0.0.0.0".into(),
                    port: "53".into(),
                    family: "inet".into(),
                },
                ..Default::default()
            },
        ];

        app.socket_filter = TextField::from("proto:tcp port:>=443 process:nginx !state:listen");
        app.recompute_socket_visible();
        assert_eq!(app.socket_visible, vec![0]);
    }

    #[test]
    fn first_and_last_follow_the_focused_firewall_pane() {
        let mut app = App::new();
        app.visible = vec![4, 8, 15];
        app.focus = Focus::Table;
        app.table_state.select(Some(1));
        app.go_first();
        assert_eq!(app.table_state.selected(), Some(0));
        app.go_last();
        assert_eq!(app.table_state.selected(), Some(2));
    }

    #[test]
    fn empty_tables_and_chains_remain_in_the_hierarchy() {
        let mut app = App::new();
        app.apply_firewall_snapshot(RulesetSnapshot {
            tables: vec![FirewallTable {
                family: "inet".into(),
                name: "pintech".into(),
            }],
            chains: vec![FirewallChain {
                family: "inet".into(),
                table: "pintech".into(),
                name: "pintech_input".into(),
                chain_type: "filter".into(),
                hook: "input".into(),
                priority: "filter".into(),
                policy: "accept".into(),
            }],
            rules: Vec::new(),
        });
        app.sidebar_state.select(Some(1));
        app.recompute_chains();
        app.recompute_visible();

        assert_eq!(app.sidebar_items, vec!["ALL", "inet/pintech"]);
        assert_eq!(app.visible_chains, vec![0]);
        assert!(app.visible.is_empty());
    }

    #[test]
    fn rule_form_supports_modal_insert_and_upward_navigation() {
        let mut form = RuleForm::new();
        assert_eq!(form.vim_mode, VimMode::Normal);
        form.field_idx = 5;
        form.prev_field();
        assert_eq!(form.field_idx, 4);
        form.enter_insert();
        assert_eq!(form.vim_mode, VimMode::Insert);
        form.active_text_field_mut().unwrap().insert('x');
        assert_eq!(form.structured[4].value, "x");
    }

    #[test]
    fn visual_mode_deletes_the_highlighted_character_range() {
        let mut form = RuleForm::new();
        form.field_idx = 4;
        form.structured[4] = TextField::from("hello");
        form.structured[4].home();
        form.enter_visual();
        form.active_text_field_mut().unwrap().right();
        form.active_text_field_mut().unwrap().right();
        assert_eq!(form.visual_range(4), Some((0, 3)));
        form.delete_visual_selection(false);
        assert_eq!(form.structured[4].value, "lo");
        assert_eq!(form.vim_mode, VimMode::Normal);
    }
}
