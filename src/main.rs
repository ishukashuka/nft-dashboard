use anyhow::Result;
use crossterm::{
    cursor::Show,
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{
        Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState, Wrap,
    },
    Terminal,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio::time;
mod firewall;
mod network;
mod rules;
mod sockets;
mod state;
mod views;

use rules::*;
use state::*;
use views::*;

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen, Show);
    }
}

async fn open_firewall(app: &mut App) {
    app.section = Section::Firewall;
    app.network_form = None;
    app.network_focus = false;
    match fetch_ruleset().await {
        Ok(snapshot) => {
            app.apply_firewall_snapshot(snapshot);
            app.error_msg.clear();
            app.status_msg = "Firewall snapshot loaded".into();
            app.mode = Mode::Normal;
        }
        Err(error) => {
            app.error_msg = error.to_string();
            app.mode = Mode::FatalError;
        }
    }
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
    let terminal_guard = TerminalGuard;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    open_firewall(&mut app).await;

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
    refresh_interval.tick().await;

    loop {
        terminal.draw(|f| {
            draw_background(f);
            if app.mode == Mode::FatalError {
                let area = f.size();
                let text = format!("\nAEGIS could not read the nftables ruleset:\n\n{}\n\n[r] Retry firewall   [F2] Network   [F3] Ports   [q] Quit", app.error_msg);
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
                if app.mode == Mode::Error { draw_error_modal(f, &app); }
                if app.mode == Mode::Help { draw_help_modal(f, &app); }
                return;
            }
            if app.section == Section::Ports {
                draw_ports(f, &app);
                if app.mode == Mode::Error { draw_error_modal(f, &app); }
                if app.mode == Mode::Help { draw_help_modal(f, &app); }
                return;
            }

            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
                .split(f.size());

            let hierarchy = if let Some(chain) = app.selected_firewall_chain() {
                format!("Firewall > {}/{} > {}", chain.family, chain.table, chain.name)
            } else if let Some(table) = app.selected_firewall_table() {
                format!("Firewall > {}/{}", table.family, table.name)
            } else {
                "Firewall > All tables".to_string()
            };
            let location = if app.mode == Mode::Detail { format!("{} > Inspector", hierarchy) } else if app.mode == Mode::Filter { format!("{} > Filter", hierarchy) } else { hierarchy };
            let header_info = Paragraph::new(navigation(
                &app.section,
                format!(
                    "{} · {} of {} rules · filter {}",
                    location,
                    app.visible.len(),
                    app.rules.len(),
                    if app.filter.value.is_empty() { "none" } else { &app.filter.value }
                ),
            ))
            .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(ACCENT)));
            f.render_widget(header_info, chunks[0]);

            let main_chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(24), Constraint::Percentage(76)])
                .split(chunks[1]);

            let sidebar_border = if app.focus == Focus::Sidebar { ACTIVE } else { MUTED };
            let sidebar_items: Vec<ListItem> = app.sidebar_items.iter().map(|s| ListItem::new(s.as_str())).collect();
            let sidebar = List::new(sidebar_items)
                .block(Block::default().borders(Borders::ALL).title(" Tables ").border_style(Style::default().fg(sidebar_border)))
                .highlight_style(Style::default().bg(SELECTED).fg(ACTIVE).add_modifier(Modifier::BOLD));
            let hierarchy_panes = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
                .split(main_chunks[0]);
            f.render_stateful_widget(sidebar, hierarchy_panes[0], &mut app.sidebar_state);

            let mut chain_items = vec![ListItem::new("ALL CHAINS")];
            chain_items.extend(app.visible_chains.iter().filter_map(|index| {
                let chain = app.chains.get(*index)?;
                let rule_count = app.rules.iter().filter(|rule| {
                    rule.family == chain.family && rule.table == chain.table && rule.chain == chain.name
                }).count();
                let mut lines = vec![Line::from(format!(
                    "{} · {} rule{}",
                    chain.name,
                    rule_count,
                    if rule_count == 1 { "" } else { "s" }
                ))];
                if chain.hook.is_empty() {
                    lines.push(Line::styled(
                        format!(
                            "  {}",
                            if chain.chain_type.is_empty() {
                                "regular chain"
                            } else {
                                &chain.chain_type
                            }
                        ),
                        Style::default().fg(MUTED),
                    ));
                } else {
                    lines.push(Line::styled(
                        format!(
                            "  type {} · hook {}",
                            if chain.chain_type.is_empty() { "-" } else { &chain.chain_type },
                            chain.hook,
                        ),
                        Style::default().fg(MUTED),
                    ));
                    lines.push(Line::styled(
                        format!(
                            "  priority {} · policy {}",
                            if chain.priority.is_empty() { "-" } else { &chain.priority },
                            if chain.policy.is_empty() { "-" } else { &chain.policy },
                        ),
                        Style::default().fg(MUTED),
                    ));
                }
                Some(ListItem::new(lines))
            }));
            let chain_border = if app.focus == Focus::Chains { ACTIVE } else { MUTED };
            let chain_list = List::new(chain_items)
                .block(Block::default().borders(Borders::ALL).title(" Chains ").border_style(Style::default().fg(chain_border)))
                .highlight_style(Style::default().bg(SELECTED).fg(ACTIVE).add_modifier(Modifier::BOLD));
            f.render_stateful_widget(chain_list, hierarchy_panes[1], &mut app.chain_state);

            let table_border = if app.focus == Focus::Table { ACTIVE } else { MUTED };
            let header = Row::new(vec!["Hndl", "Chain", "Source / Iface", "Dest / Iface", "Proto / Match", "Action", "Counters"])
                .style(Style::default().add_modifier(Modifier::BOLD).fg(ACCENT));

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
            .block(Block::default().borders(Borders::ALL).title(format!(" Rules [Sort: {} {}] ", app.sort_key.title(), if app.sort_reverse { "↓" } else { "↑" })).border_style(Style::default().fg(table_border)))
                .highlight_style(Style::default().bg(SELECTED).fg(ACTIVE).add_modifier(Modifier::BOLD))
            .highlight_symbol("▶ ");

            if app.visible.is_empty() {
                let msg = if !app.filter.value.trim().is_empty() {
                    format!("No rules match \"{}\". Press Esc in Filter to clear it.", app.filter.value)
                } else if let Some(chain) = app.selected_firewall_chain() {
                    format!("Chain {} exists and has 0 rules. Press a to add its first rule.", chain.name)
                } else if let Some(table) = app.selected_firewall_table() {
                    format!("Table {}/{} has no rules in the selected chain scope. Select a chain before adding a rule.", table.family, table.name)
                } else if app.rules.is_empty() {
                    "The ruleset has no rules. Tables and chains remain available in the hierarchy.".to_string()
                } else {
                    "No rules exist in the selected hierarchy scope.".to_string()
                };
                f.render_widget(Paragraph::new(msg).alignment(Alignment::Center).block(Block::default().borders(Borders::ALL).title(" Rules ").border_style(Style::default().fg(table_border))), main_chunks[1]);
            } else {
                f.render_stateful_widget(table, main_chunks[1], &mut app.table_state);
            }

            let footer_text = match app.mode {
                Mode::Normal => " j/k Move  gg/G First/Last  Enter Inspect  a Add  e Edit  x Del  ? Keys ",
                Mode::Add | Mode::Insert | Mode::Edit => " Tab Field  j/k Select  Space Toggle  F4 Advanced  Enter Review  Esc Cancel ",
                Mode::ConfirmDelete => " [y] Confirm Delete | [n/Esc] Cancel ",
                Mode::Filter => " Filter: ",
                Mode::Error => " [Esc/Enter] Dismiss Error ",
                Mode::Help => " [Esc/Enter] Close Help ",
                Mode::Detail => " h/l Tab  j/k Scroll  Esc Back  ? Keys ",
                Mode::FatalError => " [r] Retry | [q] Quit ",
                Mode::NetworkEdit => " [Tab] Field | [Enter] Review | [Esc] Cancel ",
                Mode::NetworkConfirm => " [y] Apply | [n/Esc] Cancel ",
                Mode::RuleReview => " [Enter] Apply | [Esc] Back ",
                Mode::Sort => " [j/k] Choose sort | [Enter] Apply | [Esc] Cancel ",
            };

            let footer_layout = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(74), Constraint::Percentage(26)])
                .split(chunks[2]);

            let footer_block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(ACCENT));
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
                    let area = if app.form.advanced {
                        centered_fixed(112, 20, f.size())
                    } else {
                        centered_rect(78, 82, f.size())
                    };
                    f.render_widget(Clear, area);

                    let title = match app.mode {
                        Mode::Add => " Add Rule (Append) ",
                        Mode::Insert => " Insert Rule (Before Selected) ",
                        _ if app.form.unsupported => " Edit Rule · Advanced nft syntax ",
                        _ => " Edit/Replace Rule ",
                    };

                    let modal_block = Block::default()
                        .title(title)
                        .borders(Borders::ALL)
                        .style(Style::default().bg(MODAL))
                        .border_style(Style::default().fg(ACTIVE));
                    f.render_widget(modal_block, area);

                    if !app.form.advanced {
                        let labels = ["Family", "Table", "Chain", "Protocol", "Source address", "Destination address", "Input interface", "Output interface", "Source port", "Destination port", "CT state", "Verdict", "Target chain", "Comment", "Counter", "Log"];
                        let start = app.form.field_idx.saturating_sub(3);
                        let end = (start + 7).min(labels.len());
                        let visible = Layout::default().direction(Direction::Vertical).margin(2).constraints(vec![Constraint::Length(3); end - start]).split(area);
                        for (row, idx) in (start..end).enumerate() {
                            let value = if idx < 14 { app.form.structured[idx].value.clone() } else if idx == 14 { if app.form.counter { "ON".into() } else { "OFF".into() } } else if app.form.log { "ON".into() } else { "OFF".into() };
                            f.render_widget(Paragraph::new(value).block(Block::default().borders(Borders::ALL).title(format!(" {} {} ", labels[idx], if idx == 3 || idx == 11 { "(j/k select)" } else { "" })).border_style(Style::default().fg(if idx == app.form.field_idx { ACTIVE } else { MUTED }))), visible[row]);
                        }
                        if app.form.field_idx < 14
                            && app.form.field_idx != 3
                            && app.form.field_idx != 11
                            && (!app.form.location_locked || app.form.field_idx > 2)
                        {
                            let active = visible[app.form.field_idx - start];
                            let field = &app.form.structured[app.form.field_idx];
                            let max_x = active.x + active.width.saturating_sub(2);
                            f.set_cursor(
                                (active.x + 1 + field.cursor as u16).min(max_x),
                                active.y + 1,
                            );
                        }
                        let generated = app.form.structured_draft().generated_for_family(&app.form.structured[0].value);
                        f.render_widget(Paragraph::new(format!("Mode: STRUCTURED\n[F4] Advanced   [Space] Toggle   Generated: {}", generated)).wrap(Wrap { trim: true }).block(Block::default().borders(Borders::ALL).title(" Preview ")), area.inner(&ratatui::layout::Margin { vertical: area.height.saturating_sub(5), horizontal: 2 }));
                    } else {
                    let inner_layout = Layout::default()
                        .direction(Direction::Vertical)
                        .margin(2)
                        .constraints([
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(2),
                        ])
                        .split(area);

                    let fields = [
                        (if app.form.location_locked { "Family · read-only" } else { "Family" }, &app.form.family),
                        (if app.form.location_locked { "Table · read-only" } else { "Table" }, &app.form.table),
                        (if app.form.location_locked { "Chain · read-only" } else { "Chain" }, &app.form.chain),
                        ("Exact rule expression", &app.form.statement),
                    ];

                    for (idx, (label, field)) in fields.iter().enumerate() {
                        let border_color = if app.form.field_idx == idx { ACTIVE } else { MUTED };
                        let field_block = Block::default()
                            .borders(Borders::ALL)
                            .title(format!(" {} ", label))
                            .style(Style::default().bg(MODAL))
                            .border_style(Style::default().fg(border_color));
                        let scroll = horizontal_field_scroll(field, inner_layout[idx].width);
                        f.render_widget(
                            Paragraph::new(field.value.as_str())
                                .scroll((0, scroll))
                                .block(field_block),
                            inner_layout[idx],
                        );
                    }

                    f.render_widget(
                        Paragraph::new("[Enter] Review change   [Esc] Cancel   Edit the expression using nft syntax")
                            .style(Style::default().fg(MUTED).bg(MODAL))
                            .alignment(Alignment::Center),
                        inner_layout[4],
                    );

                    let active_area = inner_layout[app.form.field_idx];
                    let active_field = match app.form.field_idx {
                        0 => &app.form.family,
                        1 => &app.form.table,
                        2 => &app.form.chain,
                        _ => &app.form.statement,
                    };
                    let scroll = horizontal_field_scroll(active_field, active_area.width);
                    let max_x = active_area.x + active_area.width.saturating_sub(2);
                    let cursor_x = (active_area.x + 1 + active_field.cursor as u16)
                        .saturating_sub(scroll)
                        .min(max_x);
                    f.set_cursor(cursor_x, active_area.y + 1);
                    }
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
                    draw_error_modal(f, &app);
                }
                Mode::Help => draw_help_modal(f, &app),
                Mode::Filter => {}
                Mode::Detail => {
                    if let Some(rule) = app.selected_rule() {
                        let area = centered_rect(80, 70, f.size());
                        f.render_widget(Clear, area);
                        let tabs = [InspectorTab::Details, InspectorTab::Counters, InspectorTab::RawAst].iter().map(|tab| if *tab == app.inspector_tab { format!("[ {} ]", tab.title()) } else { format!("  {}  ", tab.title()) }).collect::<Vec<_>>().join(" ");
                        let body = match app.inspector_tab {
                            InspectorTab::Details => rule.detail_lines().join("\n"),
                            InspectorTab::Counters => {
                                if rule.parsed.counters == "-" { "No counter data is present on this rule.".to_string() } else { format!("Counters\n\n{}\n\nCounters are read from the nftables rule snapshot.", rule.parsed.counters) }
                            }
                            InspectorTab::RawAst => serde_json::to_string_pretty(&rule.raw).unwrap_or_else(|_| "Unable to render Raw AST.".to_string()),
                        };
                        let text = format!("{}\n\n{}", tabs, body);
                        let p = Paragraph::new(text)
                            .scroll((app.detail_scroll, 0))
                            .wrap(Wrap { trim: false })
                            .block(Block::default().title(" Firewall > Rules > Inspector ").borders(Borders::ALL).border_style(Style::default().fg(ACCENT)));
                        f.render_widget(p, area);
                    }
                }
                Mode::RuleReview => {
                    let area = centered_rect(70, 40, f.size());
                    f.render_widget(Clear, area);
                    let before = if app.pending_operation == RuleOperation::Add { "(new rule)" } else { app.selected_rule().map(|r| r.expression.as_str()).unwrap_or("(rule no longer available)") };
                    let text = format!("Review Rule Change\n\nBefore:\n{}\n\nAfter:\n{}\n\n[Enter] Apply   [Esc] Back", before, app.pending_statement);
                    f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }).alignment(Alignment::Center).block(Block::default().borders(Borders::ALL).title(" Review structured rule ").border_style(Style::default().fg(ACTIVE))), area);
                }
                Mode::Sort => {
                    let area = centered_rect(45, 55, f.size());
                    f.render_widget(Clear, area);
                    let keys = [firewall::SortKey::ChainOrder, firewall::SortKey::Handle, firewall::SortKey::Protocol, firewall::SortKey::Source, firewall::SortKey::Destination, firewall::SortKey::Action, firewall::SortKey::Packets, firewall::SortKey::Bytes];
                    let text = keys.iter().enumerate().map(|(i, k)| format!("{}{}", if i == app.sort_index { "> " } else { "  " }, k.title())).collect::<Vec<_>>().join("\n");
                    f.render_widget(Paragraph::new(text).block(Block::default().borders(Borders::ALL).title(" Sort rules ").border_style(Style::default().fg(ACTIVE))), area);
                }
                _ => {}
            }
        })?;

        tokio::select! {
            Some(key) = rx.recv() => {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') { break; }
                if key.code != KeyCode::Char('g') {
                    app.pending_g = false;
                }
                let section_switch_owned = matches!(app.mode, Mode::Add | Mode::Insert | Mode::Edit | Mode::Filter | Mode::ConfirmDelete | Mode::NetworkEdit | Mode::NetworkConfirm | Mode::RuleReview | Mode::Sort);
                if key.code == KeyCode::F(1) && !section_switch_owned {
                    open_firewall(&mut app).await;
                    continue;
                }
                if key.code == KeyCode::F(2) && !section_switch_owned {
                    match network::load_profiles().await {
                        Ok(p) => { app.profiles = p; app.network_selected = app.network_selected.min(app.profiles.len().saturating_sub(1)); app.repair_network_selection(); app.section = Section::Network; app.mode = Mode::Normal; app.network_focus = true; app.error_msg.clear(); app.status_msg = "Network loaded".into(); }
                        Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; }
                    }
                    continue;
                }
                if key.code == KeyCode::F(3) && !section_switch_owned {
                    let listening = app.socket_tab == SocketTab::Listening;
                    match sockets::client::load(listening).await {
                        Ok(entries) => { app.replace_sockets(entries); if app.section != Section::Ports { app.previous_section = app.section; } app.section = Section::Ports; app.mode = Mode::Normal; app.error_msg.clear(); app.status_msg = "Ports loaded".into(); }
                        Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; }
                    }
                    continue;
                }
                if app.section == Section::Ports && app.mode != Mode::Normal {
                    match app.mode {
                        Mode::Detail => match key.code { KeyCode::Esc => app.mode = Mode::Normal, KeyCode::Char('j') | KeyCode::Down => app.detail_scroll = app.detail_scroll.saturating_add(1), KeyCode::Char('k') | KeyCode::Up => app.detail_scroll = app.detail_scroll.saturating_sub(1), KeyCode::Char('h') | KeyCode::Left => { app.socket_inspector_tab = app.socket_inspector_tab.previous(); app.detail_scroll = 0; }, KeyCode::Char('l') | KeyCode::Right => { app.socket_inspector_tab = app.socket_inspector_tab.next(); app.detail_scroll = 0; }, _ => {} },
                        Mode::Filter => match key.code { KeyCode::Esc => { app.socket_filter.clear(); app.recompute_socket_visible(); app.mode = Mode::Normal; }, KeyCode::Enter => app.mode = Mode::Normal, KeyCode::Left => app.socket_filter.left(), KeyCode::Right => app.socket_filter.right(), KeyCode::Home => app.socket_filter.home(), KeyCode::End => app.socket_filter.end(), KeyCode::Backspace => { app.socket_filter.backspace(); app.recompute_socket_visible(); }, KeyCode::Delete => { app.socket_filter.delete(); app.recompute_socket_visible(); }, KeyCode::Char(c) => { app.socket_filter.insert(c); app.recompute_socket_visible(); }, _ => {} },
                        Mode::Error | Mode::Help => if matches!(key.code, KeyCode::Esc | KeyCode::Enter) { app.error_msg.clear(); app.mode = Mode::Normal; },
                        _ => {}
                    }
                    continue;
                }
                if app.section == Section::Ports && app.mode == Mode::Normal {
                    match key.code {
                        KeyCode::Esc => { if app.previous_section == Section::Firewall { open_firewall(&mut app).await; } else { app.section = app.previous_section; } },
                        KeyCode::Char('q') => break,
                        KeyCode::Char('h') | KeyCode::Left => { app.socket_tab = app.socket_tab.previous(); app.socket_selected = 0; match sockets::client::load(app.socket_tab == SocketTab::Listening).await { Ok(entries) => app.replace_sockets(entries), Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; } } },
                        KeyCode::Char('l') | KeyCode::Right => { app.socket_tab = app.socket_tab.next(); app.socket_selected = 0; match sockets::client::load(app.socket_tab == SocketTab::Listening).await { Ok(entries) => app.replace_sockets(entries), Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; } } },
                        KeyCode::Char('j') | KeyCode::Down => { if !app.socket_visible.is_empty() { app.socket_selected = (app.socket_selected + 1).min(app.socket_visible.len() - 1); } },
                        KeyCode::Char('k') | KeyCode::Up => app.socket_selected = app.socket_selected.saturating_sub(1),
                        KeyCode::Char('g') if app.pending_g => { app.socket_selected = 0; app.pending_g = false; },
                        KeyCode::Char('g') => app.pending_g = true,
                        KeyCode::Char('G') => app.socket_selected = app.socket_visible.len().saturating_sub(1),
                        KeyCode::Enter => if app.selected_socket().is_some() { app.socket_inspector_tab = SocketInspectorTab::Details; app.detail_scroll = 0; app.mode = Mode::Detail; },
                        KeyCode::Char('/') => app.mode = Mode::Filter,
                        KeyCode::Char('r') => match sockets::client::load(app.socket_tab == SocketTab::Listening).await { Ok(entries) => { app.replace_sockets(entries); app.status_msg = "Ports refreshed".into(); }, Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; } },
                        KeyCode::Char('?') => { app.error_msg = "F1 Firewall · F2 Network · F3 Ports\nh/l switches Listening and Connections · j/k selects · gg/G jumps first/last · Enter inspects · / filters · r refreshes · Esc goes back · q quits".into(); app.mode = Mode::Help; },
                        _ => {}
                    }
                    continue;
                }
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
                            KeyCode::Enter => {
                                let valid = if let Some(form) = app.network_form.as_ref() {
                                    if form.title.contains("route") {
                                        let values: Vec<_> = form.fields.iter().map(|f| f.value.trim()).collect();
                                        if !network::valid_ipv4_cidr(values[0]) { app.error_msg = "Destination/Prefix must be a valid IPv4 CIDR or default.".into(); false }
                                        else if !network::valid_ipv4_gateway(values[1]) { app.error_msg = "Gateway must be a valid IPv4 address or empty.".into(); false }
                                        else if !network::valid_metric(values[2]) { app.error_msg = "Metric must be a non-negative integer or empty.".into(); false }
                                        else { app.error_msg.clear(); true }
                                    } else if form.title == "IPv4 configuration" {
                                        let values: Vec<_> = form.fields.iter().map(|f| f.value.trim()).collect();
                                        if !network::valid_ipv4_method(values[0]) { app.error_msg = "Method must be auto, manual, shared, link-local, or disabled.".into(); false }
                                        else if !network::valid_ipv4_addresses(values[1], values[0] == "manual") { app.error_msg = "Addresses must be comma-separated IPv4 CIDRs; manual mode requires at least one.".into(); false }
                                        else if !network::valid_ipv4_gateway(values[2]) { app.error_msg = "Gateway must be a valid IPv4 address or empty.".into(); false }
                                        else if !network::valid_metric(values[3]) { app.error_msg = "Metric must be a non-negative integer or empty.".into(); false }
                                        else { app.error_msg.clear(); true }
                                    } else if form.title == "DNS configuration" {
                                        if !network::valid_dns_servers(form.fields[0].value.trim()) { app.error_msg = "DNS servers must be comma-separated IPv4 or IPv6 addresses.".into(); false }
                                        else { app.error_msg.clear(); true }
                                    } else if form.title == "General configuration" {
                                        if !network::valid_autoconnect(form.fields[0].value.trim()) { app.error_msg = "Autoconnect must be yes or no.".into(); false }
                                        else { app.error_msg.clear(); true }
                                    } else { app.error_msg.clear(); true }
                                } else { false };
                                if valid {
                                    if let Some(form) = app.network_form.as_ref() {
                                        let values = form.fields.iter().map(|field| field.value.trim()).collect::<Vec<_>>().join("  ·  ");
                                        app.network_action = format!("{}\n{}", form.title, values);
                                    }
                                    app.mode = Mode::NetworkConfirm;
                                }
                            },
                            _ => {}
                        },
                        Mode::NetworkConfirm => match key.code {
                            KeyCode::Esc | KeyCode::Char('n') => { app.network_form = None; app.mode = Mode::Normal; }
                            KeyCode::Char('y') => {
                                let result = if let (Some(profile), Some(form)) = (app.selected_network_profile().cloned(), app.network_form.as_ref()) {
                                    let values: Vec<String> = form.fields.iter().map(|f| f.value.trim().to_string()).collect();
                                    if app.network_action.starts_with("delete") { if let Some(route) = profile.routes.get(app.network_route_selected) { network::remove_route(&profile, route).await } else { Ok(()) } }
                                    else if form.title == "General configuration" { network::save_autoconnect(&profile, &values[0]).await }
                                    else if form.title == "IPv4 configuration" { network::save_ipv4(&profile, &values[0], &values[1], &values[2], &values[3]).await }
                                    else if form.title == "DNS configuration" { network::save_dns(&profile, &values[0], &values[1]).await }
                                    else { let route = network::Route { destination: values[0].clone(), gateway: values[1].clone(), metric: values[2].clone() }; let old = if form.title.starts_with("Edit persistent route") { profile.routes.get(app.network_route_selected) } else { None }; network::save_route(&profile, old, &route).await }
                                } else { Ok(()) };
                                match result { Ok(()) => match network::load_profiles().await { Ok(p) => { app.profiles = p; app.network_selected = app.network_selected.min(app.profiles.len().saturating_sub(1)); app.repair_network_selection(); app.status_msg = "Persistent network configuration updated".into(); app.network_form = None; app.mode = Mode::Normal; }, Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; } }, Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; } }
                            }
                            _ => {}
                        },
                        Mode::Filter => match key.code {
                            KeyCode::Esc => { app.network_filter.clear(); app.repair_network_selection(); app.mode = Mode::Normal; },
                            KeyCode::Enter => app.mode = Mode::Normal,
                            KeyCode::Left => app.network_filter.left(),
                            KeyCode::Right => app.network_filter.right(),
                            KeyCode::Home => app.network_filter.home(),
                            KeyCode::End => app.network_filter.end(),
                            KeyCode::Backspace => { app.network_filter.backspace(); app.repair_network_selection(); },
                            KeyCode::Delete => { app.network_filter.delete(); app.repair_network_selection(); },
                            KeyCode::Char(c) => { app.network_filter.insert(c); app.repair_network_selection(); },
                            _ => {}
                        },
                        Mode::Error | Mode::Help => if matches!(key.code, KeyCode::Esc | KeyCode::Enter) { app.error_msg.clear(); app.mode = Mode::Normal; },
                        _ => {}
                    }
                    continue;
                }
                if app.section == Section::Network && app.mode == Mode::Normal {
                    match key.code {
                        KeyCode::Esc => { open_firewall(&mut app).await; },
                        KeyCode::Char('q') => break,
                        KeyCode::Tab => app.network_focus = !app.network_focus,
                            KeyCode::Char('j') | KeyCode::Down if app.network_focus => app.move_network_selection(1),
                            KeyCode::Char('k') | KeyCode::Up if app.network_focus => app.move_network_selection(-1),
                            KeyCode::Char('j') | KeyCode::Down if app.network_tab == NetworkTab::Routes => if let Some(p) = app.selected_network_profile() { app.network_route_selected = (app.network_route_selected + 1).min(p.routes.len().saturating_sub(1)); },
                            KeyCode::Char('k') | KeyCode::Up if app.network_tab == NetworkTab::Routes => app.network_route_selected = app.network_route_selected.saturating_sub(1),
                        KeyCode::Char('g') if app.pending_g => {
                            if app.network_focus { app.go_first_network_profile(); } else if app.network_tab == NetworkTab::Routes { app.network_route_selected = 0; }
                            app.pending_g = false;
                        },
                        KeyCode::Char('g') => app.pending_g = true,
                        KeyCode::Char('G') => {
                            if app.network_focus { app.go_last_network_profile(); } else if app.network_tab == NetworkTab::Routes { if let Some(p) = app.selected_network_profile() { app.network_route_selected = p.routes.len().saturating_sub(1); } }
                        },
                        KeyCode::Char('h') | KeyCode::Left if !app.network_focus => app.network_tab = app.network_tab.previous(),
                        KeyCode::Char('l') | KeyCode::Right if !app.network_focus => app.network_tab = app.network_tab.next(),
                        KeyCode::Char('r') => match network::load_profiles().await { Ok(p) => { app.profiles = p; app.network_selected = app.network_selected.min(app.profiles.len().saturating_sub(1)); app.repair_network_selection(); app.status_msg = "Network refreshed".into(); }, Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; } },
                        KeyCode::Char('/') => app.mode = Mode::Filter,
                        KeyCode::Char('f') => { open_firewall(&mut app).await; },
                        KeyCode::Char('e') => if let Some(p) = app.selected_network_profile() { app.network_form = Some(match app.network_tab { NetworkTab::General => NetworkForm { field_idx: 0, fields: vec![TextField::from(&p.autoconnect)], title: "General configuration".into() }, NetworkTab::Ipv4 => NetworkForm { field_idx: 0, fields: vec![TextField::from(&p.ipv4_method), TextField::from(&p.addresses.join(", ")), TextField::from(&p.gateway), TextField::from(&p.metric)], title: "IPv4 configuration".into() }, NetworkTab::Dns => NetworkForm { field_idx: 0, fields: vec![TextField::from(&p.dns.join(", ")), TextField::from(&p.search.join(", "))], title: "DNS configuration".into() }, NetworkTab::Routes => if let Some(route) = p.routes.get(app.network_route_selected) { NetworkForm { field_idx: 0, fields: vec![TextField::from(&route.destination), TextField::from(&route.gateway), TextField::from(&route.metric)], title: "Edit persistent route".into() } } else { NetworkForm { field_idx: 0, fields: vec![TextField::default(), TextField::default(), TextField::from("100")], title: "Add persistent route".into() } } }); app.network_action = if app.network_tab == NetworkTab::Routes { "edit persistent route".into() } else { "Review the persistent change".into() }; app.mode = Mode::NetworkEdit; },
                        KeyCode::Char('a') if app.network_tab == NetworkTab::Routes => if app.selected_network_profile().is_some() { app.network_form = Some(NetworkForm { field_idx: 0, fields: vec![TextField::default(), TextField::default(), TextField::from("100")], title: "Add persistent route".into() }); app.network_action = "Review adding this persistent route".into(); app.mode = Mode::NetworkEdit; },
                        KeyCode::Char('d') if app.network_tab == NetworkTab::Routes => if let Some(p) = app.selected_network_profile() { if let Some(route) = p.routes.get(app.network_route_selected) { app.network_action = format!("delete route {} via {}", route.destination, route.gateway); app.network_form = Some(NetworkForm { field_idx: 0, fields: vec![TextField::default()], title: "Delete persistent route".into() }); app.mode = Mode::NetworkConfirm; } },
                        KeyCode::Char('?') => { app.error_msg = "Tab switches pane · h/l switches tabs · j/k selects profiles or routes · gg/G jumps first/last · / filters profiles · e edits autoconnect, IPv4, DNS, or routes · a adds a route · d removes a route · r refreshes · f returns to Firewall · q quits".into(); app.mode = Mode::Help; },
                        _ => {}
                    }
                    continue;
                }
                match app.mode {
                    Mode::Normal => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Tab => {
                            app.focus = match app.focus {
                                Focus::Sidebar => Focus::Chains,
                                Focus::Chains => Focus::Table,
                                Focus::Table => Focus::Sidebar,
                            };
                        }
                        KeyCode::Char('j') | KeyCode::Down => app.next(),
                        KeyCode::Char('k') | KeyCode::Up => app.previous(),
                        KeyCode::Char('g') if app.pending_g => { app.go_first(); app.pending_g = false; },
                        KeyCode::Char('g') => app.pending_g = true,
                        KeyCode::Char('G') => app.go_last(),
                        KeyCode::Char('a') => {
                            app.form = app.new_rule_form_for_selection();
                            app.pending_operation = RuleOperation::Add;
                            app.mode = Mode::Add;
                        }
                        KeyCode::Char('i') => {
                            if let Some(rule) = app.selected_rule() {
                                let mut form = RuleForm::from_rule(rule);
                                form.statement.clear();
                                app.form = form;
                                app.pending_operation = RuleOperation::Insert;
                                app.mode = Mode::Insert;
                            }
                        }
                        KeyCode::Char('e') => {
                            if let Some(rule) = app.selected_rule() {
                                let form = RuleForm::from_rule(rule);
                                if form.unsupported && form.statement.value.is_empty() {
                                    app.error_msg = "This rule contains expressions the structured editor cannot safely round-trip, and its exact nft statement was unavailable. Refresh and try again, or inspect its Raw AST before editing it with nft directly.".into();
                                    app.mode = Mode::Error;
                                } else {
                                    app.form = form;
                                    app.pending_operation = RuleOperation::Replace;
                                    app.mode = Mode::Edit;
                                }
                            }
                        }
                        KeyCode::Char('x') => { if app.selected_rule().is_some() { app.mode = Mode::ConfirmDelete; } }
                        KeyCode::Char('v') | KeyCode::Enter => {
                            if app.selected_rule().is_some() {
                                app.detail_scroll = 0;
                                app.inspector_tab = InspectorTab::Details;
                                app.mode = Mode::Detail;
                            }
                        }
                        KeyCode::Char('/') => app.mode = Mode::Filter,
                        KeyCode::Char('s') => app.mode = Mode::Sort,
                        KeyCode::Char('S') => { app.sort_reverse = !app.sort_reverse; app.recompute_visible(); },
                        KeyCode::Char('?') => { app.error_msg = "Tab switches Tables, Chains, and Rules · j/k navigates · gg/G jumps first/last · a appends · i inserts · e edits · x deletes · Enter inspects · / filters · s sorts · r refreshes · F1/F2/F3 changes section · q quits".into(); app.mode = Mode::Help; },
                        KeyCode::Char('r') => match fetch_ruleset().await {
                            Ok(snapshot) => { app.apply_firewall_snapshot(snapshot); app.status_msg = "Refreshed".to_string(); }
                            Err(e) => app.status_msg = format!("Refresh failed: {}", e),
                        },
                        KeyCode::Char('n') => match network::load_profiles().await {
                            Ok(p) => { app.profiles = p; app.network_selected = 0; app.repair_network_selection(); app.section = Section::Network; app.network_focus = true; app.status_msg = "Network loaded".into(); }
                            Err(e) => { app.error_msg = e.to_string(); app.mode = Mode::Error; }
                        },
                        _ => {}
                    },
                    Mode::Detail => match key.code {
                        KeyCode::Char('j') | KeyCode::Down => app.detail_scroll = app.detail_scroll.saturating_add(1),
                        KeyCode::Char('k') | KeyCode::Up => app.detail_scroll = app.detail_scroll.saturating_sub(1),
                        KeyCode::Char('h') | KeyCode::Left => { app.inspector_tab = app.inspector_tab.previous(); app.detail_scroll = 0; },
                        KeyCode::Char('l') | KeyCode::Right => { app.inspector_tab = app.inspector_tab.next(); app.detail_scroll = 0; },
                        KeyCode::Esc => app.mode = Mode::Normal,
                        _ => {}
                    },
                    Mode::RuleReview => match key.code {
                        KeyCode::Esc => app.mode = app.pending_operation.editor_mode(),
                        KeyCode::Enter => {
                            let family = app.form.family.value.clone(); let table = app.form.table.value.clone(); let chain = app.form.chain.value.clone(); let statement = app.pending_statement.clone();
                            let mut args = vec![app.pending_operation.command().into(), "rule".into(), family, table, chain];
                            if app.pending_operation.needs_handle() { if let Some(rule) = app.selected_rule() { args.extend(["handle".into(), rule.handle.to_string()]); } }
                            args.push(statement);
                            match Command::new("nft").args(&args).output().await { Ok(out) if out.status.success() => { app.status_msg = "Structured rule applied successfully".into(); app.mode = Mode::Normal; }, Ok(out) => { app.error_msg = String::from_utf8_lossy(&out.stderr).into_owned(); app.mode = Mode::Error; }, Err(e) => { app.error_msg = format!("Failed to run nft: {}", e); app.mode = Mode::Error; } }
                            if let Ok(snapshot) = fetch_ruleset().await { app.apply_firewall_snapshot(snapshot); }
                        }
                        _ => {}
                    },
                    Mode::Sort => match key.code {
                        KeyCode::Esc => app.mode = Mode::Normal,
                        KeyCode::Char('j') | KeyCode::Down => app.sort_index = (app.sort_index + 1) % 8,
                        KeyCode::Char('k') | KeyCode::Up => app.sort_index = if app.sort_index == 0 { 7 } else { app.sort_index - 1 },
                        KeyCode::Enter => { app.sort_key = [firewall::SortKey::ChainOrder, firewall::SortKey::Handle, firewall::SortKey::Protocol, firewall::SortKey::Source, firewall::SortKey::Destination, firewall::SortKey::Action, firewall::SortKey::Packets, firewall::SortKey::Bytes][app.sort_index]; app.recompute_visible(); app.mode = Mode::Normal; },
                        _ => {}
                    },
                    Mode::Add | Mode::Insert | Mode::Edit => match key.code {
                        KeyCode::Esc => app.mode = Mode::Normal,
                        KeyCode::Tab => app.form.next_field(),
                        KeyCode::BackTab => app.form.prev_field(),
                        KeyCode::F(4) if !app.form.advanced => { app.form.advanced = true; app.form.field_idx = 3; },
                        KeyCode::F(4) if app.form.advanced && !app.form.unsupported => { app.form.advanced = false; app.form.field_idx = 0; },
                        KeyCode::Char('j') | KeyCode::Down if !app.form.advanced && (app.form.field_idx == 3 || app.form.field_idx == 11) => app.form.cycle_selector(1),
                        KeyCode::Char('k') | KeyCode::Up if !app.form.advanced && (app.form.field_idx == 3 || app.form.field_idx == 11) => app.form.cycle_selector(-1),
                        KeyCode::Char(' ') if !app.form.advanced && (app.form.field_idx == 14 || app.form.field_idx == 15) => app.form.toggle_bool(),
                        KeyCode::Left if !app.form.advanced && app.form.field_idx < 14 && (!app.form.location_locked || app.form.field_idx > 2) => app.form.structured_field_mut().left(),
                        KeyCode::Right if !app.form.advanced && app.form.field_idx < 14 && (!app.form.location_locked || app.form.field_idx > 2) => app.form.structured_field_mut().right(),
                        KeyCode::Home if !app.form.advanced && app.form.field_idx < 14 && (!app.form.location_locked || app.form.field_idx > 2) => app.form.structured_field_mut().home(),
                        KeyCode::End if !app.form.advanced && app.form.field_idx < 14 && (!app.form.location_locked || app.form.field_idx > 2) => app.form.structured_field_mut().end(),
                        KeyCode::Backspace if !app.form.advanced && app.form.field_idx < 14 && (!app.form.location_locked || app.form.field_idx > 2) => app.form.structured_field_mut().backspace(),
                        KeyCode::Delete if !app.form.advanced && app.form.field_idx < 14 && (!app.form.location_locked || app.form.field_idx > 2) => app.form.structured_field_mut().delete(),
                        KeyCode::Char(c) if !app.form.advanced && app.form.field_idx < 14 && app.form.field_idx != 3 && app.form.field_idx != 11 && (!app.form.location_locked || app.form.field_idx > 2) => app.form.structured_field_mut().insert(c),
                        KeyCode::Enter if !app.form.advanced => {
                            app.form.family = TextField::from(app.form.structured[0].value.trim());
                            app.form.table = TextField::from(app.form.structured[1].value.trim());
                            app.form.chain = TextField::from(app.form.structured[2].value.trim());
                            let draft = app.form.structured_draft();
                            let location_missing = app.form.family.value.is_empty()
                                || app.form.table.value.is_empty()
                                || app.form.chain.value.is_empty();
                            if location_missing {
                                app.status_msg = "Family, table, and chain are required".into();
                            } else if let Some(error) = draft.validation_error(&app.form.family.value) {
                                app.status_msg = error;
                            } else {
                                app.pending_statement = draft.generated_for_family(&app.form.family.value);
                                app.mode = Mode::RuleReview;
                            }
                        },
                        KeyCode::Enter if app.form.advanced => {
                            let statement = app.form.statement.value.trim().to_string();
                            if app.form.family.value.trim().is_empty()
                                || app.form.table.value.trim().is_empty()
                                || app.form.chain.value.trim().is_empty()
                            {
                                app.status_msg = "Family, table, and chain are required".into();
                            } else if statement.is_empty() {
                                app.status_msg = "Rule expression cannot be empty".to_string();
                            } else {
                                app.pending_statement = statement;
                                app.mode = Mode::RuleReview;
                            }
                        }
                        KeyCode::Left if app.form.advanced && (!app.form.location_locked || app.form.field_idx == 3) => app.form.active_field_mut().left(),
                        KeyCode::Right if app.form.advanced && (!app.form.location_locked || app.form.field_idx == 3) => app.form.active_field_mut().right(),
                        KeyCode::Home if app.form.advanced && (!app.form.location_locked || app.form.field_idx == 3) => app.form.active_field_mut().home(),
                        KeyCode::End if app.form.advanced && (!app.form.location_locked || app.form.field_idx == 3) => app.form.active_field_mut().end(),
                        KeyCode::Delete if app.form.advanced && (!app.form.location_locked || app.form.field_idx == 3) => app.form.active_field_mut().delete(),
                        KeyCode::Backspace if app.form.advanced && (!app.form.location_locked || app.form.field_idx == 3) => app.form.active_field_mut().backspace(),
                        KeyCode::Char(c) if app.form.advanced && (!app.form.location_locked || app.form.field_idx == 3) => app.form.active_field_mut().insert(c),
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
                            if let Ok(snapshot) = fetch_ruleset().await {
                                app.apply_firewall_snapshot(snapshot);
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
                        KeyCode::Esc | KeyCode::Enter => { app.error_msg.clear(); app.mode = Mode::Normal; },
                        _ => {}
                    },
                    Mode::Help => match key.code {
                        KeyCode::Esc | KeyCode::Enter => { app.error_msg.clear(); app.mode = Mode::Normal; },
                        _ => {}
                    },
                    Mode::FatalError => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('r') => match fetch_ruleset().await {
                            Ok(snapshot) => {
                                app.apply_firewall_snapshot(snapshot);
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
                    match app.section {
                        Section::Firewall => if let Ok(snapshot) = fetch_ruleset().await {
                            app.apply_firewall_snapshot(snapshot);
                        },
                        Section::Ports => if let Ok(entries) = sockets::client::load(app.socket_tab == SocketTab::Listening).await {
                            app.replace_sockets(entries);
                        },
                        Section::Network => {}
                    }
                }
            }
        }
    }

    input_running.store(false, Ordering::Relaxed);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    std::mem::forget(terminal_guard);
    Ok(())
}
