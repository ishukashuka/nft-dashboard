use crate::*;
use ratatui::text::{Line, Span};

pub(crate) const CANVAS: Color = Color::Rgb(8, 15, 28);
pub(crate) const MODAL: Color = Color::Rgb(13, 23, 38);
pub(crate) const SELECTED: Color = Color::Rgb(29, 55, 82);
pub(crate) const ACCENT: Color = Color::Rgb(44, 211, 225);
pub(crate) const ACTIVE: Color = Color::Rgb(255, 190, 72);
pub(crate) const MUTED: Color = Color::Rgb(105, 130, 153);

pub(crate) fn draw_background(f: &mut ratatui::Frame) {
    f.render_widget(
        Block::default().style(Style::default().bg(CANVAS)),
        f.size(),
    );
}

pub(crate) fn navigation(section: &Section, context: String) -> Line<'static> {
    let tab = |label: &'static str, active: bool| {
        Span::styled(
            if active {
                format!(" ◆ {} ", label)
            } else {
                format!("   {} ", label)
            },
            Style::default()
                .fg(if active { ACTIVE } else { MUTED })
                .add_modifier(if active {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        )
    };
    Line::from(vec![
        Span::styled(
            " AEGIS ",
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" NETWORK CONTROL  ", Style::default().fg(Color::White)),
        tab("F1 FW", *section == Section::Firewall),
        tab("F2 NET", *section == Section::Network),
        tab("F3 PORTS", *section == Section::Ports),
        Span::styled(format!(" │ {} ", context), Style::default().fg(MUTED)),
    ])
}

pub(crate) fn draw_ports(f: &mut ratatui::Frame, app: &App) {
    let tab = app.socket_tab;
    let location = if app.mode == Mode::Detail {
        format!("Ports > {} > Inspector", tab.title())
    } else {
        format!("Ports > {}", tab.title())
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.size());
    let filter_label = if app.socket_filter.value.is_empty() {
        "none"
    } else {
        app.socket_filter.value.as_str()
    };
    f.render_widget(
        Paragraph::new(navigation(
            &app.section,
            format!(
                "{} · {} visible · filter {}",
                location,
                app.socket_visible.len(),
                filter_label
            ),
        ))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" PORTS / LIVE SOCKET MAP ")
                .border_style(Style::default().fg(ACCENT)),
        ),
        chunks[0],
    );
    let tab_label = [SocketTab::Listening, SocketTab::Connections]
        .iter()
        .map(|t| {
            if *t == tab {
                format!("[ {} ]", t.title())
            } else {
                format!("  {}  ", t.title())
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let header = if tab == SocketTab::Listening {
        vec!["Proto", "Local Address", "Port", "Process", "PID", "State"]
    } else {
        vec!["Proto", "Local", "Remote", "Process", "PID", "State"]
    };
    let rows = app
        .socket_visible
        .iter()
        .map(|idx| {
            let s = &app.sockets[*idx];
            let owner = s.process_name();
            if tab == SocketTab::Listening {
                Row::new(vec![
                    s.protocol.clone(),
                    s.local.address.clone(),
                    s.local.port.clone(),
                    owner,
                    s.pid(),
                    s.state.clone(),
                ])
            } else {
                Row::new(vec![
                    s.protocol.clone(),
                    s.local.display(),
                    s.remote
                        .as_ref()
                        .map(|e| e.display())
                        .unwrap_or_else(|| "-".into()),
                    owner,
                    s.pid(),
                    s.state.clone(),
                ])
            }
        })
        .collect::<Vec<_>>();
    let widths = if tab == SocketTab::Listening {
        vec![
            Constraint::Length(7),
            Constraint::Percentage(25),
            Constraint::Length(8),
            Constraint::Percentage(20),
            Constraint::Length(8),
            Constraint::Length(10),
        ]
    } else {
        vec![
            Constraint::Length(7),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(18),
            Constraint::Length(8),
            Constraint::Length(10),
        ]
    };
    let pane = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Min(0)])
        .split(chunks[1]);
    f.render_widget(
        Paragraph::new(tab_label).alignment(Alignment::Center),
        pane[0],
    );
    if app.socket_visible.is_empty() {
        let msg = if app.sockets.is_empty() {
            if tab == SocketTab::Listening {
                "No listening sockets found"
            } else {
                "No active connections found"
            }
        } else {
            "No sockets match the current filter"
        };
        f.render_widget(
            Paragraph::new(msg).alignment(Alignment::Center).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Sockets ")
                    .border_style(Style::default().fg(MUTED)),
            ),
            pane[1],
        );
    } else {
        let table = Table::new(rows, widths)
            .header(
                Row::new(header).style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", location))
                    .border_style(Style::default().fg(ACTIVE)),
            )
            .highlight_style(
                Style::default()
                    .bg(SELECTED)
                    .fg(ACTIVE)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        let mut state = TableState::default();
        state.select(Some(app.socket_selected));
        f.render_stateful_widget(table, pane[1], &mut state);
    }
    let footer: String = if app.mode == Mode::Filter {
        if app.socket_filter_error.is_empty() {
            format!(
                " Filter: {}  · AND · field:value · !exclude · re:pattern ",
                app.socket_filter.value
            )
        } else {
            format!(
                " Filter: {}  · ERROR: {} ",
                app.socket_filter.value, app.socket_filter_error
            )
        }
    } else if app.mode == Mode::Detail {
        " h/l Tab  j/k Scroll  Esc Back  ? Keys ".into()
    } else {
        " h/l Tab  j/k Move  gg/G First/Last  Enter Inspect  / Filter  : Command  r Refresh  ? Keys  q Quit "
            .into()
    };
    let footer_inner = Block::default().borders(Borders::ALL).inner(chunks[2]);
    f.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL).border_style(
            Style::default().fg(if app.socket_filter_error.is_empty() {
                ACCENT
            } else {
                Color::Red
            }),
        )),
        chunks[2],
    );
    if app.mode == Mode::Filter {
        f.set_cursor(
            (footer_inner.x + 9 + app.socket_filter.cursor as u16)
                .min(footer_inner.right().saturating_sub(1)),
            footer_inner.y,
        );
    }
    if app.mode == Mode::Detail {
        if let Some(s) = app.selected_socket() {
            let area = centered_rect(75, 70, f.size());
            f.render_widget(Clear, area);
            let tabs = [
                SocketInspectorTab::Details,
                SocketInspectorTab::Process,
                SocketInspectorTab::Raw,
            ]
            .iter()
            .map(|t| {
                if *t == app.socket_inspector_tab {
                    format!("[ {} ]", t.title())
                } else {
                    format!("  {}  ", t.title())
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
            let body = match app.socket_inspector_tab {
                SocketInspectorTab::Details => format!("Protocol:       {}\nAddress family: {}\nLocal:          {}\nRemote:         {}\nState:           {}\nListening:       {}", s.protocol.to_uppercase(), s.local.family, s.local.display(), s.remote.as_ref().map(|e| e.display()).unwrap_or_else(|| "-".into()), s.state, if s.listening { "yes" } else { "no" }),
                SocketInspectorTab::Process => if s.owners.is_empty() { "No process ownership metadata available (permission or kernel limitation).".into() } else { s.owners.iter().map(|o| format!("Process: {}\nPID:     {}\nFD:      {}", o.name, o.pid.map(|v| v.to_string()).unwrap_or_else(|| "-".into()), o.fd.map(|v| v.to_string()).unwrap_or_else(|| "-".into()))).collect::<Vec<_>>().join("\n\n") },
                SocketInspectorTab::Raw => format!("Protocol: {}\nState: {}\nLocal: {}\nRemote: {}\nOwners: {:?}", s.protocol, s.state, s.local.display(), s.remote.as_ref().map(|e| e.display()).unwrap_or_else(|| "-".into()), s.owners),
            };
            f.render_widget(
                Paragraph::new(format!("{}\n\n{}", tabs, body))
                    .scroll((app.detail_scroll, 0))
                    .wrap(Wrap { trim: false })
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(format!(" {} ", location))
                            .border_style(Style::default().fg(ACCENT)),
                    ),
                area,
            );
        }
    }
}

pub(crate) fn draw_network(f: &mut ratatui::Frame, app: &App) {
    let visible_profiles = app.network_visible_indices();
    let network_location = app
        .selected_network_profile()
        .map(|p| {
            format!(
                "Network > Connections > {} > {}",
                p.name,
                app.network_tab.title()
            )
        })
        .unwrap_or_else(|| "Network > Connections".to_string());
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(f.size());
    let filter_label = if app.network_filter.value.is_empty() {
        "none"
    } else {
        app.network_filter.value.as_str()
    };
    let head = Paragraph::new(navigation(
        &app.section,
        format!(
            "{} · {} of {} profiles · filter {}",
            network_location,
            visible_profiles.len(),
            app.profiles.len(),
            filter_label
        ),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" NETWORK / CONNECTION PROFILES ")
            .border_style(Style::default().fg(ACCENT)),
    );
    f.render_widget(head, chunks[0]);
    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(chunks[1]);
    let items = visible_profiles
        .iter()
        .filter_map(|index| app.profiles.get(*index))
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
    if let Some(position) = visible_profiles
        .iter()
        .position(|index| *index == app.network_selected)
    {
        state.select(Some(position));
    }
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Connections ")
                .border_style(Style::default().fg(if app.network_focus { ACTIVE } else { MUTED })),
        )
        .highlight_style(
            Style::default()
                .bg(SELECTED)
                .fg(ACTIVE)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, panes[0], &mut state);
    if let Some(p) = app.selected_network_profile() {
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
                for (index, r) in p.routes.iter().enumerate() {
                    let selected = index == app.network_route_selected && !app.network_focus;
                    lines.push(Line::styled(
                        format!(
                            "{} {:<25} {:<19} {}",
                            if selected { "▶" } else { " " },
                            r.destination,
                            r.gateway,
                            r.metric
                        ),
                        Style::default().fg(if selected { ACTIVE } else { Color::White }),
                    ));
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
                    .border_style(Style::default().fg(if app.network_focus {
                        MUTED
                    } else {
                        ACTIVE
                    })),
            ),
            panes[1],
        );
    } else {
        let empty_message = if app.profiles.is_empty() {
            "No NetworkManager profiles found\n\nPress r to refresh.".to_string()
        } else {
            format!(
                "No connection profiles match \"{}\".\n\nPress / and Esc to clear the filter.",
                app.network_filter.value
            )
        };
        f.render_widget(
            Paragraph::new(empty_message)
                .alignment(Alignment::Center)
                .block(Block::default().borders(Borders::ALL).title(" Details ")),
            panes[1],
        );
    }
    let footer: String = match app.mode {
        Mode::NetworkEdit => " [Tab] Field  [Enter] Review  [Esc] Cancel ".into(),
        Mode::NetworkConfirm => " [y] Apply  [Esc] Cancel ".into(),
        Mode::Error => " [Esc] Back  [F1/F2/F3] Section ".into(),
        Mode::Filter => format!(
            " Filter: {}  {} ",
            app.network_filter.value,
            if app.network_filter_error.is_empty() {
                "· AND · field:value · !exclude · re:pattern".to_string()
            } else {
                format!("ERROR: {}", app.network_filter_error)
            }
        ),
        _ => " Tab Pane  h/l Tab  j/k Move  gg/G First/Last  / Filter  : Command  e Edit  a Add  d Del  ? Keys  q Quit ".into(),
    };
    let footer_inner = Block::default().borders(Borders::ALL).inner(chunks[2]);
    f.render_widget(
        Paragraph::new(footer).block(Block::default().borders(Borders::ALL).border_style(
            Style::default().fg(if app.network_filter_error.is_empty() {
                ACCENT
            } else {
                Color::Red
            }),
        )),
        chunks[2],
    );
    if app.mode == Mode::Filter {
        f.set_cursor(
            (footer_inner.x + 9 + app.network_filter.cursor as u16)
                .min(footer_inner.right().saturating_sub(1)),
            footer_inner.y,
        );
    }
}

pub(crate) fn draw_network_modal(f: &mut ratatui::Frame, app: &App) {
    let Some(form) = &app.network_form else {
        return;
    };
    let area = centered_rect(sixty_percent(form.fields.len()), 45, f.size());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", form.title))
        .border_style(Style::default().fg(ACTIVE));
    f.render_widget(block, area);
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(vec![Constraint::Length(3); form.fields.len()])
        .split(area);
    for (i, field) in form.fields.iter().enumerate() {
        let labels: Vec<&str> = if form.title == "General configuration" {
            vec!["Autoconnect (yes/no)"]
        } else if form.title.contains("route") {
            vec!["Destination/Prefix", "Gateway", "Metric"]
        } else if form.title.contains("IPv4") {
            vec!["Method", "Addresses", "Gateway", "Metric"]
        } else {
            vec!["DNS servers", "Search domains"]
        };
        f.render_widget(
            Paragraph::new(field.value.as_str()).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" {} ", labels[i]))
                    .border_style(Style::default().fg(if i == form.field_idx {
                        ACTIVE
                    } else {
                        MUTED
                    })),
            ),
            inner[i],
        );
    }
    if app.mode == Mode::NetworkEdit {
        let active = inner[form.field_idx];
        let field = &form.fields[form.field_idx];
        let max_x = active.x + active.width.saturating_sub(2);
        f.set_cursor(
            (active.x + 1 + field.cursor as u16).min(max_x),
            active.y + 1,
        );
    }
    if !app.error_msg.is_empty() && app.mode == Mode::NetworkEdit {
        f.render_widget(
            Paragraph::new(app.error_msg.as_str()).style(Style::default().fg(Color::Red)),
            area.inner(&ratatui::layout::Margin {
                vertical: area.height.saturating_sub(2),
                horizontal: 2,
            }),
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

pub(crate) fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
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

pub(crate) fn centered_fixed(width: u16, height: u16, area: Rect) -> Rect {
    let width = width.min(area.width.saturating_sub(4)).max(1);
    let height = height.min(area.height.saturating_sub(2)).max(1);
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

pub(crate) fn horizontal_field_scroll(field: &TextField, width: u16) -> u16 {
    let visible_width = width.saturating_sub(3) as usize;
    field.cursor.saturating_sub(visible_width) as u16
}

pub(crate) fn vim_field_line(value: &str, selection: Option<(usize, usize)>) -> Line<'static> {
    let Some((start, end)) = selection else {
        return Line::from(value.to_string());
    };
    let byte_at = |character_index: usize| {
        value
            .char_indices()
            .nth(character_index)
            .map(|(byte_index, _)| byte_index)
            .unwrap_or(value.len())
    };
    let start = byte_at(start);
    let end = byte_at(end);
    Line::from(vec![
        Span::raw(value[..start].to_string()),
        Span::styled(
            value[start..end].to_string(),
            Style::default().fg(CANVAS).bg(ACTIVE),
        ),
        Span::raw(value[end..].to_string()),
    ])
}

pub(crate) fn draw_error_modal(f: &mut ratatui::Frame, app: &App) {
    let area = centered_fixed(96, 9, f.size());
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(format!("{}\n\n[Esc/Enter] Dismiss", app.error_msg))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" AEGIS · Action failed ")
                    .style(Style::default().bg(MODAL))
                    .border_style(Style::default().fg(Color::Red)),
            ),
        area,
    );
}

pub(crate) fn draw_help_modal(f: &mut ratatui::Frame, app: &App) {
    let area = centered_fixed(104, 16, f.size());
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(format!(
            "AEGIS QUICK REFERENCE\n\n{}\n\n[Esc/Enter] Close",
            app.error_msg
        ))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Help ")
                .style(Style::default().bg(MODAL))
                .border_style(Style::default().fg(ACCENT)),
        ),
        area,
    );
}

pub(crate) fn draw_chain_modal(f: &mut ratatui::Frame, app: &App) {
    let area = centered_fixed(90, 22, f.size());
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(match app.mode {
            Mode::ChainEdit => " Chain editor ",
            Mode::ChainReview => " Review chain transaction ",
            Mode::ChainConfirm => " Destructive chain action ",
            _ => " Chain ",
        })
        .style(Style::default().bg(MODAL))
        .border_style(Style::default().fg(match app.mode {
            Mode::ChainConfirm => Color::Red,
            Mode::ChainReview => ACTIVE,
            _ => ACCENT,
        }));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if app.mode == Mode::ChainConfirm {
        if let Some(chain) = app.selected_firewall_chain() {
            let count = app
                .rules
                .iter()
                .filter(|rule| {
                    rule.family == chain.family
                        && rule.table == chain.table
                        && rule.chain == chain.name
                })
                .count();
            let text = match app.chain_destructive_action {
                ChainDestructiveAction::Flush => format!(
                    "FLUSH {}/{} > {}\n\nThis permanently removes {} rule{}. The chain remains.\n\n[y] Confirm flush   [Esc/n] Cancel",
                    chain.family,
                    chain.table,
                    chain.name,
                    count,
                    if count == 1 { "" } else { "s" }
                ),
                ChainDestructiveAction::Delete => format!(
                    "DELETE {}/{} > {}\n\nThis flushes {} rule{} and deletes the chain in one nft transaction. References from other chains may prevent deletion.\n\n[y] Confirm delete   [Esc/n] Cancel",
                    chain.family,
                    chain.table,
                    chain.name,
                    count,
                    if count == 1 { "" } else { "s" }
                ),
            };
            f.render_widget(
                Paragraph::new(text)
                    .alignment(Alignment::Center)
                    .wrap(Wrap { trim: true }),
                inner,
            );
        }
        return;
    }

    let Some(form) = app.chain_form.as_ref() else {
        return;
    };
    if app.mode == Mode::ChainReview {
        f.render_widget(
            Paragraph::new(format!(
                "{}\n\n[Enter] Apply atomically   [Esc] Back",
                form.review()
            ))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
            inner,
        );
        return;
    }

    let values = [
        format!("Name       {}", form.name.value),
        format!(
            "Kind       < {} >",
            if form.base_chain { "base" } else { "regular" }
        ),
        format!("Type       {}", form.chain_type.value),
        format!("Hook       {}", form.hook.value),
        format!("Priority   {}", form.priority.value),
        format!("Policy     < {} >", form.policy.value),
        format!("Device     {}", form.device.value),
    ];
    let active = form.actual_field_index();
    let mut lines = vec![
        Line::from(format!("Location   {}/{}", form.family, form.table)),
        Line::from(""),
    ];
    for (index, value) in values.iter().enumerate() {
        let visible = if form.operation == ChainOperation::Add {
            index <= 1 || form.base_chain
        } else {
            index == 0 || (form.base_chain && matches!(index, 2..=5))
        };
        if visible {
            lines.push(Line::styled(
                value.clone(),
                if index == active {
                    Style::default().fg(ACTIVE).add_modifier(Modifier::BOLD)
                } else if form.operation == ChainOperation::Edit && !matches!(index, 0 | 5) {
                    Style::default().fg(MUTED)
                } else {
                    Style::default()
                },
            ));
        } else {
            lines.push(Line::from(""));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(
        if form.operation == ChainOperation::Edit {
            "Type, hook and priority are immutable. NORMAL: j/k field · h/l choice · i edit · Enter review · Esc cancel"
        } else {
            "NORMAL: j/k field · h/l choice · i edit · Enter review · Esc cancel"
        },
        Style::default().fg(MUTED),
    ));
    lines.push(Line::styled(
        format!("-- {} --", form.vim_mode.label()),
        Style::default().fg(if form.vim_mode == VimMode::Insert {
            ACTIVE
        } else {
            ACCENT
        }),
    ));
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);

    if form.vim_mode == VimMode::Insert {
        if let Some(field) = match active {
            0 => Some(&form.name),
            2 => Some(&form.chain_type),
            3 => Some(&form.hook),
            4 => Some(&form.priority),
            6 => Some(&form.device),
            _ => None,
        } {
            let label_width = 11;
            f.set_cursor(
                (inner.x + label_width + field.cursor as u16).min(inner.right().saturating_sub(1)),
                inner.y + 2 + active as u16,
            );
        }
    }
}

pub(crate) fn draw_rule_move_modal(f: &mut ratatui::Frame, app: &App) {
    let area = centered_fixed(100, 22, f.size());
    f.render_widget(Clear, area);
    let text = app
        .pending_rule_move
        .as_ref()
        .map(RuleMovePlan::preview)
        .unwrap_or_else(|| "The rule move is no longer available.".into());
    f.render_widget(
        Paragraph::new(format!(
            "{}\n\n[Enter] Apply atomically   [Esc] Cancel",
            text
        ))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Review evaluation-order change ")
                .style(Style::default().bg(MODAL))
                .border_style(Style::default().fg(ACTIVE)),
        ),
        area,
    );
}

pub(crate) fn draw_command_bar(f: &mut ratatui::Frame, app: &App) {
    let screen = f.size();
    let area = Rect::new(
        screen.x + 1,
        screen.bottom().saturating_sub(3),
        screen.width.saturating_sub(2).max(1),
        3.min(screen.height),
    );
    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Command · :! runs with AEGIS privileges ")
        .style(Style::default().bg(MODAL))
        .border_style(Style::default().fg(ACTIVE));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let scroll = horizontal_field_scroll(&app.command, inner.width.saturating_sub(1));
    f.render_widget(
        Paragraph::new(format!(":{}", app.command.value))
            .scroll((0, scroll))
            .style(Style::default().bg(MODAL)),
        inner,
    );
    f.set_cursor(
        (inner.x + 1 + app.command.cursor as u16)
            .saturating_sub(scroll)
            .min(inner.right().saturating_sub(1)),
        inner.y,
    );
}

pub(crate) fn draw_command_output(f: &mut ratatui::Frame, app: &App) {
    let area = centered_rect(72, 70, f.size());
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(app.command_output.as_str())
            .scroll((app.detail_scroll, 0))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Shell output · j/k scroll · Esc/Enter close ")
                    .style(Style::default().bg(MODAL))
                    .border_style(Style::default().fg(ACCENT)),
            ),
        area,
    );
}
