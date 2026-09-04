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
        format!(
            " Filter: {}  [Enter] Keep  [Esc] Clear ",
            app.socket_filter.value
        )
    } else if app.mode == Mode::Detail {
        " h/l Tab  j/k Scroll  Esc Back  ? Keys ".into()
    } else {
        " h/l Tab  j/k Move  gg/G First/Last  Enter Inspect  / Filter  r Refresh  ? Keys  q Quit "
            .into()
    };
    let footer_inner = Block::default().borders(Borders::ALL).inner(chunks[2]);
    f.render_widget(
        Paragraph::new(footer).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT)),
        ),
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
            " Filter: {}  [Enter] Keep  [Esc] Clear ",
            app.network_filter.value
        ),
        _ => " Tab Pane  h/l Tab  j/k Move  gg/G First/Last  / Filter  e Edit  a Add  d Del  ? Keys  q Quit ".into(),
    };
    let footer_inner = Block::default().borders(Borders::ALL).inner(chunks[2]);
    f.render_widget(
        Paragraph::new(footer).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT)),
        ),
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
