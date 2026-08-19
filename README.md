# nft-dashboard

> **Note:** This project was generated with AI assistance. I created this dashboard as a personal tool to help manage `nftables` firewalls visually while learning terminal utilities and Linux networking.

A modern, asynchronous terminal dashboard for managing `nftables` firewall rulesets, built with Rust, Ratatui, Crossterm, and Tokio.

![Rust](https://img.shields.io/badge/rust-2021-orange.svg)
![Platform](https://img.shields.io/badge/platform-linux-blue.svg)

## Features

- **Hierarchical Navigation:** Filter rulesets dynamically by Table/Chain using a dedicated sidebar (`Tab` to toggle focus).
- **Structured Rule Parser:** Automatically breaks down `nftables` JSON AST into dedicated columns: Source, Destination, Protocol/Match, Action, and Counters.
- **Rule Inspector:** Inspect full generated statements and raw JSON trees with vertical scrolling (`v` / `Enter`, `j` / `k`).
- **Rule Management:** Add (`a`), Insert (`i`), Edit/Replace (`e`), and Delete (`x`) rules directly from modal popups.
- **Safety Safeguards:** Deletion confirmation dialogs and `stderr` syntax error popups.
- **Auto-Refresh:** Keeps UI synced in real-time with background changes made by Docker, Libvirt, or Fail2ban.

## Prerequisites

- **Linux Operating System** (Kernel supporting `nftables`)
- **`nft` CLI binary** installed and available in `$PATH`
- **Root/`sudo` access** (required to fetch and modify kernel firewall tables)
- **Rust Toolchain** (if compiling from source)

## Quick Start

1. Clone the repository:
   ```bash
   git clone [https://github.com/ishukashuka/nft-dashboard.git](https://github.com/ishukashuka/nft-dashboard.git)
   cd nft-dashboard
