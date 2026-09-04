# AEGIS Network Control

AEGIS is a Linux terminal control plane for inspecting and managing three related network surfaces from one keyboard-first workspace:

- nftables rules, counters, filtering, sorting, inspection, and reviewed mutations
- persistent NetworkManager IPv4, DNS, autoconnect, and route configuration
- live listening sockets and active connections with process ownership where permissions allow

The interface is intentionally conservative around changes. Firewall and NetworkManager writes show a review or confirmation screen before execution. Complex nftables rules open with the exact statement reported by `nft`; if that lossless form is unavailable, AEGIS keeps the rule read-only instead of silently dropping expressions.

## Requirements

- Linux
- `nft` for the Firewall workspace
- `nmcli` for the Network workspace
- `ss` for the Ports workspace
- a current stable Rust toolchain to build

Reading or changing nftables commonly requires root or `CAP_NET_ADMIN`. Process details from `ss` may also be limited for unprivileged users. A Firewall permission error does not prevent using Network or Ports.

## Run

```bash
cargo run --release
```

Use `F1`, `F2`, and `F3` to switch workspaces. In list views, `j`/`k` moves one item, `gg` jumps to the first item, and `G` jumps to the last. Press `?` on any workspace for its local key reference, or `q` to quit. The footer always shows the controls valid for the current mode.

Press `/` in Firewall, Network, or Ports to open a visible live filter. In Firewall, `s` chooses a sort field and `Shift+S` reverses the current sort direction. Press `e` to edit the selected rule; complex NAT, set, and range rules open directly in Advanced mode.

The Firewall workspace reads tables, chains, and rules as separate nftables objects. Empty tables and chains remain visible in the hierarchy, and chain entries show their rule count plus available type, hook, priority, and policy metadata.

Network edits change persistent NetworkManager profiles. AEGIS deliberately does not reactivate a connection automatically, because doing so can interrupt remote access.

## Development

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt -- --check
```
