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

Filters use a small, `rg`-inspired query language. Space-separated terms are combined with AND, so each term must match. Plain terms search every visible field; use `field:value` to target one field, `!` to exclude matches, double quotes for spaces, and `re:` for a regular expression. Matching is case-insensitive unless the term contains an uppercase character. Numeric fields accept `=`, `>`, `>=`, `<`, and `<=`, with optional `k`, `m`, or `g` suffixes.

```text
proto:udp port:1812,1813 action:accept
table:pintech comment:"RADIUS Auth" !action:drop
packets:>1k bytes:>=1m
process:nginx port:>=443 !state:listen
re:^wg address:10.0.0.0/8
```

Firewall fields are `family`, `table`, `chain`, `handle`, `src`, `dst`, `iface`, `proto`, `port`, `action`, `comment`, `packets`, `bytes`, `counter`, and `expression`. Add `@all` to search beyond the currently selected table and chain. Network fields are `name`, `type`, `device`, `state`, `autoconnect`, `method`, `address`, `gateway`, `metric`, `dns`, `search`, and `route`. Ports fields are `proto`, `local`, `remote`, `address`, `port`, `process`, `pid`, `state`, `family`, and `user`. Invalid fields, expressions, or unfinished quotes are shown inline while the last valid result set remains visible.

The Firewall workspace reads tables, chains, and rules as separate nftables objects. Empty tables and chains remain visible in the hierarchy, and chain entries show their rule count plus available type, hook, priority, and policy metadata.

Chain actions are available when the Chains pane is focused. Press `a` to create a regular or base chain, `e` to rename a chain or change a base-chain policy, `X` to flush all rules while keeping the chain, and `x` to delete it. Creation supports type, hook, priority, policy, and the device required by netdev ingress/egress chains. Type, hook, priority, and device are intentionally immutable in the editor because changing a chain's topology requires rebuilding it; AEGIS does not silently destroy and recreate a live chain. Flush and delete always require confirmation, and deletion performs its flush and removal in one nft transaction.

When the Rules pane is focused, `K` moves the selected rule one evaluation position up and `J` moves it one position down. Movement is available only with a specific chain selected, an empty filter, and the normal ascending `Chain order` sort, so the displayed neighbor is always the real evaluation neighbor. Since nftables has no native move command, AEGIS atomically inserts an exact copy at the new position and deletes the old handle. The review screen warns that the handle changes and that hidden runtime state in stateful expressions may reset; rules without a lossless nft statement are not moved.

Rule forms use modal Vim controls: Normal mode navigates fields with `j`/`k`, Insert mode edits text after `i`, and Visual mode selects text after `v`. Use `Esc` to return to Normal and `Enter` in Normal to review. From any main workspace, `:!command` runs a non-interactive shell command with AEGIS's current privileges and displays its captured output; commands are terminated after 30 seconds.

Network edits change persistent NetworkManager profiles. AEGIS deliberately does not reactivate a connection automatically, because doing so can interrupt remote access.

## Development

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt -- --check
```
