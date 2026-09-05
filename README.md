# AEGIS Network Control

**Linux networking without making me memorize Linux networking.**

AEGIS is a terminal control plane for inspecting and managing several Linux networking surfaces from one keyboard-first interface:

- nftables rules, counters, filtering, sorting, inspection, and reviewed mutations
- persistent NetworkManager IPv4, DNS, autoconnect, and route configuration
- live listening sockets and active connections with process ownership where permissions allow

AEGIS is built by AI for my own personal use.

I wanted one place where I could look at a Linux machine and understand what its firewall and network configuration were actually doing without constantly translating raw `nft`, `iptables`, `nmcli`, and `ss` output in my head.

The less flattering version is:

> **I'm too stupid to enjoy reading iptables output and too lazy to memorize nftables. So I had AI build me an interface I can actually understand.**

That is essentially why AEGIS exists.

The implementation itself was generated primarily through AI coding agents under my direction and tested against my own systems. It is not professionally security-audited software, and publishing the source does not mean I consider it universally safe for production infrastructure.

---

## Why

Linux already has excellent networking tools.

The problem, for me, was never that `nft`, `nmcli`, or `ss` were incapable.

The problem was that I didn't want to spend my time doing this:

```bash
sudo nft list ruleset
```

and then mentally reconstructing the relationship between tables, chains, rules, expressions, handles, counters, priorities, hooks, and policies every time I needed to change something.

I also didn't want another abstraction that completely hides what Linux is actually doing.

So AEGIS sits in the middle.

It reads the real system state using the normal Linux networking interfaces and presents it in a form that I find easier to navigate, inspect, filter, and modify.

The system still speaks nftables, NetworkManager, and sockets.

AEGIS gives me the interface I wanted on top of them.

---

## Design

AEGIS currently brings together three related networking surfaces.

### Firewall

The Firewall workspace manages nftables:

- tables
- chains
- rules
- counters
- filtering
- sorting
- structured rule inspection
- rule creation and editing
- chain management
- rule movement
- reviewed mutations

AEGIS treats tables, chains, and rules as separate nftables objects.

Empty tables and chains remain visible in the hierarchy, and chain entries show their rule count together with available type, hook, priority, and policy metadata.

### Network

The Network workspace manages persistent NetworkManager configuration, including:

- IPv4 configuration
- DNS
- autoconnect
- gateways
- route metrics
- routes

Changes affect persistent NetworkManager profiles.

AEGIS deliberately does **not** automatically reactivate a connection after editing it.

Automatically bouncing a network connection from a network-management application is an excellent way to disconnect yourself from a remote machine.

### Ports

The Ports workspace shows live socket information, including:

- listening sockets
- active connections
- protocol
- local and remote endpoints
- state
- process
- PID
- user
- address family

Process ownership is shown where the current privileges allow it.

---

## Conservative mutations

AEGIS is deliberately more conservative when writing than when reading.

Firewall and NetworkManager mutations go through a review or confirmation step before execution.

For nftables in particular, AEGIS tries not to pretend it understands rules that it cannot represent correctly.

Complex nftables rules can contain expressions that do not map cleanly into a convenient structured form.

When editing such a rule, AEGIS uses the exact statement reported by `nft` where a lossless representation is available.

If that representation is unavailable, the rule remains read-only instead of silently dropping expressions and producing a different firewall rule.

The basic principle is:

> **If AEGIS cannot represent a mutation without losing information, it should not guess.**

---

## Requirements

AEGIS currently requires:

- Linux
- `nft` for the Firewall workspace
- `nmcli` for the Network workspace
- `ss` for the Ports workspace
- a current stable Rust toolchain to build

Reading or modifying nftables commonly requires root or `CAP_NET_ADMIN`.

Process information from `ss` can also be limited when running without sufficient privileges.

A Firewall permission error does not prevent the Network or Ports workspaces from being used.

---

## Run

Build and run with:

```bash
cargo run --release
```

AEGIS is keyboard-first.

Use:

```text
F1    Firewall
F2    Network
F3    Ports
```

In list views:

```text
j     move down
k     move up
gg    jump to first item
G     jump to last item
?     show workspace help
q     quit
```

The footer displays controls that are valid for the current mode.

---

## Filtering

Press `/` in Firewall, Network, or Ports to open the live filter.

Filters use a small `rg`-inspired query language.

Space-separated terms are combined using AND, so every term must match.

Plain terms search visible fields:

```text
udp
```

Target a specific field with:

```text
proto:udp
```

Exclude a match with:

```text
!action:drop
```

Use quotes for values containing spaces:

```text
comment:"Allow application"
```

Use `re:` for regular expressions:

```text
re:^wg
```

Matching is case-insensitive unless the term contains an uppercase character.

Numeric fields support:

```text
=
>
>=
<
<=
```

and optional `k`, `m`, and `g` suffixes.

Examples:

```text
proto:udp port:1812,1813 action:accept
table:firewall comment:"Application traffic" !action:drop
packets:>1k bytes:>=1m
process:nginx port:>=443 !state:listen
re:^wg address:10.0.0.0/8
```

Invalid fields, expressions, and unfinished quotes are shown inline while the last valid result set remains visible.

---

## Filter fields

Firewall supports:

```text
family
table
chain
handle
src
dst
iface
proto
port
action
comment
packets
bytes
counter
expression
```

Add `@all` to search beyond the currently selected table and chain.

Network supports:

```text
name
type
device
state
autoconnect
method
address
gateway
metric
dns
search
route
```

Ports supports:

```text
proto
local
remote
address
port
process
pid
state
family
user
```

---

## Firewall sorting

In the Firewall workspace, press:

```text
s
```

to select a sort field.

Use:

```text
Shift+S
```

to reverse the current sort direction.

Sorting includes useful firewall properties such as chain order, handle, protocol/match information, source, destination, action, and counters.

---

## Firewall rule editing

Press:

```text
e
```

with a rule selected to edit it.

AEGIS provides a structured editor for rules it can safely model.

The editor can represent common properties including:

- family
- table
- chain
- protocol
- source and destination addresses
- input and output interfaces
- source and destination ports
- connection-tracking state
- verdict
- jump/goto target
- counters
- logging
- comments

A generated nftables expression can be reviewed before the mutation is executed.

Rules containing constructs that the structured editor does not model safely are opened in Advanced mode.

Examples include:

- complex NAT variants
- sets and maps
- limits
- quotas
- marks
- FIB expressions
- other unmodeled statements

The goal is not to support every nftables expression through a pretty form.

The goal is to avoid destroying information when AEGIS encounters something more complicated than its form understands.

---

## Chain management

When the Chains pane is focused:

```text
a     create chain
e     edit chain
X     flush chain
x     delete chain
```

AEGIS can create regular and base chains.

Base-chain creation supports:

- type
- hook
- priority
- policy
- device where required for netdev ingress/egress

The editor allows safe changes such as renaming a chain or changing a base-chain policy.

Type, hook, priority, and device are intentionally immutable after creation.

Changing those properties effectively changes the topology of the chain and can require rebuilding it.

AEGIS does not silently destroy and recreate a live chain to make an edit appear convenient.

Flush and delete operations always require confirmation.

Deletion performs its flush and removal in one nft transaction.

---

## Moving firewall rules

When the Rules pane is focused:

```text
K     move selected rule up
J     move selected rule down
```

Movement is available only when:

- a specific chain is selected
- the filter is empty
- sorting is normal ascending `Chain order`

These restrictions ensure that the visually adjacent rule is also the actual nftables evaluation neighbor.

nftables does not provide a native "move this rule" operation.

AEGIS therefore performs movement by atomically inserting an exact copy at the new position and deleting the old handle.

The review screen warns that:

- the rule handle will change
- hidden runtime state in stateful expressions may reset

Rules without a lossless nftables statement are not moved.

Again, if AEGIS cannot reproduce something safely, it refuses to guess.

---

## Vim-style forms

Rule forms use modal Vim-style controls.

```text
Normal mode    navigate
Insert mode    edit
Visual mode    select text
```

Common controls:

```text
j / k    navigate fields
i        enter Insert mode
v        enter Visual mode
Esc      return to Normal mode
Enter    review from Normal mode
```

I use Vim-style navigation elsewhere, so AEGIS uses it too.

This project is built for my workflow first.

---

## Shell commands

From a main workspace:

```text
:!command
```

runs a non-interactive shell command with AEGIS's current privileges and displays the captured output.

Commands are terminated after 30 seconds.

This is intentionally not an embedded interactive shell.

AEGIS provides a convenient escape hatch for normal system commands without trying to become a terminal multiplexer or shell implementation.

---

## Network configuration

Network edits modify persistent NetworkManager profiles.

AEGIS can manage common properties such as:

- IPv4 addressing
- gateway
- DNS
- DNS search domains
- autoconnect
- route metrics
- static routes

Input is validated before mutation where AEGIS has enough information to do so.

AEGIS intentionally does not reactivate the connection after changing a profile.

The configuration is written persistently, but applying a network change that may terminate the current connection remains an explicit action outside AEGIS.

---

## Development

Run the test suite:

```bash
cargo test --all-targets
```

Run Clippy with warnings treated as errors:

```bash
cargo clippy --all-targets -- -D warnings
```

Check formatting:

```bash
cargo fmt -- --check
```

---

## Built by AI

AEGIS is built by AI for my own personal use.

That wording is intentional.

I came up with what I wanted, made the product and architecture decisions through actual use, tested it on my own machines, reported what broke or felt wrong, and iterated on the result.

The implementation itself was produced primarily by AI coding agents.

I am not publishing this repository to pretend otherwise.

AEGIS exists largely because there are areas of Linux networking that I do not particularly want to learn deeply just to perform ordinary operations comfortably. Rather than forcing myself to memorize every nftables command and expression, I built an interface around the mental model I actually want to use.

That also means the project's confidence should be understood correctly.

Passing tests does not constitute a security audit.

Working on my machines does not mean it will behave correctly on every Linux distribution, NetworkManager configuration, nftables ruleset, or remote server.

The code has not been professionally security-audited or comprehensively independently reviewed by a human developer.

If you want to use AEGIS on your own infrastructure:

- read the code
- understand the commands it executes
- test it somewhere safe
- review mutations before accepting them
- audit the parts relevant to your environment
- fork and harden it if your requirements are different

I use it because it solves my problem.

You should decide whether it solves yours.

---

## What AEGIS is not

AEGIS is not intended to replace:

- nftables
- NetworkManager
- `ss`
- proper firewall knowledge
- proper network engineering
- security review
- your distribution's native networking tools

Those remain the actual system interfaces.

AEGIS is the control surface I wanted on top of them.

It exists because I would rather see the state clearly, review a change, press a key, and move on than spend the afternoon remembering which variation of an nftables command I need.

That is the project.
