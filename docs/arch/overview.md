# Overview: Network Design

wganchor exposes a VPS's secondary public IP as a locally-bindable address
on a home machine, tunneled over WireGuard. This doc covers the network
topology and the core routing facts the rest of the design depends on.
Interface/key/config mechanics are in `wireguard.md`; failure detection and
self-repair are in `resilience.md`.

> IPs in this doc (and throughout `docs/`) are RFC 5737 TEST-NET-3
> placeholders, not the real deployment's addresses: `203.0.113.10` stands
> in for the VPS primary/management IP, `203.0.113.20` for the VPS
> secondary/relay IP.

## Roles

- **VPS primary IP** (`203.0.113.10`) — SSH/management only. Never relayed.
- **VPS secondary IP** (`203.0.113.20`) — the relay exit IP. This is what
  gets exposed as a locally-bindable address on the home machine.
- Home machine sits behind ordinary residential NAT.

Management traffic stays on the primary IP and relay traffic on the
secondary IP as a deliberate split: the relay's routing changes can never
affect SSH reachability to the VPS.

## Why no "don't deliver locally" trick is needed

Vultr documents a secondary IP as a `/32` sharing the primary IP's gateway,
noting that a `/32` "prevents the OS from responding to ARP locally —
traffic must be explicitly routed to the instance." In practice, Vultr
routes the secondary IP to the instance's link at the network layer,
independent of whether the OS binds it locally — inbound traffic to the
unbound secondary IP arrives on the VPS's primary interface regardless.

The VPS therefore never binds the secondary IP itself (no Netplan entry, no
local address anywhere) — it only needs a route handing that IP to
`wganchor<N>`. No dummy interface or iptables `DROP` rule is needed to
suppress local delivery, because no local interface ever owns that address
in the first place.

A freshly assigned public IP is "hot" immediately: background internet
scanning reaches it within seconds of assignment, before any tunnel exists.
This is why the client applies a default-deny firewall to the relay
interface from the moment it's created — see `firewall.md`.

## Packet path

- **VPS → tunnel (inbound)**: `AllowedIPs`-derived routing on the VPS-side
  peer (`AllowedIPs = 203.0.113.20/32`) forwards inbound traffic for the
  secondary IP into `wganchor<N>` automatically. This requires
  `net.ipv4.ip_forward=1` and VPS firewall rules allowing the WireGuard
  listen port and forwarding between the public interface and
  `wganchor<N>` — see `config-and-lifecycle.md`'s Lifecycle section for
  what `wganchor install server` sets up automatically versus what remains
  the operator's responsibility on the VPS's own firewall.
- **Home → tunnel (outbound)**: the home-side peer's `AllowedIPs` is always
  `0.0.0.0/0` (see `wireguard.md`'s "Config schema" — WireGuard's own
  cryptokey routing, not the kernel routing table, drops any outbound
  packet not covered by `AllowedIPs`), with no equivalent of `wg-quick`'s
  `AllowedIPs`-derived kernel route ever added, so that wide `AllowedIPs`
  can never hijack this shared, multi-purpose machine's default route.
  Instead, a policy route (`ip rule` keyed on the relay IP as source, plus
  a dedicated routing table) sends source-relay-IP traffic out through the
  tunnel — see `wireguard.md`'s "Client-side policy routing" for the
  table/priority formula. `internal/routing` reconciles this on every
  bring-up and via `wganchor watch` (`resilience.md`), so it's restored
  automatically rather than needing to survive by accident.
- **Keepalive / MTU**: `PersistentKeepalive = 25` (home side only) keeps
  NAT mappings alive across idle periods; WireGuard's own overhead needs no
  special MTU handling.

For the empirical validation history behind these facts (Vultr's routing
behavior, the packet-path PoC), see
`docs/sprints/archive/2026-08-29-bootstrap/`.
