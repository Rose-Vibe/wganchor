# Overview: Network Design

## Roles (confirmed 2026-08-28)

- **VPS primary IP** `203.0.113.10` — SSH/management only. Never relayed.
- **VPS secondary IP** `203.0.113.20` — the relay exit IP. This is what
  gets exposed as a locally-bindable address on the home machine.
- Home machine sits behind ordinary residential NAT.

Keeping management traffic on the primary IP and relay traffic on the
secondary IP is a deliberate split, not an accident of what Vultr happened
to assign — it means the relay's routing changes can never accidentally
affect SSH reachability to the VPS.

## Vultr secondary-IP behavior (confirmed empirically, not just docs)

Vultr's own docs describe the secondary IP as a `/32` on the same
interface as the primary, sharing its gateway, with the note that a `/32`
"prevents the OS from responding to ARP locally — traffic must be
explicitly routed to the instance." We confirmed what that means in
practice by testing against the real instance *before* configuring
anything:

- `203.0.113.20` was added via the Vultr panel; Vultr auto-rebooted the
  instance as part of that (confirmed via `uptime -s` matching the panel
  action, no manual reboot needed).
- The secondary IP was **not** added to Netplan and has no local address
  anywhere on the VPS.
- From the home machine, `ping 203.0.113.20` was run while `tcpdump -i
  enp1s0 host 203.0.113.20` ran on the VPS. The ICMP echo requests
  **arrived on `enp1s0`** (confirmed by packet capture), even though the
  address is unbound and the VPS never replied.

Conclusion: Vultr routes the secondary IP to the instance's link at the
network layer, independent of whether the OS binds it locally. This is
exactly what the project's core assumption requires — the VPS can leave
the secondary IP unbound and forward it to `wganchor0` via a plain route,
**no "don't deliver locally" trick needed** (no dummy interface, no
iptables DROP rule to suppress local delivery — the kernel was never
going to deliver it locally in the first place, since no local interface
owns that address).

Also observed in the same capture: an unsolicited TCP SYN from an
unrelated IP hit the address within seconds of assignment — expected
background internet scanning noise on a freshly announced IP, not
something to design around, but a reminder that the secondary IP is "hot"
the moment it's assigned, before any tunnel exists to route it somewhere
useful.

## Packet path (confirmed empirically via the manual PoC, 2026-08-29)

Validated end-to-end by hand per `docs/sprints/archive/2026-08-29-bootstrap/plan-wireguard-poc-COMPLETE.md`
— inbound, outbound, idle/keepalive, and MTU all passed. Exact mechanism:

- **VPS side**: `wg-quick`'s normal `AllowedIPs`-derived route handling is
  sufficient — no manual routing needed here. `AllowedIPs = 203.0.113.20/32`
  on the VPS-side peer makes `wg-quick` auto-add `203.0.113.20/32 dev
  wganchor0`, so inbound internet traffic to the secondary IP (arriving on
  `enp1s0`, per the Vultr routing behavior confirmed above) is forwarded into
  the tunnel automatically. `net.ipv4.ip_forward=1` (persisted,
  `plan-environment.md`) is required for this forwarding to happen at all.
- **VPS firewall (ufw)**: found active by default with `INPUT` and `FORWARD`
  both `DROP` — not mentioned in the original design. Required additive
  rules, beyond just `ip_forward=1`: `ufw allow 60217/udp` (the WireGuard
  listen port) and bidirectional `ufw route allow` between `enp1s0` and
  `wganchor0` (both IPv4 and IPv6). Without these, the handshake and
  forwarding both silently fail. These are part of the durable environment
  setup the real `wganchor server` will need to establish, not PoC-only
  scaffolding — the same port/interface names are permanent.
- **Home side — outbound is the direction that needed real design work**:
  a narrow `AllowedIPs` (e.g. `203.0.113.20/32`) on the home-side peer
  causes **WireGuard's own cryptokey routing** — not the kernel routing
  table — to silently drop any packet whose destination isn't covered by
  it. This is an internal WireGuard-level filter independent of `ip route`/
  `ip rule`, and it's the actual reason a plain policy-route setup wasn't
  enough on its own. Fix: widen the home peer's `AllowedIPs` to `0.0.0.0/0`
  so WireGuard will forward for any destination, while adding `Table = off`
  under `[Interface]` so `wg-quick` does **not** also turn that wide
  `AllowedIPs` into a kernel default-route override — that would hijack the
  whole (shared, multi-purpose) home machine's default route, which is
  unacceptable collateral damage on a box that also runs Docker/Tailscale/
  other traffic.
- **Home side — policy routing for the outbound path**: with `Table = off`,
  nothing in the kernel routes source-`203.0.113.20` traffic through
  `wganchor0` on its own, so a manual `ip rule` + custom routing table is
  required: `ip rule add from 203.0.113.20 table 60217 priority 20217`
  plus `ip route add default dev wganchor0 table 60217`. Priority `20217`
  and table ID `60217` were chosen after checking `ip rule show` /
  `ip route show table all` for collisions with an unrelated, pre-existing
  fwmark-based VPN app on this machine (priorities 5210–5270, table `52`)
  — arbitrary-but-memorable values tied to the project's own port, not
  otherwise significant. **This rule and route must both exist for the
  outbound (and inbound-reply) path to work**, and — this was the actual
  root cause of an extended inbound-path failure during the PoC — the
  custom table's route does **not** survive an interface-name-shadowed
  `wg-quick down`/`up` cycle and must be re-added after any such cycle,
  since it isn't managed by wg-quick at all. A dropped/missing route in
  table `60217` manifests as: SYN arrives fine, the kernel accepts it
  (visible as a `SYN-RECV` socket via `ss`), but the SYN-ACK reply's route
  lookup (source `203.0.113.20`) falls through past the now-empty custom
  table to the main table's ordinary default route (the real LAN gateway),
  so the reply goes out the wrong interface with a source address that
  isn't the machine's real WAN IP and never reaches the client. The real
  Go implementation must (re)establish this route as part of bringing the
  tunnel up, not just once at install time.
- **`rp_filter` — ruled out, not the cause**: initially suspected (a
  `TcpExtIPReversePathFilter` counter increment was observed during
  debugging) and both `net.ipv4.conf.wganchor0.rp_filter` and
  `net.ipv4.conf.all.rp_filter` were temporarily set to `0` as a diagnostic
  test. This did **not** fix the inbound failure — the actual cause was the
  missing table-`60217` route above. Both values were reverted to their
  original default (`2`, loose mode) once the real cause was found; no
  `rp_filter` change is needed in the final design. Kept here as a note so
  a future debugging session doesn't re-chase the same red herring.
- **Idle/keepalive**: confirmed — `PersistentKeepalive = 25` (home side
  only, per `docs/arch/wireguard.md`) kept the handshake refreshing well
  within a 5+ minute idle period; the inbound path worked identically
  before and after the idle wait.
- **MTU**: confirmed — a 1 MB file transferred over the inbound path with a
  matching SHA-256 checksum on both ends; no fragmentation or stall
  observed despite WireGuard's ~80-byte overhead.

## Status

- [x] Vultr secondary-IP local-binding question — confirmed, see above.
- [x] Full packet path validated end-to-end (inbound + outbound + idle
      keepalive + MTU) — see "Packet path" above. All PoC exit criteria met,
      manual config torn down on both machines (ephemeral keys/configs
      deleted; the durable VPS ufw rules and `ip_forward` sysctl were kept
      as part of the environment, not torn down).
