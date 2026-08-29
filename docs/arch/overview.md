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

## Intended packet path

Not yet built or tested end-to-end — this is the design the manual PoC
(`docs/sprints/bootstrap/plan-wireguard-poc.md`) exists to validate.

- **Inbound** (internet-initiated): internet → Vultr edge (routes the
  secondary `/32` to the VPS's link, confirmed above) → VPS `enp1s0` →
  kernel routing table (no local address match) → `ip route` sends it to
  `wganchor0` (requires `net.ipv4.ip_forward=1`) → WireGuard tunnel → home
  `wganchor0` → local socket bound to `203.0.113.20`.
- **Outbound** (home-initiated): local socket on home machine, bound to
  `203.0.113.20` → home `wganchor0` → tunnel → VPS `wganchor0` → VPS routes it back
  out `enp1s0` sourced as `203.0.113.20` (not NAT'd — the VPS legitimately
  owns that IP from Vultr's perspective) → internet. This direction is
  untested so far and is where `rp_filter`/policy-routing is most likely
  to surprise us — it has its own dedicated step in the PoC plan.

Exact `ip route`/`ip rule` forms, `rp_filter` adjustments, and
`PersistentKeepalive` interval are to be finalized during the PoC and
recorded back into this doc, per `plan-research.md`'s deliverables.

## Status

- [x] Vultr secondary-IP local-binding question — confirmed, see above.
- [ ] Full packet path validated end-to-end (inbound + outbound + idle
      keepalive + MTU) — pending `plan-wireguard-poc.md`.
