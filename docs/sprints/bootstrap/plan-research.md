# Plan: Research

No `docs/arch/` exists yet. This plan's output *is* the initial architecture
doc set — later plans (in this sprint and beyond) reference it, so it needs
to land before `plan-environment.md` and `plan-wireguard-poc.md` are acted on.

## Open questions to resolve

1. **Vultr secondary IP mechanics**
   - How is a second IPv4 requested (portal vs. `vultr-cli` vs. API) and
     what's the lead time / restart requirement?
   - Confirmed so far: added via the control panel or API, instance reboot
     required, max 2 additional IPs per instance, Vultr generates a
     per-OS Netplan snippet for it.
   - Open: does Vultr route the secondary IP to the instance regardless of
     whether it's bound to a local interface, or does it require the IP to
     be configured locally (e.g. answers ARP) to receive traffic at all?
     This determines whether the VPS can leave the IP *unbound* and just
     route it to `wg0`, or whether it must be bound to a dummy interface
     first. Needs to be confirmed empirically against the actual account/
     instance, not just docs, since behavior can vary by network mode.

2. **Routing design (the "no delivery-local trick" claim in the README)**
   - Document the intended packet path, in both directions — both need to
     be validated in the PoC, not just inbound:
     - Inbound (internet-initiated): internet → Vultr edge → VPS NIC →
       (route, not local delivery) → `wg0` → tunnel → home `wg0` → local
       socket bound to the secondary IP.
     - Outbound (home-initiated): local socket on home machine, bound to
       the secondary IP → home `wg0` → tunnel → VPS `wg0` → (source-routed
       back out the VPS's NIC as the secondary IP, not NAT'd) → internet.
       This half is untested by a simple "listener + external curl" setup
       and is the more likely place for `rp_filter`/policy-routing
       surprises — call it out explicitly as its own PoC step.
   - Specify the exact `ip route` / `ip rule` entries needed on the VPS
     (route the /32 to `wg0`, forwarding enabled) and on the home machine
     (secondary IP assigned to `wg0` or a policy route pointing outbound
     traffic from it through `wg0`).
   - Note where `net.ipv4.ip_forward` and reverse-path filtering
     (`rp_filter`) need adjusting, since asymmetric-looking routing for a
     single /32 is exactly what `rp_filter` is designed to flag.
   - State the NAT assumption explicitly: the home machine is expected to
     sit behind NAT (typical home internet), so the VPS-side WireGuard
     peer entry only stays reachable while the NAT mapping is alive.
     `PersistentKeepalive` on the home side's config is required, not
     optional — record the interval decided on here so the PoC and the
     later Go config schema agree on it.

3. **WireGuard on this stack**
   - Confirmed: both hosts have in-kernel WireGuard (kernel ≥ 5.6), so
     `wireguard-tools` (`wg`, `wg-quick`) is the only package needed — no
     DKMS, no userspace `wireguard-go` fallback required.
   - Decide interface creation approach for the Go implementation later:
     `wgctrl-go` only *configures* an existing WireGuard device, it does
     not create one. Creating the device needs either shelling out to
     `ip link add <name> type wireguard` or an in-process netlink call
     (e.g. `vishvananda/netlink`, which the CLAUDE.md "no external
     frameworks for simple tasks" rule doesn't rule out — it's a
     netlink binding, not a framework — but confirm there's no
     stdlib-only path first).

4. **Key management model**
   - Where do the WireGuard keypairs live, who generates them (`server`
     vs `client` subcommand vs a separate `keygen` step), and how does the
     public key + endpoint get from one side to the other for the config
     file. Keep this manual/file-based for now — no auto key-exchange
     protocol in scope. Resolved in
     `docs/arch/config-and-lifecycle.md`: private key stored inline in the
     JSON config, `0600`, mirroring `wg-quick`'s own convention.

5. **Config format, location, and lifecycle** — resolved ahead of the Go
   skeleton work in `plan-wireguard-poc.md`, written up in
   `docs/arch/config-and-lifecycle.md`:
   - Config format is JSON (stdlib `encoding/json`, no dependency; scales
     to more complex/nested state later without a format change).
   - Layered lookup: `--config` flag → XDG user config
     (`os.UserConfigDir()`) → `/etc/wganchor/config.json` (no implicit cwd
     lookup — dropped after review, see the doc for why).
   - Lifecycle: systemd units per role, `install`/`uninstall` subcommands,
     all state filesystem-resident at standard locations so any copy of
     the binary can manage an installed instance. See the doc for the
     full rationale and what's still deferred (capability-scoped
     execution, live control socket).

## Deliverables

- `docs/arch/overview.md` — system diagram and packet-path description
  (answers to questions 1–2 above).
- `docs/arch/wireguard.md` — interface creation/config approach, key
  management model (questions 3–4).
- `docs/arch/config-and-lifecycle.md` — already written (question 5); no
  further action needed here beyond keeping it in sync if the PoC
  surfaces a reason to change it.
- Both docs state which parts are confirmed by testing on the real VPS
  (from `plan-wireguard-poc.md`) vs. which are documentation-only claims,
  so a wrong assumption is easy to find later.
- Record the exact idempotent command forms used during the PoC (e.g.
  `ip addr replace` / `ip route replace` rather than `add`, which fails on
  a second run) — per the CLAUDE.md rule that all network manipulation
  must be safe to re-run, sprint 2's implementation should reuse these
  forms rather than rediscovering them.

## Exit criteria

- [x] Vultr secondary-IP behavior confirmed against the actual instance
      (not just docs) — does it need local binding or not. Confirmed via
      `tcpdump` on the VPS while pinging the unbound secondary IP from the
      home machine: packets arrive on `enp1s0` with no local binding
      needed. See `docs/arch/overview.md`.
- [x] `docs/arch/overview.md` written — packet-path design is documented;
      full end-to-end validation still pending the PoC (tracked there,
      not a research-plan exit criterion).
- [x] `docs/arch/wireguard.md` written and describes interface creation +
      key management approach (shell out to `ip`/`wg`, no netlink/wgctrl
      dependency; keys self-provisioned via `wg genkey`/`wg pubkey`).
- [x] `docs/arch/config-and-lifecycle.md` written (config format,
      location, key storage, install/uninstall, systemd lifecycle).
- [x] Open questions above are either answered in the docs or explicitly
      logged as deferred with a reason.

**Research plan complete.** Per the sprint README, see
`SPRINT.md` for the checkpoint before `plan-environment.md` and
`plan-wireguard-poc.md` execution begins.
