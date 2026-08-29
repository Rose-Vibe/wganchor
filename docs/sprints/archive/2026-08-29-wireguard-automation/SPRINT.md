# Sprint: WireGuard Automation

## Purpose

The bootstrap sprint (`docs/sprints/archive/2026-08-29-bootstrap/`) proved the
relay mechanism works by hand and left `wganchor server`/`wganchor client` as
a skeleton that only parses a config file and prints it. This sprint replaces
the manual `ip`/`wg` steps from that PoC with real Go automation, and adds
the install/uninstall lifecycle so `wganchor` behaves like a normal system
daemon (per `docs/arch/config-and-lifecycle.md`'s stated goal).

No new design work is expected here — `docs/arch/wireguard.md`,
`docs/arch/config-and-lifecycle.md`, and `docs/arch/overview.md`'s "Packet
path" section (written after the PoC, with the actual empirically-confirmed
mechanism) already answer nearly every question this sprint's plans raise.
This sprint is about translating already-validated shell commands into
idempotent Go code, plus implementing the already-designed install/uninstall
surface.

## Scope

1. **Tunnel runtime** (`plan-tunnel-runtime.md`): `server`/`client`
   subcommands actually create/configure the WireGuard interface,
   self-provision keys, and set up routing, matching the mechanism
   validated in the bootstrap PoC exactly (`AllowedIPs`/`Table`-equivalent
   behavior, policy routing on the client/home side, `AllowedIPs`-derived
   routes on the server/VPS side).
2. **Lifecycle** (`plan-lifecycle.md`): `install`/`uninstall` subcommands,
   templated systemd units, per `config-and-lifecycle.md`'s existing design.
3. **Live two-VPS validation**: deferred until a second VPS is available.
   The user has offered to provision one on request — ask when
   implementation actually reaches that validation point, per
   `docs/arch/wireguard.md`. Do not assume it's unavailable or skip the
   step outright.

## Known state at sprint start (2026-08-29)

- `wganchor` builds as a static binary (`main.go`, `config.go` at the repo
  root). `server`/`client` subcommands parse a config file (layered lookup,
  `0600` enforcement, `--instance <N>` flag) and print it (private key
  redacted) — no interface/tunnel/routing code yet.
- One VPS is provisioned: `203.0.113.10` (primary/management),
  `203.0.113.20` (relay, secondary IP). A second VPS is available from
  the user on request, needed only for the live multi-instance validation
  step below.
- The exact mechanism this sprint's code must reproduce is written up in
  `docs/arch/overview.md`'s "Packet path" section, including the ufw rules
  and the `rp_filter` red herring (not needed) discovered during the PoC.

## Plans

- `plan-tunnel-runtime.md` — real interface/key/route automation.
- `plan-lifecycle.md` — `install`/`uninstall`, systemd units.

## Exit criteria for the sprint

- `wganchor server`/`wganchor client` bring up a real, working tunnel
  end-to-end from config alone (no manual `ip`/`wg` commands), re-validated
  live against the existing single VPS: inbound, outbound, and
  idle/keepalive all pass, matching the bootstrap PoC's results.
- All network manipulation is idempotent — re-running either subcommand
  against an already-configured interface is a no-op, not an error or a
  duplicate.
- `install`/`uninstall` work via systemd, matching
  `config-and-lifecycle.md`'s design; multi-instance install/systemd is
  validated structurally (`--instance 1`) without needing a second VPS.
- Live two-independent-tunnel validation either completed (if a second VPS
  is provisioned during this sprint) or explicitly logged as the one
  remaining deferred item — never silently dropped.

No checkpoint like bootstrap's `SPRINT.md` — this sprint doesn't install
new system packages or touch anything beyond what the bootstrap PoC already
exercised by hand. The normal CLAUDE.md autonomous pipeline applies
throughout, including through implementation, stopping only for the
standard exceptions (architectural conflict, irreversible consequence,
systemic test failure, unsafe/destructive action).

**Sprint complete, 2026-08-29.** All four exit criteria met:

- Real tunnel bring-up (`plan-tunnel-runtime.md`) implemented, reviewed
  (two passes), and live-validated end-to-end against the original VPS —
  see that plan's exit criteria and `docs/arch/wireguard.md`.
- All network manipulation confirmed idempotent, including full
  reconciliation of removed `relay_ips` and (added during the lifecycle
  milestone) cleanup of client-side policy-routing rules on purge.
- Install/uninstall via systemd (`plan-lifecycle.md`) implemented,
  reviewed (two passes, several rounds of fixes), and live-validated —
  including the multi-instance structural check (`--instance 1` on the
  home machine alone, no second VPS needed).
- Live two-independent-tunnel validation completed against a second,
  temporarily-borrowed VPS with its own genuine secondary IP: both
  tunnels ran concurrently, inbound and outbound both confirmed over the
  real public internet path, and the borrowed VPS was fully reverted
  afterward (firewall rules, `ip_forward`, `wireguard-tools` package, and
  all `wganchor` state removed) — see `plan-lifecycle.md`'s exit criteria
  for the full record.

`wganchor` now does everything CLAUDE.md's goal describes: a single
static binary that brings up and tears down a real relay tunnel, self-
provisions its own keys, and installs/uninstalls itself as a systemd
service, all idempotently. No further sprint is planned as of this
writing.
