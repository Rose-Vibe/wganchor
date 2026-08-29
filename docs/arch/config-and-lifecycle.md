# Config, Keys, and Lifecycle

Status: design decisions, not yet implemented. This governs the "Config
file loading" step of `docs/sprints/bootstrap/plan-wireguard-poc.md`'s Go
skeleton, and everything here is meant to be settled before that step
starts, so the skeleton doesn't need reworking in sprint 2.

## Goal

CLAUDE.md states the target: a single static Linux binary, `server` and
`client` subcommands, idempotent and safe-to-re-run network manipulation.
The intent is that once configured, `wganchor` behaves like a normal Linux
system daemon — install it, point it at a config, it comes up on boot and
stays up. None of this is built yet; the bootstrap sprint's manual PoC
exists specifically to discover what the automation needs to do before
this gets implemented.

## Config file

### Format: JSON

Chosen over TOML/YAML/INI: `encoding/json` is stdlib (no dependency, in
keeping with CLAUDE.md's "no external frameworks for simple tasks"), and
it scales cleanly if the config grows more complex later — nested peer
lists, multiple listen addresses, etc. — without a format change. The
trade-off (no comments, less pleasant to hand-edit) is accepted; `wganchor`
should offer a way to generate/validate a config rather than relying on
hand-editing with inline documentation.

### Lookup order

Checked in this order, first match wins:

1. `--config <path>` — explicit flag, always wins. Covers dev/portable use
   (e.g. `--config ./wganchor.json`) explicitly rather than implicitly.
2. `$XDG_CONFIG_HOME/wganchor/<N>.json` (via Go's `os.UserConfigDir()`,
   not a hardcoded `~/.config` — keeps a cross-platform door open at no
   cost now, even though WireGuard/NET_ADMIN realities mean any non-Linux
   port is a stretch goal, not a near-term plan).
3. `/etc/wganchor/<N>.json` — the system-daemon default, used when
   installed via `wganchor install` (see Lifecycle below).

`N` is the instance number, per `docs/arch/wireguard.md`'s multi-instance
naming — `0` when no `--instance` flag is given, not a specially-named
`config.json`. There's no `--instance` flag in the bootstrap sprint (see
that doc), so today `N` is always `0` in practice, but the path the Go
skeleton actually looks for is `.../0.json` from the start, exactly so it
never needs renaming later.

No implicit cwd lookup (no bare `./wganchor.json` default). This tool runs
as root, and a root-run process that silently picks up whatever config
happens to sit in its working directory is a footgun — an unexpected file
changes what interfaces/routes a root process configures, and a
key-bearing config in a dev working tree is one `git add .` away from
being committed. `--config ./wganchor.json` covers the same dev use case
explicitly, at the cost of one flag.

### Keys

Private key stored inline in the same JSON config, file mode `0600`. This
mirrors `wg-quick`'s own `/etc/wireguard/wg0.conf` convention (private key
inline, restrictive permissions) rather than inventing a separate key
store — the tool is a thin wrapper around WireGuard, so it should look
like WireGuard config to anyone who's used it before. If config ever
splits secret from non-secret fields (e.g. to make the non-secret part
shareable/committable), that's a later, additive change — not needed for
v1.

`0600` is enforced, not just documented: any config the tool writes
(`install`, a future `keygen`/`init`) is created `0600` from the start,
and on load the tool checks the file's mode and refuses to start — same
posture as `ssh`'s private-key check and `wg`'s own world-readable-key
warning, not a silent log line easy to miss on a headless box.

## Lifecycle (systemd, install/uninstall)

Design only, not yet implemented — decided here, ahead of the Go skeleton
work, so the subcommand surface doesn't need reworking later.

- Ship a systemd *template* unit per role (`wganchor-server@.service`,
  `wganchor-client@.service`), instantiated with the instance number
  (`wganchor-server@0.service` for the default/only instance today):
  `Restart=on-failure`, `WantedBy=multi-user.target`. Templated from the
  start, not a flat unit name for instance 0 — see
  `docs/arch/wireguard.md`'s multi-instance naming decision.
- On startup, the daemon must idempotently reconcile interface/route state
  rather than assume a clean slate — a prior crash leaving `wganchor0`
  half-configured must not require manual cleanup before it can start
  again. Same idempotency rule CLAUDE.md already states for network
  manipulation generally, applied specifically to the restart/recovery
  case.
- `wganchor install [server|client]`: copies itself to
  `/usr/local/bin/wganchor` (conventional location for a non-distro-
  packaged binary — `/usr/bin` is reserved for package-manager-installed
  files), writes the systemd unit instance and a default
  `/etc/wganchor/0.json` skeleton if absent, `systemctl enable --now
  wganchor-<role>@0.service`. The skeleton is written with concrete
  values (port, interface name), not left to implicit in-code defaults —
  see the `listen_port` note in `docs/arch/wireguard.md`.
- `wganchor uninstall`: stops/disables the service, removes the unit;
  removing `/etc/wganchor` (config + keys) requires an explicit `--purge`
  flag, mirroring apt's remove-vs-purge split — never delete keys/config
  as a side effect of an ordinary uninstall.
- **Design constraint driving all of the above:** all state must be
  filesystem-resident at the standard locations (`/etc/wganchor/`, the
  systemd unit) rather than known only to the currently-running process.
  That way `install`/`uninstall`/`status` are just file + `systemctl`
  operations, and any copy of the `wganchor` binary — not just the one
  that's actually installed and running — is equally capable of managing
  the installed instance. A live control socket (e.g. for "reload without
  restart") is a reasonable later addition, not required for v1.

## Open / deferred

- Run as root vs. a dedicated user with `AmbientCapabilities=CAP_NET_ADMIN`:
  defaulting to root for v1 (matches `wg-quick` itself), capability-scoped
  execution is a later hardening pass, not a blocker.
- Live status/control socket: deferred, `wg show` already covers basic
  status independent of this tool.
- Multiple independent tunnel instances (`--instance <N>` flag itself, and
  the `install`/`uninstall` plumbing to manage more than one at once):
  naming/path shape reserved in `docs/arch/wireguard.md` and above (the
  config path, port, and systemd unit are already templated on `N`), only
  the flag and multi-instance `install`/`uninstall` UX remain unbuilt. No
  second VPS is in scope, so there's nothing to exercise this with yet.
