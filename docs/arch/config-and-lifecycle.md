# Config, Keys, and Lifecycle

This doc covers the on-disk config format and lookup, where keys live, and
the systemd-based install/uninstall lifecycle. Implemented in
`internal/config/`, `internal/lifecycle/lifecycle.go`, and
`internal/lifecycle/units.go`.

## Goal

A single static Linux binary, with `server` and `client` subcommands, that
behaves like a normal Linux system daemon once configured: install it,
point it at a config, it comes up on boot and stays up. All network
manipulation is idempotent and safe to re-run.

## Config file

### Format: JSON

Chosen over TOML/YAML/INI: `encoding/json` is stdlib (no dependency,
matching CLAUDE.md's "no external frameworks for simple tasks"), and it
scales cleanly if the config grows more complex later — nested peer lists,
multiple listen addresses — without a format change. The trade-off (no
comments, less pleasant to hand-edit) is accepted; `wganchor` offers a way
to generate/validate a config rather than relying on hand-editing with
inline documentation.

### Lookup order

Checked in this order, first match wins:

1. `--config <path>` — explicit flag, always wins. Covers dev/portable use
   (e.g. `--config ./wganchor.json`) explicitly rather than implicitly.
2. `$XDG_CONFIG_HOME/wganchor/<N>.json` (via Go's `os.UserConfigDir()`,
   not a hardcoded `~/.config` — keeps a cross-platform door open at no
   cost now, even though WireGuard/`NET_ADMIN` realities make any
   non-Linux port a stretch goal, not a near-term plan).
3. `/etc/wganchor/<N>.json` — the system-daemon default, used when
   installed via `wganchor install` (see Lifecycle below).

`N` is the instance number, per `docs/arch/wireguard.md`'s multi-instance
naming — `0` when no `--instance` flag is given, not a specially-named
`config.json`.

**No implicit cwd lookup** (no bare `./wganchor.json` default). This tool
runs as root, and a root-run process that silently picks up whatever
config happens to sit in its working directory is a footgun — an
unexpected file changes what interfaces/routes a root process configures,
and a key-bearing config in a dev working tree is one `git add .` away
from being committed. `--config ./wganchor.json` covers the same dev use
case explicitly, at the cost of one flag.

### Keys

Private key stored inline in the same JSON config, file mode `0600`. This
mirrors `wg-quick`'s own `/etc/wireguard/wg0.conf` convention (private key
inline, restrictive permissions) rather than inventing a separate key
store — the tool is a thin wrapper around WireGuard, so it looks like
WireGuard config to anyone who's used it before.

`0600` is enforced, not just documented: any config the tool writes
(`install`, a future `keygen`/`init`) is created `0600` from the start,
and on load the tool checks the file's mode and refuses to start — the
same posture as `ssh`'s private-key check and `wg`'s own
world-readable-key warning, not a silent log line.

## Lifecycle (systemd, install/uninstall)

- Ships a systemd *template* unit per role (`wganchor-server@.service`,
  `wganchor-client@.service`, embedded in the binary via `//go:embed` from
  `units/`), instantiated with the instance number
  (`wganchor-server@0.service` for instance `0`):
  `Restart=on-failure`, `WantedBy=multi-user.target`.
  - **`Type=oneshot` + `RemainAfterExit=yes`, not the systemd default
    `Type=simple`.** `wganchor server`/`client` brings the tunnel up and
    exits — it is not a long-lived foreground process. `Type=simple`
    would make `systemctl is-active` report "inactive" for a genuinely
    working tunnel. `Type=oneshot`/`RemainAfterExit=yes` makes a completed
    bring-up show correctly as `active (exited)`.
  - A unit that fails before completing bring-up (e.g. a fresh,
    unconfigured skeleton) hits `Restart=on-failure` and, with systemd's
    default `StartLimitBurst=5`/`StartLimitIntervalSec=10`, settles into
    `ActiveState=failed` within about a second rather than looping
    forever — systemd's own self-limiting behavior, not something
    `wganchor` implements. A manual `systemctl start` after that window
    (or `install` re-run later) tries again normally.
- On startup, the daemon idempotently reconciles interface/route state
  rather than assuming a clean slate — a prior crash leaving `wganchor0`
  half-configured does not require manual cleanup before it can start
  again.
- `wganchor install <server|client> [--instance N]`: copies itself to
  `/usr/local/bin/wganchor` (`/usr/bin` is reserved for
  package-manager-installed files) via atomic temp-file-plus-rename,
  writes the systemd unit template if it's missing *or* differs from the
  binary's own embedded copy (never removed while another instance
  depends on it — see `uninstall` below — but always kept in sync with
  the running binary's version on `install`), writes a default
  `/etc/wganchor/<N>.json` skeleton if absent (concrete `listen_port`/
  `interface_name` filled in, `peer_public_key`/`peer_endpoint`/
  `relay_ips` left blank for the operator), then `systemctl
  daemon-reload` and `systemctl enable wganchor-<role>@<N>.service`.
  - **`enable` and `start` are separate calls, not `enable --now`.** A
    fresh skeleton config has no peer info yet, so an immediate start is
    *expected* to fail on a brand-new instance. `install` calls
    `systemctl start` separately and reports a failure there as an
    informational `note:` pointing at the config path, not a fatal error
    for `install` as a whole — everything `install` is actually
    responsible for (binary, config, unit file, enablement) can still
    have succeeded.
- `wganchor uninstall <server|client> [--instance N] [--purge]`: stops/
  disables the instance's unit (`systemctl disable --now`, tolerating "was
  never installed" as a no-op) and clears any lingering
  `ActiveState=failed` record for it (`systemctl reset-failed`,
  best-effort — cosmetic only). The shared template unit file is only
  removed once no *other* enabled instance of that role remains. Removing
  `/etc/wganchor` (config + keys) and the interface requires an explicit
  `--purge` flag, mirroring apt's remove-vs-purge split — never delete
  keys/config as a side effect of an ordinary uninstall.
  - **Detecting other enabled instances**: done by globbing
    `/etc/systemd/system/multi-user.target.wants/wganchor-<role>@*.service`
    for the actual enablement symlinks `systemctl enable` creates — not by
    parsing `systemctl list-unit-files`, which only ever lists the shared
    template itself (state `indirect`), never the per-instance
    instantiated units, so it can't answer "is any other instance still
    enabled" at all. The symlink-glob approach is both correct and
    directly unit-testable against a `t.TempDir()` fixture, with no
    `systemctl` needed in tests.
- **Design constraint driving all of the above**: all state is
  filesystem-resident at standard locations (`/etc/wganchor/`, the
  systemd unit) rather than known only to the currently-running process.
  `install`/`uninstall`/`status` are just file + `systemctl` operations,
  and any copy of the `wganchor` binary — not just the one that's actually
  installed and running — is equally capable of managing the installed
  instance. A live control socket (e.g. for "reload without restart") is a
  reasonable later addition, not required for v1.

## Known gaps / deferred

- **Run as root vs. a dedicated user** with
  `AmbientCapabilities=CAP_NET_ADMIN`: defaults to root for v1 (matches
  `wg-quick` itself); capability-scoped execution is a later hardening
  pass.
- **Live status/control socket**: deferred — `wg show` already covers
  basic status independent of this tool.
