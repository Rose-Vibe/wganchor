# Plan: Lifecycle (install/uninstall, systemd)

Depends on `docs/arch/config-and-lifecycle.md`'s "Lifecycle" section
(already fully designed) and `plan-tunnel-runtime.md` (the bring-up logic
the installed systemd service actually invokes on start).

## Goal

Implement `wganchor install [server|client]` / `wganchor uninstall`, and
ship the templated systemd units, per the design already written in
`config-and-lifecycle.md` — this plan is implementation of an
already-reviewed design, not new design work.

## Preconditions (checked before any state is touched)

Both `install` and `uninstall` mutate `/usr/local/bin`, `/etc/wganchor`,
and `/etc/systemd/system`, and shell out to `systemctl` — all state
changes that must either fully happen or not start at all, never partially
apply:

- Refuse with an actionable error if not running as root
  (`os.Geteuid() != 0`) — mirrors `wg`/`ip`'s own root requirement, and
  root is the documented v1 posture in `config-and-lifecycle.md`.
- Refuse with an actionable error if `systemctl` isn't on `PATH`
  (`exec.LookPath`) — this design is systemd-specific per
  `config-and-lifecycle.md`; a non-systemd host is unsupported, not
  silently half-handled.
- Both checks run first, before step 1 of `install` touches anything —
  otherwise a failure partway through (e.g. binary copied and a fresh
  keypair written to a new config, but the unit/enable step never runs)
  leaves state that a later successful `install` run would treat as
  "already installed, skip," masking the earlier partial failure.

## `install`

`wganchor install <server|client> [--instance N]` (role is required, not
optional — needed to know which unit/binary role to install):

1. Copy the running binary to `/usr/local/bin/wganchor` — skip if the
   destination already has identical content (compare a hash, not just
   path existence, so re-running `install` after a `go build` picks up a
   rebuilt binary; matches CLAUDE.md's idempotency rule).
2. If `/etc/wganchor/<N>.json` doesn't already exist: generate a WireGuard
   keypair immediately, using the **same internal key-provisioning
   function** `plan-tunnel-runtime.md`'s server/client self-provisioning
   calls on first run — not a second implementation of the
   generate/write-back/`0600`/print-pubkey sequence, since that's
   security-sensitive logic (the private key must never touch argv or an
   insecure file mode) that must not have two places to drift apart. The
   only thing `install` adds on top is calling it synchronously and
   printing the pubkey in `install`'s own output, so the operator doesn't
   have to dig through `journalctl` after `enable --now` to find it —
   without this, self-provisioning would still fire on the service's
   first start moments later regardless, just less conveniently. Also
   writes the skeleton config with concrete `listen_port` (`60217+N`) and
   `interface_name` (`wganchor<N>`) filled in — per `wireguard.md`: "the
   skeleton is written with concrete values ... not left implicit."
   `peer_public_key`/`peer_endpoint` are left blank for the operator to
   fill in by hand. Mode `0600` from creation.
3. Write the templated systemd unit files (see below) if not already
   present, `systemctl daemon-reload`, then `systemctl enable --now
   wganchor-<role>@<N>.service`.
4. Print the generated (or, if the config already existed, the existing)
   public key and the config path. For `server` specifically, also print
   the manual firewall/forwarding prerequisites from
   `plan-tunnel-runtime.md`'s "Firewall — explicitly out of scope" section
   (port, direction, and `ip_forward`), since `wganchor` doesn't set these
   itself — this guidance doesn't apply to a `client` install, which has
   no listen port or forwarding to open.

Re-running `install` for an already-installed instance is idempotent: same
binary-copy behavior, an existing config's keys are **never** regenerated
or overwritten, and `systemctl enable --now` is itself idempotent.

**Not supported / undefined:** installing both `server` and `client` for
the *same* instance number on the same machine — they'd share one config
file and one `wganchor<N>` interface, which doesn't match this tool's
asymmetric VPS/home model. Not guarded against in code for this sprint,
but noted here rather than left silent.

## `uninstall`

`wganchor uninstall <server|client> --instance N [--purge]` (role
required, same reasoning as `install` — `uninstall` needs it to know
which unit to target):

- `systemctl disable --now wganchor-<role>@<N>.service` — this removes
  only the per-instance enablement symlink, not the shared
  `wganchor-<role>@.service` template file itself (the template is used
  by *every* instance of that role on the machine, per `install`'s "if
  not already present" step). `systemctl daemon-reload`.
- The template unit file is only ever removed if no other enabled
  instance of that role remains on the machine (checked via
  `systemctl list-units 'wganchor-<role>@*.service'` or equivalent before
  deleting it) — mirrors the same "only if nothing else references it"
  guard `--purge` already applies to `/etc/wganchor` below. Uninstalling
  instance 1's client must never break an already-running instance 0
  client on the same box.
- `/usr/local/bin/wganchor` is **never** removed by `uninstall`, with or
  without `--purge` — it's shared across every instance and role on the
  machine, and this plan has no "is this the last instance anywhere"
  logic to safely decide otherwise. Binary removal, if ever wanted, is
  out of scope for this sprint.
- Without `--purge`: config and the `wganchor<N>` interface are left
  alone.
- With `--purge`: additionally remove `/etc/wganchor/<N>.json` (and
  `/etc/wganchor/` itself if no other instance's config remains), and tear
  down the `wganchor<N>` interface (`ip link delete <name>`, ignoring
  "already gone" as success). Matches the apt remove-vs-purge split
  already decided in `config-and-lifecycle.md` — never delete keys/config
  as a side effect of a plain `uninstall`.
- Uninstalling an instance that was never installed is a no-op, not an
  error (matches "safe to re-run").

## systemd units

- `wganchor-server@.service` / `wganchor-client@.service`, templated
  (`%i` = instance number): `ExecStart=/usr/local/bin/wganchor server
  --instance %i` (or `client`), `Restart=on-failure`,
  `WantedBy=multi-user.target`.
- Shipped as strings embedded in the Go binary via `//go:embed` (stdlib,
  no new dependency) and written out to `/etc/systemd/system/` by
  `install` — keeps the "single static binary" property intact, no
  separate files to distribute alongside it.

## Second-instance structural validation (no second VPS needed)

`wganchor install client --instance 1`, pointed at a placeholder,
intentionally-unreachable `peer_endpoint` — an IP literal in the
TEST-NET-1 documentation range (e.g. `192.0.2.1:51820`), not a hostname,
so the test doesn't incidentally depend on DNS resolution succeeding or
failing (connectivity is not being tested here at all — this step is
purely about the install/systemd/config plumbing) — must produce a
distinct `wganchor-client@1.service` without disturbing an
already-installed instance `0`. Confirms systemd templating and
multi-instance config paths don't collide, independent of whether a
second real VPS is reachable.

## Live two-VPS validation — deferred, ask user when reached

Per `docs/arch/wireguard.md`'s explicit note: a second, independent VPS is
needed to validate two live tunnels running at once, end-to-end. **Do not
attempt this until the structural validation above passes.** Do not assume
a second VPS is unavailable or skip this step outright — the user has
already offered to provision one on request; ask at that point.

## Exit criteria

- [ ] `wganchor install server` / `install client` on a fresh instance
      produce a running, enabled systemd service and a `0600` config with
      concrete `listen_port`/`interface_name`; keypair generated and
      public key printed.
- [ ] Re-running `install` for the same instance is idempotent: no
      duplicated units, no regenerated keys/config.
- [ ] `wganchor uninstall` stops/disables/removes the per-instance
      enablement; config and interface survive unless `--purge` is
      passed; `--purge` removes them. The binary and the shared
      `wganchor-<role>@.service` template file are never removed by
      `uninstall` (with or without `--purge`).
- [ ] Uninstalling a never-installed instance is a no-op, not an error.
- [ ] Uninstalling one instance of a role (e.g. `client` instance `1`)
      while another instance of the same role (`client` instance `0`)
      remains installed and enabled does not disable or remove that other
      instance, and does not delete the shared template unit file while
      it's still in use.
- [ ] `install`/`uninstall` invoked as non-root, or on a host without
      `systemctl` on `PATH`, fail with an actionable error before any
      state is touched (verified: no binary copied, no config written, no
      unit installed).
- [ ] `install client --instance 1` produces a distinct, non-colliding
      systemd unit and config from instance `0`, verified without needing
      a second VPS.
- [ ] Live two-independent-tunnel validation: either completed (if the
      user provides a second VPS during this sprint) or explicitly logged
      as the sprint's one remaining deferred item, not silently dropped.
