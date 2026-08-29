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
  by *every* instance of that role on the machine, and `install` keeps it
  in sync with the binary's own copy rather than only writing it once —
  see "Revisions during implementation" below). `systemctl daemon-reload`.
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

## Revisions during implementation, not anticipated in the original plan

- **`Type=oneshot` + `RemainAfterExit=yes`, not the systemd default
  `Type=simple`.** `wganchor server`/`client` brings the tunnel up and
  exits; it isn't a long-lived foreground process. Under `Type=simple`,
  `systemctl is-active` falsely reported "inactive" for a genuinely
  working tunnel. Live-verified fix: `active (exited)` now shown correctly
  alongside a real `wg show` handshake. See `docs/arch/config-and-lifecycle.md`.
- **`install` calls `systemctl enable` and `systemctl start` separately,
  not `enable --now`.** After the `Type=oneshot` fix, `enable --now` on a
  fresh, intentionally-incomplete skeleton config (no `peer_public_key`/
  `peer_endpoint`/`relay_ips` yet) synchronously fails and was propagating
  as `install` itself returning non-zero — even though everything
  `install` is actually responsible for (binary, config, unit, enablement)
  had succeeded. `start`'s failure is now reported as an informational
  `note:` instead. Also added: `uninstall` now runs `systemctl
  reset-failed` on the unit (best-effort) to clear the cosmetic "failed"
  ghost entry this same on-failure/incomplete-config interaction can leave
  in `systemctl list-units --all`.
- **`otherEnabledInstanceUnits` globs the `multi-user.target.wants`
  enablement-symlink directory directly, not `systemctl list-unit-files`.**
  The latter was tried first and empirically only ever lists the shared
  template itself (state `indirect`) for a templated unit, never the
  per-instance instantiated units — it can't answer "is any other instance
  still enabled" at all. The symlink-glob approach is correct and directly
  unit-testable against a `t.TempDir()` fixture.
- **The shared unit template is kept in sync on every `install`, not only
  written once "if not already present."** `writeUnitIfChanged` rewrites
  the on-disk template whenever it differs from the binary's embedded
  copy (still never *removed* while another instance depends on it — that
  guard is unchanged). Without this, a machine installed before the
  `Type=oneshot` fix above would have kept running the broken
  `Type=simple` unit through every later `install`, silently — this is
  the same class of bug the `Type=oneshot` revision was written to fix,
  just one layer up (a good template embedded in the binary, never
  reaching the disk of a machine installed before that template changed).
  Unit-tested (missing / stale / already-current cases) against a
  `t.TempDir()` fixture, same pattern as `otherEnabledInstanceUnits`.
- **`uninstall --purge` on a client also removes leftover `ip rule`
  policy-routing entries, not just the interface.** The plan's original
  purge step (above) only mentioned `ip link delete`, but policy rules
  created by `ReconcileClientRouting` (`ip rule add from <ip> table
  <N> ...`) aren't device-bound — deleting the interface alone leaves them
  in the kernel forever, since nothing else revisits them once the config
  recording their relay IPs is gone. `purgeClientPolicyRules` reads live
  `ip rule show` output (reusing `parseIPRuleShowForTable`/
  `tableForInstance` from the runtime path) rather than trusting the
  config's `relay_ips`, so cleanup is correct even if they'd already
  drifted. Server-role purge is unaffected — the server side only creates
  device-scoped host routes, which `ip link delete` already reclaims.
  Live-verified: a throwaway client instance's `ip addr`/`ip rule`/route-
  table entries were confirmed present after `start` and fully gone after
  `uninstall --purge`, with the real running instance left undisturbed.
- **Purge tears down the interface (and, for a client, its policy rules)
  *before* removing the config file, not after.** The config is the only
  record of a non-default `interface_name`; removing it first meant a
  failed interface teardown could never be retried correctly (a re-run
  would fall back to `defaultInterfaceName` and lose track of the real
  one).

## Exit criteria

- [x] `wganchor install server` / `install client` on a fresh instance
      produce a running, enabled systemd service and a `0600` config with
      concrete `listen_port`/`interface_name`; keypair generated and
      public key printed. (Live-verified on both the VPS and the home
      machine; "running" qualified by the enable/start split above — a
      fresh skeleton's `start` is expected to fail until the operator
      fills in peer info, and `install` still exits 0 in that case.)
- [x] Re-running `install` for the same instance is idempotent: no
      duplicated units, no regenerated keys/config. (Live-verified: real
      instance `0` on both machines re-`install`ed with no disruption to
      its running state.)
- [x] `wganchor uninstall` stops/disables/removes the per-instance
      enablement; config and interface survive unless `--purge` is
      passed; `--purge` removes them. The binary and the shared
      `wganchor-<role>@.service` template file are never removed by
      `uninstall` (with or without `--purge`).
- [x] Uninstalling a never-installed instance is a no-op, not an error.
- [x] Uninstalling one instance of a role (e.g. `client` instance `1`)
      while another instance of the same role (`client` instance `0`)
      remains installed and enabled does not disable or remove that other
      instance, and does not delete the shared template unit file while
      it's still in use. (Unit-tested against `t.TempDir()` fixtures;
      live-verified on both machines with real instance `0` left
      undisturbed by installing/purging a throwaway instance `1`/`2`/`3`.)
- [x] `install`/`uninstall` invoked as non-root, or on a host without
      `systemctl` on `PATH`, fail with an actionable error before any
      state is touched (verified: no binary copied, no config written, no
      unit installed). (Live-verified the non-root case; the missing-
      `systemctl` case relies on `exec.LookPath` and is additionally
      covered by unit tests around `precheckLifecycle`.)
- [x] `install client --instance 1` produces a distinct, non-colliding
      systemd unit and config from instance `0`, verified without needing
      a second VPS. (Live-verified on the home machine.)
- [x] Live two-independent-tunnel validation: either completed (if the
      user provides a second VPS during this sprint) or explicitly logged
      as the sprint's one remaining deferred item, not silently dropped.
      **Completed.** The user provisioned a second, independent VPS
      (a sibling project's host, borrowed for this validation only) with
      a genuine provider-assigned secondary IPv4 distinct from its own
      primary/management address — confirmed via the provider's instance
      metadata service before touching anything, specifically to avoid
      routing the relay IP over the box's own SSH-bearing primary address.
      `wganchor install server --instance 1` on that VPS and
      `wganchor install client --instance 1` at home, keys exchanged
      manually, `relay_ips` set to the secondary IP. Result, with the
      real instance `0` tunnel (a different VPS) active and undisturbed
      throughout:
      - Both tunnels handshake and run concurrently; `wg show` lists two
        separate interfaces with distinct keys, ports, and
        `AllowedIPs`; instance 1's client-side policy-routing table/
        priority (60218/20218) is correctly isolated from instance 0's
        (60217/20217).
      - Inbound: an HTTP server bound to the secondary IP at home,
        reached over the public internet by curling it from the VPS
        itself, returned the expected response.
      - Outbound: a curl from home sourced from the secondary IP
        (`--interface`) reached an HTTP server on the VPS's primary IP;
        the VPS's access log recorded the source as the secondary IP,
        confirming egress is actually routed through the tunnel rather
        than the host's normal route.
      - Teardown: both instances `uninstall --purge`d cleanly, and the
        borrowed VPS's firewall rules, `ip_forward` sysctl, and
        `wireguard-tools` package were all reverted to their pre-test
        state (verified: `iptables -L FORWARD` policy unchanged,
        no wganchor units/binary/config remain). The user's own
        provider-assigned secondary IP itself was left alone — that's
        provisioned at the account level, not something `wganchor`
        or this validation ever touched.
