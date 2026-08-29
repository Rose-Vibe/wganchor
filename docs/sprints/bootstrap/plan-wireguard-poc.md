# Plan: Manual WireGuard PoC + Go Skeleton

Depends on `plan-research.md` (routing design) and `plan-environment.md`
(packages installed, secondary IP assigned).

## Manual proof-of-concept (no Go involved yet)

The goal is to prove the packet path from `docs/arch/overview.md` actually
works on the real VPS before writing any code that automates it.

- [x] Generate a WireGuard keypair on each machine by hand (`wg genkey`,
      `wg pubkey`).
- [x] Hand-write `wganchor0.conf` on both sides — interface name
      `wganchor0` and `ListenPort 60217` on the VPS side, per
      `docs/arch/wireguard.md` (deliberately not `wg0`/`51820`, to avoid
      colliding with a typical unrelated WireGuard setup on either
      machine) — home side includes `PersistentKeepalive` at the interval
      decided in the research doc, since home is expected to sit behind
      NAT. Bring the tunnel up with `wg-quick up ./wganchor0.conf`.
      Confirm `wg show wganchor0` reports a handshake. Confirmed.
- [x] On the VPS, apply the routing design from the research doc: route
      the secondary IP's /32 to `wganchor0`, forwarding enabled. Also
      required VPS ufw rules not anticipated in the original design — see
      `docs/arch/overview.md`.
- [x] On the home machine, assign the secondary IP to `wganchor0` (or
      configure the policy route that lets a process bind it). Required
      `AllowedIPs = 0.0.0.0/0` + `Table = off` + a manual `ip rule`/custom
      routing table (`60217`/`20217`) — see `docs/arch/overview.md` for the
      full mechanism and why a narrow `AllowedIPs` isn't sufficient.
- [x] **Inbound path:** run a trivial listener on the home machine bound
      explicitly to the secondary IP (e.g. `python3 -m http.server --bind
      <secondary-ip> 8080` or `nc -l`). From a third machine (not the VPS,
      not the home machine — e.g. a phone on cellular, or any external
      host) hit `http://<secondary-ip>:8080` and confirm the response
      arrives. Confirmed (external host: a briefly-borrowed VPS from an
      unrelated project, per user's explicit one-time authorization).
- [x] **Outbound path:** from the home machine, originate a connection
      bound to the secondary IP (e.g. `curl --interface <secondary-ip>
      https://ifconfig.me`) and confirm the external service reports back
      the secondary IP, not the VPS's primary IP or the home machine's
      real WAN IP. This is the direction most likely to hit `rp_filter`
      or policy-routing gaps — don't skip it. Confirmed — see
      `docs/arch/overview.md` for the WireGuard cryptokey-routing fix that
      was actually required (not a kernel-routing or `rp_filter` issue).
- [x] **Idle/NAT keepalive check:** leave the tunnel idle for at least 5
      minutes, then repeat the inbound test. Confirms `PersistentKeepalive`
      is actually keeping the NAT mapping alive rather than the first test
      passing only because the handshake was still fresh. Confirmed —
      handshake refreshed throughout the idle period, inbound test
      unchanged afterward.
- [x] **MTU check:** transfer a payload larger than one MTU (e.g. a 1 MB
      file) over the inbound path. WireGuard's ~80-byte overhead means a
      small HTTP response can succeed while larger transfers fragment or
      stall — this needs its own test, not an inference from the small
      request above. Confirmed — 1 MB file transferred with matching
      SHA-256 on both ends.
- [x] Kill the listener and confirm the secondary IP stops responding
      (rules out "it was reachable some other way" false positives).
      Confirmed — `curl` returned exit 7 / HTTP 000 after the listener was
      killed.
- [x] Tear down the manual config (`wg-quick down ./wganchor0.conf`, remove
      the routes) —
      this PoC's artifacts don't need to persist, the config file the Go
      implementation writes later will supersede it. Done on both
      machines; ephemeral keys/configs deleted. VPS ufw rules and
      `ip_forward` sysctl were kept (durable environment setup, not
      PoC-only scaffolding).

All steps passed; no plan/assumption revisions were needed beyond the
routing/firewall mechanism details now recorded in `docs/arch/overview.md`
(the original design's *shape* was correct, the exact `AllowedIPs`/`Table`/
`ip rule` mechanics just weren't knowable without running it).

## Go project skeleton

Only start this once the manual PoC succeeds — no point building on an
unvalidated design.

- [x] `go.mod` for the module, single `main.go`-plus-packages layout, no
      external frameworks per CLAUDE.md conventions. (`go.mod` has no
      `require` lines.)
- [x] `server` and `client` subcommands (stdlib `flag`/`os.Args`
      dispatch, not a CLI framework — this is a two-subcommand tool).
- [x] `--instance <N>` flag (default `0`, `--instance=0` explicitly
      identical to omitting the flag — not a special case), per
      `docs/arch/wireguard.md`'s uniform instance-numbering formula.
      Drives the config path (`.../<N>.json`), the default
      `interface_name` (`wganchor<N>`), and the default `listen_port`
      (`60217 + N`) — pure computation, no live tunnel or second VPS
      needed to write or test it. Bounds-checked so `listen_port` stays a
      valid port number.
- [x] Config file loading: JSON, using the layered lookup order from
      `docs/arch/config-and-lifecycle.md` (`--config` flag →
      `os.UserConfigDir()/wganchor/<N>.json` → `/etc/wganchor/<N>.json`,
      `N` from `--instance`; no implicit cwd lookup — dev use passes
      `--config` explicitly). Refuses to load a config file that isn't
      mode `0600`, or one that's a directory. Schema matches what
      `docs/arch/wireguard.md` specifies for keys, peer endpoint, and
      `relay_ips` (a list, even though this deployment only has one relay
      IP so far). Parsing only; no WireGuard calls yet, and no
      `install`/`uninstall`/systemd work — that's later, this step is
      just proving the lookup-and-parse path.
- [x] Both subcommands currently just print the parsed config and exit —
      real interface/tunnel setup is sprint 2. Private key is redacted in
      the printed output.
- [x] `gofmt` clean, `go build` and `go vet` pass.
- [x] Build with `CGO_ENABLED=0`, then confirm staticness with `file` and
      `ldd` (`ldd` should report "not a dynamic executable") — matches the
      CLAUDE.md "single static Linux binary" convention, and this is the
      only place in the sprint that actually checks it. Confirmed.

Reviewed by an Opus-model implementation reviewer: PASS, with one required
fix (compiled binary was untracked in the repo root, `.gitignore` didn't
cover it) and three optional nits (directory rejection on explicit
`--config`, instance bounds checking, a stronger distinctness assertion in
the no-config-found test), all applied before commit.

## Exit criteria

- [x] External host reached a process bound to the secondary IP on the
      home machine, through a hand-configured WireGuard tunnel, on both
      the inbound and outbound paths, and after an idle/NAT-keepalive
      period — this is the sprint's key validation and gates sprint 2
      being planned at all.
- [x] A payload larger than one MTU transferred successfully over the
      tunnel.
- [x] Any deviation from the research doc's assumed routing design is
      written back into `docs/arch/overview.md`.
- [x] `wganchor server` / `wganchor client` build as a single static
      binary (verified via `ldd`/`file`, not assumed), parse a config
      file, and run without error.
- [x] `--instance 1` (no config file present) computes a distinct config
      path, default `interface_name`, and default `listen_port` from the
      no-flag/`--instance 0` case, confirming the uniform numbering
      formula actually holds in code — verified by inspection/printed
      output, no second VPS or live tunnel required. Also locked in by
      `TestResolveConfigPathNoneFoundReturnsErrAndChecked` and
      `TestInstanceDefaultsAreDistinct`.
