# Plan: Environment Setup

Depended on `plan-research.md` for the Vultr secondary-IP question — now
resolved (see `docs/arch/overview.md`): the secondary IP is confirmed to
route to the VPS's link without any local binding, so no Netplan change
is needed for it at all.

## VPS (Vultr, Ubuntu 26.04, primary `203.0.113.10`, relay `203.0.113.20`)

- [x] Second IPv4 (`203.0.113.20`) requested via the Vultr control
      panel and assigned; Vultr auto-rebooted the instance as part of
      that, confirmed still reachable over SSH on the primary IP
      afterward. Nothing further to do here — do **not** add
      `203.0.113.20` to Netplan; it stays unbound per
      `docs/arch/overview.md`.
- [x] `apt update && apt install -y wireguard-tools` — installed
      (`wireguard-tools 1.0.20250521-1ubuntu1`), 2026-08-29.
- [x] `sysctl net.ipv4.ip_forward=1`, persisted via
      `/etc/sysctl.d/99-wganchor.conf` (not just the running kernel) —
      confirmed both the file and the live sysctl value read back `1`.
- [x] Confirm `wg` and `wg-quick` are on `PATH` — `/usr/bin/wg`,
      `/usr/bin/wg-quick`.
- [x] Confirm nothing else on the VPS already listens on UDP `60217` (the
      `wganchor` default, chosen specifically to avoid the standard
      WireGuard `51820` — see `docs/arch/wireguard.md`) — `ss -uln | grep
      60217`. The VPS is the side holding the listening endpoint (home is
      typically behind NAT and initiates), so a collision here matters at
      least as much as on the home machine. Confirmed free, both before
      and after the `wireguard-tools` install.

## Home machine (Ubuntu 24.04, `6.8.0-138-generic`)

- [x] `apt update && apt install -y wireguard-tools` — installed
      (`wireguard-tools v1.0.20210914`), 2026-08-29. Machine already runs
      Tailscale (its own userspace WireGuard, interface `tailscale0`) —
      confirmed no collision with `wganchor0`/`60217`, which is exactly
      the scenario the naming/port decisions in `docs/arch/wireguard.md`
      were made to avoid.
- [x] Confirm `wg` and `wg-quick` are on `PATH` — `/usr/bin/wg`,
      `/usr/bin/wg-quick`.
- [x] Confirm nothing else on this machine already listens on UDP `60217`
      (`ss -uln | grep 60217`) — confirmed free, both before and after
      the `wireguard-tools` install.

## Go toolchain

- [x] Install Go (latest stable) on whichever machine will build the
      binary. Both machines are `x86_64`/Linux (confirmed via `uname -m`
      on each), so no cross-compilation is needed regardless of which
      builds. **Decision: home machine is the build machine** — installed
      Go 1.27.0 to `/usr/local/go` (tarball sha256 verified against the
      official `go.dev/dl` JSON index before extracting), `PATH` already
      included `/usr/local/go/bin` via `~/.bashrc` from a prior setup.
      VPS has no Go toolchain and doesn't need one — it only ever runs the
      built binary.
- [x] `go version` confirms install (`go1.27.0 linux/amd64` on the home
      machine); `go env GOOS GOARCH` → `linux`/`amd64`, matching the VPS's
      own `uname -m` (`x86_64`) — no `GOOS`/`GOARCH` override needed when
      building for the VPS.

## Exit criteria

- [x] `wireguard-tools` installed and functional on both machines.
- [x] VPS has a second public IPv4 assigned and confirmed reachable at the
      network layer (`203.0.113.20`, confirmed via `tcpdump` in
      `docs/arch/overview.md`).
- [x] IP forwarding persisted on the VPS.
- [x] Go builds successfully on the chosen build machine(s), targeting
      `linux/amd64` (confirmed matching the VPS's actual arch,
      `x86_64`/`amd64`, via `uname -m` — not assumed).
