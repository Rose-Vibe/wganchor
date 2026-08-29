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
- [ ] `apt update && apt install -y wireguard-tools`
- [ ] `sysctl net.ipv4.ip_forward=1`, persisted via
      `/etc/sysctl.d/`, not just the running kernel.
- [ ] Confirm `wg` and `wg-quick` are on `PATH`.
- [ ] Confirm nothing else on the VPS already listens on UDP `60217` (the
      `wganchor` default, chosen specifically to avoid the standard
      WireGuard `51820` — see `docs/arch/wireguard.md`) — `ss -uln | grep
      60217`. The VPS is the side holding the listening endpoint (home is
      typically behind NAT and initiates), so a collision here matters at
      least as much as on the home machine.

## Home machine (Ubuntu 24.04, `6.8.0-138-generic`)

- [ ] `apt update && apt install -y wireguard-tools`
- [ ] Confirm `wg` and `wg-quick` are on `PATH`.
- [ ] Confirm nothing else on this machine already listens on UDP `60217`
      (`ss -uln | grep 60217`) — avoid a collision before the PoC.

## Go toolchain

- [ ] Install Go (latest stable) on whichever machine will build the
      binary. Since the project ships a single static Linux binary, only
      the build machine strictly needs Go — decide now whether that's the
      home machine (cross-compiling `GOOS=linux GOARCH=amd64` for the VPS
      if architectures differ) or both, and record the decision here.
- [ ] `go version` confirms install; `go env GOOS GOARCH` recorded for
      each machine so cross-compilation targets are known.

## Exit criteria

- [ ] `wireguard-tools` installed and functional on both machines.
- [x] VPS has a second public IPv4 assigned and confirmed reachable at the
      network layer (`203.0.113.20`, confirmed via `tcpdump` in
      `docs/arch/overview.md`).
- [ ] IP forwarding persisted on the VPS.
- [ ] Go builds successfully on the chosen build machine(s), targeting
      `linux/amd64` (or whatever the VPS's actual arch is — confirm via
      `uname -m`, don't assume amd64).
