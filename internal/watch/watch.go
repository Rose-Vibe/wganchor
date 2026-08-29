// Package watch implements `wganchor watch <role>`: a self-healing
// reconciliation loop that repairs live routing/address/rule state when
// it drifts from the config, per docs/arch/resilience.md.
package watch

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"wganchor/internal/config"
	"wganchor/internal/routing"
)

// shouldTrigger reports whether line — one line of `ip monitor rule`
// output — announces the deletion of the rule this instance owns,
// identified by requiring *both* table and priority (from
// routing.TableForInstance/PriorityForInstance) to match: this tool's own
// rules always carry both together, and requiring both avoids a false
// trigger on an unrelated rule that happens to share only one of the two
// numbers. Deletion lines are prefixed "Deleted " ahead of the same
// shape `ip rule show` itself uses (confirmed empirically against the
// installed iproute2 build, e.g. "Deleted 20217:\tfrom 203.0.113.20
// lookup 60217"); an added/changed rule has no such prefix and must
// never trigger.
//
// parseFailed reports a "Deleted" line that couldn't be cleanly read
// enough to rule out being ours — an unparsable priority field, or a
// priority match with no parseable table — worth logging (it may mean a
// newer iproute2 changed the line format), unlike the common, silent
// case of a deletion that simply isn't ours (a cleanly-parsed, different
// priority; or no "Deleted" prefix at all).
func shouldTrigger(line string, table, priority int) (trigger, parseFailed bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 || fields[0] != "Deleted" {
		return false, false
	}
	fields = fields[1:]
	if len(fields) == 0 {
		return false, true
	}
	prio, err := strconv.Atoi(strings.TrimSuffix(fields[0], ":"))
	if err != nil {
		return false, true
	}
	if prio != priority {
		return false, false
	}
	for i, f := range fields {
		if (f == "lookup" || f == "table") && i+1 < len(fields) {
			if t, err := strconv.Atoi(fields[i+1]); err == nil {
				return t == table, false
			}
			return false, true
		}
	}
	return false, true
}

// watchRules runs `ip monitor rule` for as long as ctx is live, calling
// onStart immediately after every (re)start of the subprocess — the
// first start included — and onEvent whenever a deleted-rule line
// matches table/priority per shouldTrigger. A start failure (e.g. `ip`
// missing from PATH) is treated exactly like a post-start subprocess
// exit — logged and retried after a capped exponential backoff — rather
// than returning, so the watcher never silently stops watching even if
// it never manages a single successful start; each restart is logged.
// The backoff only resets once a run has stayed up for a while (rather
// than immediately after every successful Start), so a subprocess that
// starts fine but crash-loops instantly still backs off exponentially
// instead of retrying every second forever. Returns nil once ctx is
// cancelled.
func watchRules(ctx context.Context, table, priority int, onStart func(), onEvent func()) error {
	const initialBackoff = time.Second
	const maxBackoff = 30 * time.Second
	const minHealthyUptime = 10 * initialBackoff
	backoff := initialBackoff

	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, "ip", "monitor", "rule")
		stdout, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintf(os.Stderr, "wganchor watch: ip monitor rule: %v; retrying in %s\n", err, backoff)
			if !sleepOrCancelled(ctx, backoff) {
				return nil
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}

		started := time.Now()
		onStart()

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			trig, parseFailed := shouldTrigger(line, table, priority)
			if parseFailed {
				fmt.Fprintf(os.Stderr, "wganchor watch: could not parse ip monitor rule line, not triggering: %q\n", line)
			}
			if trig {
				onEvent()
			}
		}
		if scanErr := scanner.Err(); scanErr != nil {
			fmt.Fprintf(os.Stderr, "wganchor watch: ip monitor rule: reading output: %v\n", scanErr)
		}
		waitErr := cmd.Wait()

		if ctx.Err() != nil {
			return nil
		}
		if time.Since(started) >= minHealthyUptime {
			backoff = initialBackoff
		}
		fmt.Fprintf(os.Stderr, "wganchor watch: ip monitor rule exited (%v); restarting in %s\n", waitErr, backoff)
		if !sleepOrCancelled(ctx, backoff) {
			return nil
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
	return nil
}

// sleepOrCancelled waits for d or ctx cancellation, whichever comes
// first, reporting whether the full wait elapsed (false means ctx was
// cancelled and the caller should stop retrying).
func sleepOrCancelled(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// reconcileOnce loads configPath fresh (so an edit made while the
// watcher is running takes effect on the next trigger, matching the
// existing "config is the source of truth" posture) and reconciles the
// live state for role/instance against it. ValidateConfig runs here just
// as it does on the run() bring-up path (cmd/wganchor) — config.Load
// alone accepts a semantically-empty config (e.g. relay_ips: null), and
// without this check a config caught mid-edit would make the watcher
// itself delete every currently-live address/rule for the instance: the
// exact damage this self-healing daemon exists to prevent, not repair.
func reconcileOnce(role string, instance int, configPath string) (routing.ReconcileResult, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return routing.ReconcileResult{}, err
	}
	name := cfg.InterfaceName
	if name == "" {
		name = config.DefaultInterfaceName(instance)
	}
	if err := config.ValidateConfig(cfg, role); err != nil {
		return routing.ReconcileResult{}, err
	}
	if role == "server" {
		return routing.ReconcileServerRoutes(name, cfg.RelayIPs)
	}
	return routing.ReconcileClientRouting(name, cfg.RelayIPs, instance)
}

// describeChanges renders a ReconcileResult as the human-readable
// changes list used in watch's log lines. table is used only for the
// client-side entries (rules and the table default route) that are
// inherently table-scoped; server-side host routes are not.
func describeChanges(table int, r routing.ReconcileResult) string {
	var parts []string
	for _, ip := range r.AddrsAdded {
		parts = append(parts, fmt.Sprintf("added address %s/32", ip))
	}
	for _, ip := range r.AddrsRemoved {
		parts = append(parts, fmt.Sprintf("removed address %s/32", ip))
	}
	for _, route := range r.RoutesAdded {
		if route == "default" {
			parts = append(parts, fmt.Sprintf("added default route (table %d)", table))
		} else {
			parts = append(parts, fmt.Sprintf("added route %s/32", route))
		}
	}
	for _, route := range r.RoutesRemoved {
		if route == "default" {
			parts = append(parts, fmt.Sprintf("removed default route (table %d)", table))
		} else {
			parts = append(parts, fmt.Sprintf("removed route %s/32", route))
		}
	}
	for _, ip := range r.RulesAdded {
		parts = append(parts, fmt.Sprintf("added rule for %s (table %d)", ip, table))
	}
	for _, ip := range r.RulesRemoved {
		parts = append(parts, fmt.Sprintf("removed rule for %s (table %d)", ip, table))
	}
	return strings.Join(parts, ", ")
}

// Run is `wganchor watch <role> --instance N`'s main loop: an
// event-driven trigger (watchRules) plus a periodic backstop, both
// funneled through the same reconcileOnce/logging path, serialized so
// two triggers never reconcile concurrently against the same interface.
// Per docs/arch/resilience.md: log only when a reconcile actually
// repairs something, except for startup/restart/event announcements,
// which are logged unconditionally since they're operationally useful on
// their own.
func Run(role string, instance int, configPath string, interval time.Duration) error {
	table := routing.TableForInstance(instance)
	priority := routing.PriorityForInstance(instance)
	prefix := fmt.Sprintf("wganchor watch (%s, instance %d)", role, instance)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		cancel()
	}()

	var mu sync.Mutex
	trigger := func(label string, alwaysAnnounce bool) {
		mu.Lock()
		defer mu.Unlock()
		if alwaysAnnounce {
			fmt.Printf("%s: %s, reconciling\n", prefix, label)
		}
		result, err := reconcileOnce(role, instance, configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: reconcile error: %v\n", prefix, err)
			return
		}
		if !result.Changed() {
			return
		}
		changes := describeChanges(table, result)
		if alwaysAnnounce {
			fmt.Printf("%s: repaired — %s\n", prefix, changes)
		} else {
			fmt.Printf("%s: %s, repaired — %s\n", prefix, label, changes)
		}
	}

	first := true
	onStart := func() {
		if first {
			first = false
			trigger("starting up", true)
			return
		}
		trigger("ip monitor rule subprocess restarted", true)
	}
	// A repair here (e.g. `ip rule del from <ip> table <N>` removing a
	// stale rule) itself emits a "Deleted ..." ip-monitor line at our own
	// table/priority, which shouldTrigger matches — so a real repair is
	// always immediately followed by one more "rule change detected"
	// reconcile that finds nothing left to do. Self-terminating, just a
	// confusing-looking extra log line; not worth suppressing given the
	// alternative (tracking and ignoring our own writes) is more state
	// than this is worth.
	onEvent := func() {
		trigger("rule change detected", true)
	}

	watchErrCh := make(chan error, 1)
	go func() {
		watchErrCh <- watchRules(ctx, table, priority, onStart, onEvent)
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			<-watchErrCh
			return nil
		case err := <-watchErrCh:
			return err
		case <-ticker.C:
			trigger("periodic check", false)
		}
	}
}
