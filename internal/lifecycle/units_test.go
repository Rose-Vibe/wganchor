package lifecycle

import (
	"strings"
	"testing"
)

// TestUnitTemplateForRole guards the two properties this milestone's
// implementation history has already gotten wrong once for real:
// Type=oneshot/RemainAfterExit=yes (see docs/arch/config-and-lifecycle.md's
// "Lifecycle" section) and each role's embedded template actually
// containing that role's own ExecStart line, not the other role's.
func TestUnitTemplateForRole(t *testing.T) {
	cases := []struct {
		role         string
		wantExecPart string
	}{
		{"server", "wganchor server --instance %i"},
		{"client", "wganchor client --instance %i"},
	}
	for _, c := range cases {
		tmpl := unitTemplateForRole(c.role)
		for _, want := range []string{
			"Type=oneshot",
			"RemainAfterExit=yes",
			"WantedBy=multi-user.target",
			"Restart=on-failure",
			c.wantExecPart,
		} {
			if !strings.Contains(tmpl, want) {
				t.Errorf("unitTemplateForRole(%q) missing %q\ngot:\n%s", c.role, want, tmpl)
			}
		}
	}
}

func TestUnitFileNameAndUnitName(t *testing.T) {
	if got, want := unitFileName("client"), "wganchor-client@.service"; got != want {
		t.Errorf("unitFileName(client) = %q, want %q", got, want)
	}
	if got, want := unitName("server", 2), "wganchor-server@2.service"; got != want {
		t.Errorf("unitName(server, 2) = %q, want %q", got, want)
	}
}

// TestWatchUnitTemplateForRole guards the same properties as
// TestUnitTemplateForRole, for the watch companion unit: BindsTo the
// bring-up unit (so it stops when the tunnel it watches stops),
// WantedBy the bring-up unit specifically — not multi-user.target — so
// enabling it creates the symlink under the bring-up unit's own .wants/
// directory instead, Restart=always with a RestartSec (unlike the
// bring-up unit's bare Restart=on-failure) since a clean exit of a
// long-running watcher is still worth restarting, and
// StartLimitIntervalSec=0 so systemd's own default start-rate limit
// never puts the unit into a permanent failed state — internal/watch's own
// internal backoff already handles a crash-looping `ip monitor rule`
// without needing the process itself to exit and be restarted.
func TestWatchUnitTemplateForRole(t *testing.T) {
	cases := []struct {
		role         string
		wantExecPart string
	}{
		{"server", "wganchor watch server --instance %i"},
		{"client", "wganchor watch client --instance %i"},
	}
	for _, c := range cases {
		tmpl := watchUnitTemplateForRole(c.role)
		for _, want := range []string{
			"Type=simple",
			"Restart=always",
			"RestartSec=5",
			"StartLimitIntervalSec=0",
			"BindsTo=wganchor-" + c.role + "@%i.service",
			"WantedBy=wganchor-" + c.role + "@%i.service",
			c.wantExecPart,
		} {
			if !strings.Contains(tmpl, want) {
				t.Errorf("watchUnitTemplateForRole(%q) missing %q\ngot:\n%s", c.role, want, tmpl)
			}
		}
	}
}

func TestWatchRoleFor(t *testing.T) {
	if got, want := unitFileName(watchRoleFor("client")), "wganchor-watch-client@.service"; got != want {
		t.Errorf("unitFileName(watchRoleFor(client)) = %q, want %q", got, want)
	}
	if got, want := unitName(watchRoleFor("server"), 2), "wganchor-watch-server@2.service"; got != want {
		t.Errorf("unitName(watchRoleFor(server), 2) = %q, want %q", got, want)
	}
}
