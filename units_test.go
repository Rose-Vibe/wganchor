package main

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
