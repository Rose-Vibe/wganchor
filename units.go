package main

import (
	_ "embed"
	"fmt"
)

// Systemd unit templates, embedded so the binary stays single-file (no
// separate files to distribute alongside it) — see
// docs/sprints/wireguard-automation/plan-lifecycle.md.
//
//go:embed units/wganchor-server@.service
var serverUnitTemplate string

//go:embed units/wganchor-client@.service
var clientUnitTemplate string

// unitTemplateForRole returns the embedded systemd unit template content
// for role. Callers are expected to have already validated role is
// "server" or "client".
func unitTemplateForRole(role string) string {
	if role == "server" {
		return serverUnitTemplate
	}
	return clientUnitTemplate
}

// unitFileName is the shared systemd template file name for role — used
// by every instance of that role on the machine (%i is the instance
// number), per config-and-lifecycle.md.
func unitFileName(role string) string {
	return fmt.Sprintf("wganchor-%s@.service", role)
}

// unitName is the concrete, instantiated systemd unit name for a specific
// role and instance.
func unitName(role string, instance int) string {
	return fmt.Sprintf("wganchor-%s@%d.service", role, instance)
}
