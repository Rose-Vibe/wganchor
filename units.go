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

//go:embed units/wganchor-watch-server@.service
var watchServerUnitTemplate string

//go:embed units/wganchor-watch-client@.service
var watchClientUnitTemplate string

// unitTemplateForRole returns the embedded systemd unit template content
// for role. Callers are expected to have already validated role is
// "server" or "client".
func unitTemplateForRole(role string) string {
	if role == "server" {
		return serverUnitTemplate
	}
	return clientUnitTemplate
}

// watchUnitTemplateForRole is unitTemplateForRole's counterpart for the
// watch companion unit.
func watchUnitTemplateForRole(role string) string {
	if role == "server" {
		return watchServerUnitTemplate
	}
	return watchClientUnitTemplate
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

// watchRoleFor derives the "role" string that, fed through unitFileName/
// unitName (both plain string formatting, unlike unitTemplateForRole),
// yields exactly the watch companion unit's file name — e.g. "client" ->
// "watch-client" -> "wganchor-watch-client@.service"/
// "wganchor-watch-client@N.service". Kept distinct from the true role so
// it's never passed to unitTemplateForRole, which only knows "server"/
// "client" and would silently fall back to the client bring-up template
// otherwise.
func watchRoleFor(role string) string {
	return "watch-" + role
}
