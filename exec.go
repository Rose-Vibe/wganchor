package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// runCmd runs name with args and returns trimmed stdout. On failure the
// error includes stderr, since exec.Command's bare error ("exit status 1")
// is useless for diagnosing an ip/wg failure.
func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...) //nolint:gosec // callers always pass a fixed system binary (ip/wg/nft/systemctl) with internally-constructed args, never external/untrusted input
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// runCmdStdin is runCmd but feeds stdin to the child process — used so a
// private key can be piped in rather than ever appearing in argv.
func runCmdStdin(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...) //nolint:gosec // callers always pass a fixed system binary with internally-constructed args, never external/untrusted input
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(stdout.String()), nil
}

// commandSucceeds runs name with args and reports only whether it
// exited zero, for existence/type checks where stdout doesn't matter.
func commandSucceeds(name string, args ...string) bool {
	cmd := exec.Command(name, args...) //nolint:gosec // callers always pass a fixed system binary with internally-constructed args, never external/untrusted input
	return cmd.Run() == nil
}
