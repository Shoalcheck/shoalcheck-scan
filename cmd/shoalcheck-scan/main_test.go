package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestShowPermissions_ExitsWithoutConnecting verifies --show-permissions is a
// pure local print: it returns nil WITHOUT building a collector or contacting a
// cluster, exactly like `shoalcheck audit --show-permissions`. (If it tried to
// connect it would fail/hang in the test environment.)
func TestShowPermissions_ExitsWithoutConnecting(t *testing.T) {
	if err := run([]string{"--show-permissions"}); err != nil {
		t.Fatalf("--show-permissions must exit 0 without connecting, got: %v", err)
	}
}

// TestShowPermissions_IgnoresOtherFlags verifies --show-permissions short-circuits
// even when cluster-targeting flags are present (it never reaches collect.New).
func TestShowPermissions_IgnoresOtherFlags(t *testing.T) {
	err := run([]string{"--show-permissions", "--kubeconfig", "/nonexistent/kubeconfig", "--context", "nope"})
	if err != nil {
		t.Fatalf("--show-permissions must not connect even with --kubeconfig/--context, got: %v", err)
	}
}

// TestDiscountOutOfRange verifies the discount guard fires before any cluster
// access, so a bad flag fails fast and cluster-free.
func TestDiscountOutOfRange(t *testing.T) {
	err := run([]string{"--discount", "1.5"})
	if err == nil || !strings.Contains(err.Error(), "--discount must be in [0, 0.9]") {
		t.Fatalf("want discount-range error, got: %v", err)
	}
}

// TestUnknownFlagErrors verifies flag parsing rejects unknown flags rather than
// silently proceeding to connect.
func TestUnknownFlagErrors(t *testing.T) {
	if err := run([]string{"--frobnicate"}); err == nil {
		t.Fatal("unknown flag must be an error")
	}
}

// ASKING FOR HELP IS NOT A FAILURE, and on this binary least of all: shoalcheck-scan is the open-source build, so
// `shoalcheck-scan --help` is the first command a stranger who found it on GitHub types. It printed the usage and
// then "error: flag: help requested" at exit 1.
func TestScan_HelpIsNotAnError(t *testing.T) {
	for _, h := range []string{"--help", "-h"} {
		if code := exitCode(run([]string{h})); code != 0 {
			t.Errorf("shoalcheck-scan %s exits %d; asking for help exits 0", h, code)
		}
	}
}

// The OSS scan emits the same JSON the audit keeps, so it refuses the same non-reading: a run against a cluster
// that refused every connection used to print a valid AuditReport with zero findings to stdout at exit 0, which a
// pipeline would store as a clean result.
func TestScan_RefusesARunThatReadNothing(t *testing.T) {
	kc := filepath.Join(t.TempDir(), "kubeconfig")
	body := "apiVersion: v1\nkind: Config\nclusters: [{name: dead, cluster: {server: \"http://127.0.0.1:1\"}}]\n" +
		"users: [{name: none, user: {}}]\ncontexts: [{name: dead, context: {cluster: dead, user: none}}]\ncurrent-context: dead\n"
	if err := os.WriteFile(kc, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "scan.json")
	err := run([]string{"--kubeconfig", kc, "--output", out})
	if err == nil {
		t.Fatal("a scan of a cluster that refused every connection succeeded")
	}
	if exitCode(err) == 0 {
		t.Error("the refusal exits 0")
	}
	if _, serr := os.Stat(out); serr == nil {
		t.Error("the scan wrote a report for a run that read nothing")
	}
}
