// Command shoalcheck-scan is the OSS (Apache-2.0) audit scanner.
//
// It connects to a Kubernetes cluster READ-ONLY (never Secrets, ConfigMaps,
// env values, logs, or exec), runs the detection rules, assembles a schema-v1
// AuditReport, and writes it as JSON to --output (or stdout). It does NOT
// render HTML — that is the proprietary `shoalcheck` binary's job.
//
// IMPORT BOUNDARY: this binary depends ONLY on the Apache-2.0 packages
// (collect, rules, prom, pricing, redact, types) via internal/pipeline. It MUST
// NOT import shoalcheck/internal/report. scripts/depcheck.sh enforces this, and
// scripts/oss-tree.sh proves the OSS subset (including this binary) compiles
// standalone with zero proprietary dependencies.
//
// This is the product boundary made real: the OSS half collects a cluster and
// emits the AuditReport JSON; the proprietary renderer turns that JSON into the
// polished HTML report.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/pipeline"
	"github.com/Shoalcheck/shoalcheck-scan/internal/trace"
)

const usage = `shoalcheck-scan — OSS Kubernetes audit scanner (JSON output).

usage:
  shoalcheck-scan [--kubeconfig <path>] [--context <name>] [--output <path.json>]
             [--include-system] [--prometheus-url <url>] [--discount <0..0.9>]
             [--redact] [--cluster-name <name>]
  shoalcheck-scan --show-permissions

Connects to a cluster READ-ONLY (never reads Secrets, ConfigMaps, env values,
logs, or exec), runs detection rules, assembles a schema-v1 AuditReport, and
writes it as JSON. Render the JSON to HTML with the 'shoalcheck render' command.

flags:
  --kubeconfig       path to kubeconfig (default: standard loading rules)
  --context          kubeconfig context (default: current context)
  --output           path to write the AuditReport JSON (default: stdout)
  --cluster-name     display name for the cluster (default: context name or 'cluster')
  --include-system   evaluate rules in system namespaces too
  --prometheus-url   base URL of a Prometheus-compatible endpoint
                     (e.g. http://127.0.0.1:9090); enables usage-based analysis.
                     If omitted, in-cluster endpoints are auto-detected.
  --discount         fractional list-price discount in [0,0.9] (e.g. 0.3 = 30%)
                     for RI/Savings-Plan-adjusted spend. Default: 0 (list).
  --redact           tokenize cluster/node/namespace/workload/RBAC names so the
                     report is safe to share externally.
  --force            overwrite an existing --output file (default: refuse)
  --show-permissions print the exact read-only access required, then exit
                     without connecting to any cluster.
`

func main() {
	err := run(os.Args[1:])
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	os.Exit(exitCode(err))
}

// exitCode is 0 for success and for a help request — the usage was printed, which is what was asked for —
// and 1 for anything else.
func exitCode(err error) int {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 1
}

func run(args []string) error {
	fs := flag.NewFlagSet("shoalcheck-scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: standard loading rules)")
	kctx := fs.String("context", "", "kubeconfig context (default: current context)")
	output := fs.String("output", "", "path to write the AuditReport JSON (default: stdout)")
	clusterName := fs.String("cluster-name", "", "display name for the cluster (default: context name or 'cluster')")
	includeSystem := fs.Bool("include-system", false, "evaluate rules in system namespaces too")
	prometheusURL := fs.String("prometheus-url", "", "base URL of a Prometheus-compatible endpoint (e.g. http://127.0.0.1:9090)")
	discount := fs.Float64("discount", 0, "fractional discount in [0,0.9] on COMPUTE list price (e.g. 0.3 = 30% off node hours, for RI/Savings-Plan rates); storage, load balancers and control plane stay at list")
	redactOut := fs.Bool("redact", false, "tokenize cluster/node/namespace/workload/RBAC names so the report is safe to share externally")
	force := fs.Bool("force", false, "overwrite an existing --output file (default: refuse)")
	showPerms := fs.Bool("show-permissions", false, "print the exact read-only access the scan needs, then exit without connecting")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// --show-permissions never touches a cluster: print scope and exit 0. This
	// lets an SRE review exactly what access the scan needs before granting it.
	if *showPerms {
		printPermissions(os.Stdout)
		return nil
	}
	if *discount < 0 || *discount > 0.9 {
		return fmt.Errorf("--discount must be in [0, 0.9], got %v", *discount)
	}
	if *output != "" {
		if err := guardOutput(*output, *force); err != nil {
			return err
		}
	}

	// The OSS binary records its own session too. It is the one people read the SOURCE of before running it,
	// so it is the last place that should emit a report making a read-only claim with no measurement behind it —
	// and the JSON it writes is exactly what a reviewer would diff against their own audit log.
	rec := trace.New(nil)
	rec.SetPhase(trace.PhaseRun)

	col, err := collect.New(*kubeconfig, *kctx, collect.WithTransportRecorder(rec))
	if err != nil {
		return err
	}

	// The collect→rules→assemble→compliance→validate→redact pipeline is the
	// exact same code path the proprietary `shoalcheck audit` runs, via the shared
	// internal/pipeline package. The only difference: this binary emits JSON
	// and never imports the proprietary HTML renderer.
	ar, err := pipeline.Run(context.Background(), pipeline.Options{
		Collector:     col,
		ClusterName:   *clusterName,
		IncludeSystem: *includeSystem,
		PrometheusURL: *prometheusURL,
		Discount:      *discount,
		Redact:        *redactOut,
		Recorder:      rec,
		Log:           os.Stderr,
	})
	if err != nil {
		return err
	}
	// The same question `shoalcheck audit` asks before it keeps anything: a run that reached no object is not a
	// reading, and a JSON document with zero findings on stdout is what a pipeline would store as a clean one.
	if err := pipeline.NothingRead(ar); err != nil {
		return fmt.Errorf("%w; no report was written", err)
	}

	data, err := json.MarshalIndent(ar, "", "  ")
	if err != nil {
		return err
	}
	if *output == "" {
		if _, err := os.Stdout.Write(append(data, '\n')); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "scan complete — %d findings (JSON on stdout)\n", len(ar.Findings))
		return nil
	}
	if err := os.WriteFile(*output, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *output, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s — %d findings\n", *output, len(ar.Findings))
	return nil
}

func guardOutput(path string, force bool) error {
	if force {
		return nil
	}
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	return fmt.Errorf("%s exists; pass --force to overwrite", path)
}

// printPermissions writes the exact read-only access the scan will use, driven
// from collect.CollectedResources() (the same list the collector and the
// published ClusterRole are tested against). Mirrors `shoalcheck audit
// --show-permissions` so the OSS scanner is reviewable before it touches a
// cluster.
func printPermissions(w io.Writer) {
	fmt.Fprintln(w, "shoalcheck-scan — required access (read-only, get + list only):")
	fmt.Fprintln(w)
	for _, ra := range collect.CollectedResources() {
		group := ra.APIGroup
		if group == "" {
			group = "core"
		}
		fmt.Fprintf(w, "  %-26s %-26s %s\n", group, ra.Resource, strings.Join(ra.Verbs, ","))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Never read: Secret values, ConfigMap data, logs, exec. Pod environment values arrive")
	fmt.Fprintln(w, "inside pod specs and are dropped on arrival; only variable names are kept.")
	fmt.Fprintln(w, "Never written: no create/update/patch/delete, no watch.")
	fmt.Fprintln(w, "Apply the matching ClusterRole from deploy/rbac.yaml.")
}
