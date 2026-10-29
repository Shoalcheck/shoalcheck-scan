# shoalcheck-scan

The open part of [Shoalcheck](https://shoalcheck.com), a read-only Kubernetes audit you run from your laptop.

This is the code that talks to your cluster: the collector, the transport every request goes through, and
the detection rules. It is published so you can read and build exactly what touches your cluster instead of
taking our word for it. Apache-2.0.

## What it may and may not read

- **The role.** [`deploy/rbac.yaml`](deploy/rbac.yaml) is the whole access the collector needs: `get` and
  `list` on the resource types it reads, and nothing else. No `watch`, no `create`, `update`, `patch` or
  `delete` on anything. Run with that role and your API server enforces it, not our code.
- **The never-read guard.** [`internal/trace/guard.go`](internal/trace/guard.go). Every client goes through
  one transport, and that transport refuses any request for `secrets`, `configmaps`, `pods/log`,
  `pods/exec`, `pods/attach` or `serviceaccounts/token` before it is sent, in any API group. That holds
  even if you run with a cluster-admin kubeconfig. The test that pins it counts what reaches a real HTTP
  server: [`internal/trace/guard_test.go`](internal/trace/guard_test.go).
- **The count.** [`internal/trace/recorder.go`](internal/trace/recorder.go) records every request the
  process issues, by verb and resource. A reading prints its reads and writes, and your API server's audit
  log is the witness: the counts should match it.
- **Where data goes.** Nowhere. The scan writes a JSON report to your disk. Nothing is uploaded, and there
  is no account.

## Build and run

```sh
go build ./cmd/shoalcheck-scan
./shoalcheck-scan --show-permissions     # print the exact read-only access it needs, without connecting
./shoalcheck-scan --output report.json   # scan the current kubeconfig context, write JSON
go test ./internal/trace/... ./internal/collect/...   # the guard, the count and the role
```

Most packages test on their own here, including `internal/trace` and `internal/collect`. A few test against
fixtures that live in the Shoalcheck monorepo and run in its CI; [the workflow](.github/workflows/ci.yml)
lists the ones that run here.

## What is not here

The HTML report, history and comparisons, the CI gate, tickets, the desktop app and the MCP server are the
commercial part of Shoalcheck. See [shoalcheck.com](https://shoalcheck.com).

This repository is generated from the Shoalcheck monorepo (`make oss-tree`); changes land there first.
Module path: `github.com/Shoalcheck/shoalcheck-scan`.
