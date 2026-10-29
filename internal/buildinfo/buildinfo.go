// Package buildinfo is what a binary of this product says it is: the release, the ruleset, the commit, the build
// time and the runtime. Every binary links it — the command line, the window, and the MCP server, which links no
// collector — so `shoalcheck version` and `shoalcheck-mcp --version` print the same lines from one function.
//
// TWO NUMBERS, BECAUSE THEY MOVE INDEPENDENTLY. Version is the release, injected by the release build's ldflags
// (-X shoalcheck/internal/buildinfo.Version=<v>) and empty in every local build. EngineVersion is the ruleset a
// reading is produced by, and it is the one that travels on the reading itself — two readings of one cluster taken
// by different engine versions are not comparable, which is why the comparison gates read it. A single "version"
// would have to pick one and would be the wrong one half the time.
//
// The commit and the build time are NOT parameters and are never fabricated: they come from the build info Go
// embeds when it can see the VCS, and when it cannot see it the fields say so rather than printing a zero time.
//
// Standard library only: a binary fenced away from the collector must be able to link it.
package buildinfo

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is the release this binary is part of, set by the release build. "" in a local build.
var Version string

// EngineVersion identifies the finding-producing engine. internal/rules stamps it on every finding and
// internal/history's Gate 0 refuses to compare two readings that do not share it; its history, and the gate that
// makes it move when the finding set can, are beside rules.EngineVersion. It lives here so that a binary that
// cannot link the rules can still say which ruleset its release produces readings with.
const EngineVersion = "0.24.0"

// Release is Version, or "dev" for a build that was not given one.
func Release() string {
	if Version == "" {
		return "dev"
	}
	return Version
}

const notRecorded = "not recorded in this build"

// Stamp is the commit and the build time Go recorded from the VCS. A build from a source tarball, or one made with
// -buildvcs=false, has no stamp at all — and the honest answer there is that it is not recorded, not a zero.
func Stamp() (commit, built string) {
	commit, built = notRecorded, notRecorded
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	dirty := false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if s.Value != "" {
				commit = s.Value
			}
		case "vcs.time":
			if s.Value != "" {
				built = s.Value
			}
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if dirty && commit != notRecorded {
		// A binary built over uncommitted changes is not the commit it names, and somebody reading a support
		// ticket has to know that before they go looking at that commit.
		commit += " (with uncommitted changes)"
	}
	return
}

// Text is what `<program> version` prints.
func Text(program string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", program, Release())
	fmt.Fprintf(&b, "  engine   %s   the ruleset a reading is produced by\n", EngineVersion)
	commit, built := Stamp()
	fmt.Fprintf(&b, "  commit   %s\n", commit)
	fmt.Fprintf(&b, "  built    %s\n", built)
	fmt.Fprintf(&b, "  runtime  %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return b.String()
}
