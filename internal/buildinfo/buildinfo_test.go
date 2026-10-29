package buildinfo

import (
	"strings"
	"testing"
)

// WHAT A BINARY SAYS IT IS, IN ONE PLACE. `shoalcheck version` and `shoalcheck-mcp --version` print the same lines
// under their own names, so a support conversation asks one question of either.
func TestText_NamesTheProgramTheReleaseTheEngineAndFabricatesNothing(t *testing.T) {
	defer func(v string) { Version = v }(Version)
	for _, c := range []struct{ stamped, want string }{{"", "dev"}, {"0.1.0-rc.12", "0.1.0-rc.12"}} {
		Version = c.stamped
		got := Text("shoalcheck-mcp")
		if first := strings.SplitN(got, "\n", 2)[0]; first != "shoalcheck-mcp "+c.want {
			t.Errorf("Version %q: the first line is %q, want %q", c.stamped, first, "shoalcheck-mcp "+c.want)
		}
		if Release() != c.want {
			t.Errorf("Version %q: Release() is %q, want %q", c.stamped, Release(), c.want)
		}
		for _, want := range []string{"engine   " + EngineVersion, "commit   ", "built    ", "runtime  "} {
			if !strings.Contains(got, want) {
				t.Errorf("no %q line:\n%s", want, got)
			}
		}
		if strings.Contains(got, "0001-01-01") || strings.Contains(got, "1970-01-01") {
			t.Errorf("a zero timestamp is printed as a build date:\n%s", got)
		}
	}
}

// The lines after the first are the same whatever the program, so two binaries of one release agree.
func TestText_TwoProgramsDifferOnlyInTheirName(t *testing.T) {
	a, b := strings.SplitN(Text("shoalcheck"), "\n", 2), strings.SplitN(Text("shoalcheck-mcp"), "\n", 2)
	if len(a) != 2 || len(b) != 2 || a[1] != b[1] {
		t.Errorf("two programs of one build print different details:\n%s\n---\n%s", Text("shoalcheck"), Text("shoalcheck-mcp"))
	}
}
