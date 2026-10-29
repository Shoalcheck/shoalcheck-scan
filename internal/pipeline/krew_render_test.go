package pipeline

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// THE RENDERER MUST BE ABLE TO RENDER ITS OWN TEMPLATE. scripts/krew-manifest.sh refuses any output still
// holding a template expression, and the template's header comment explained that rule by quoting one — so
// the renderer refused every manifest it was ever given, on its own documentation. Nothing ran it before a
// release; this runs it on a checksums file covering every platform the manifest declares.
func TestKrew_TheRendererRendersTheManifest(t *testing.T) {
	man, err := os.ReadFile("../../deploy/krew/shoalcheck.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var sums strings.Builder
	for _, m := range regexp.MustCompile(`\{\{ \.Sha256_([a-z0-9]+)_([a-z0-9]+) \}\}`).FindAllStringSubmatch(string(man), -1) {
		ext := "tar.gz"
		if m[1] == "windows" {
			ext = "zip"
		}
		fmt.Fprintf(&sums, "%064x  kubectl-shoalcheck_0.1.0_%s_%s.%s\n", len(m[1])+len(m[2]), m[1], m[2], ext)
	}
	path := filepath.Join(t.TempDir(), "checksums.txt")
	if err := os.WriteFile(path, []byte(sums.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "scripts/krew-manifest.sh", "v0.1.0", path)
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the renderer refused its own manifest: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "{{") {
		t.Errorf("the rendered manifest still holds a template expression:\n%s", out)
	}
	if !strings.Contains(string(out), "kubectl-shoalcheck_0.1.0_windows_amd64.zip") {
		t.Errorf("the rendered manifest offers no Windows archive:\n%s", out)
	}
}
