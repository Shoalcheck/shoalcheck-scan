package collect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capture_format_test.go — a capture says which format it is, so a later build can refuse one it cannot read.
//
// A capture is read back by `shoalcheck gate --capture` in a pipeline that holds no kubeconfig, possibly by a newer
// build than the one that wrote it. An inventory whose shape moved underneath it would decode with fields silently
// zero — a kind that reads as empty rather than unread — and the gate would judge a change against a cluster that
// never existed. So the file carries its format, and a reader refuses any format it was not written for.

func TestCapture_SaysWhichFormatItIs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	in := sampleCapture()
	if err := SaveCapture(path, in); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		Format     string `json:"format"`
		CapturedAt string `json:"capturedAt"`
		Context    string `json:"context"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		t.Fatal(err)
	}
	if head.Format != CaptureFormat || head.CapturedAt == "" || head.Context != "prod-cluster" {
		t.Errorf("the capture's own header is %+v", head)
	}
}

func TestCapture_RefusesAFormatItDoesNotRead(t *testing.T) {
	dir := t.TempDir()
	future := filepath.Join(dir, "future.json")
	if err := os.WriteFile(future, []byte(`{"format":"shoalcheck-capture/9","inventory":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCapture(future); err == nil || !strings.Contains(err.Error(), "shoalcheck-capture/9") ||
		!strings.Contains(err.Error(), CaptureFormat) {
		t.Errorf("a capture of another format was read: %v", err)
	}
	// A bare inventory — what this package wrote before a capture carried its format — is refused as unversioned.
	bare := filepath.Join(dir, "bare.json")
	b, _ := json.Marshal(sampleCapture())
	if err := os.WriteFile(bare, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCapture(bare); err == nil || !strings.Contains(err.Error(), "does not say") {
		t.Errorf("an unversioned capture was read: %v", err)
	}
}

// Rewritten over an existing file that was world-readable, a capture is still 0600: os.WriteFile keeps an existing
// file's mode, and a capture written over a looser file would inherit the looseness.
func TestCapture_TightensAnExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveCapture(path, sampleCapture()); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("the capture was written %o over a looser file; want 0600", perm)
	}
}
