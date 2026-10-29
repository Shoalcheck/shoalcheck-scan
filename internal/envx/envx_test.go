package envx

import "testing"

// An operator who set the old name keeps the setting after the rename; the new name wins when both are set.
func TestGet_FallsBackToThePreRenameName(t *testing.T) {
	t.Setenv("SHOALCHECK_X_TEST", "")
	t.Setenv("ASSAY_X_TEST", "old")
	if got := Get("SHOALCHECK_X_TEST"); got != "old" {
		t.Errorf("the pre-rename variable was not read: %q", got)
	}
	t.Setenv("SHOALCHECK_X_TEST", "new")
	if got := Get("SHOALCHECK_X_TEST"); got != "new" {
		t.Errorf("the current name did not win: %q", got)
	}
	if _, ok := Lookup("SHOALCHECK_NEVER_SET_ANYWHERE"); ok {
		t.Error("an unset variable reported as set")
	}
}
