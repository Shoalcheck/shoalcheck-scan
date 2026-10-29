package types

import (
	"reflect"
	"strings"
	"testing"
)

// A READING CARRIES STRINGS AN ATTACKER WROTE INTO THE CLUSTER. The HTML report escapes them; the terminal
// surfaces — `shoalcheck findings`, `explain`, the table — print a finding's title and evidence to a terminal
// that INTERPRETS control bytes. A condition message of "PWN\x1b[2J\x1b[32mNO ISSUES FOUND\x1b]0;x\x07" could
// clear the screen, paint a fake clean verdict, hide a finding or rewrite the window title. SanitizeControls
// strips the bytes a terminal acts on from every string in a reading, once, before anything renders it.
func TestSanitizeControls_StripsTerminalEscapesEverywhere(t *testing.T) {
	esc := "\x1b[2J\x1b]0;title\x07"
	bidi := "\u202eRTL-override\u202c\u2066isolate\u2069"
	c1 := "C1\u0085next-line"
	del := "del\x7f"
	ar := &AuditReport{
		SchemaVersion: "v1",
		Cluster:       ClusterInfo{Name: "prod" + esc, Region: "eu" + del},
		SectionLedes:  map[string]string{"s" + esc: "lede " + esc},
		Findings: []Finding{{
			ID:          "f-1",
			Title:       "title " + esc + bidi,
			Description: "desc\ttab\nkeep\r\n" + c1,
			Evidence:    []string{"ev " + esc, "ev2 " + del},
			AffectedResources: []ResourceRef{{
				Kind: "Pod", Namespace: "ns" + esc, Name: "name" + esc,
				OwnerChain: []OwnerLink{{Kind: "Deployment", Name: "owner" + esc}},
			}},
		}},
		Methodology: Methodology{
			RunBasis: &RunBasis{
				DataVersions: map[string]DataVersion{"kubeversions": {Source: "src" + esc, Version: "v" + esc}},
			},
		},
	}

	SanitizeControls(ar)

	var offenders []string
	walkStrings(ar, func(s string) {
		for _, r := range s {
			if r == 0x1b || r == 0x07 || r == 0x7f || r == 0x85 ||
				(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) ||
				(r < 0x20 && r != '\t' && r != '\n' && r != '\r') {
				offenders = append(offenders, s)
				return
			}
		}
	})
	if len(offenders) > 0 {
		t.Fatalf("control bytes survived in %d string(s): %q", len(offenders), offenders[0])
	}

	// What a reader should keep is kept: the words, the tab and the newlines (a CRLF becomes a newline).
	if !strings.Contains(ar.Findings[0].Description, "desc\ttab\nkeep\n") {
		t.Errorf("tab/newline whitespace was stripped: %q", ar.Findings[0].Description)
	}
	if !strings.HasPrefix(ar.Findings[0].Title, "title ") {
		t.Errorf("visible text was lost: %q", ar.Findings[0].Title)
	}
	// The control bytes are gone; the inert printable remnant ("[2J…") is left as literal text, because a
	// terminal does nothing with it once the ESC that would begin the sequence has been removed. What matters
	// is that the escape can no longer START.
	if n := ar.Findings[0].AffectedResources[0].Name; !strings.HasPrefix(n, "name") || strings.ContainsRune(n, 0x1b) {
		t.Errorf("a resource name kept an escape: %q", n)
	}
	if n := ar.Findings[0].AffectedResources[0].OwnerChain[0].Name; !strings.HasPrefix(n, "owner") || strings.ContainsRune(n, 0x1b) {
		t.Errorf("an owner name kept an escape: %q", n)
	}
	// Map values and keys are reached too.
	for k, v := range ar.SectionLedes {
		if strings.ContainsRune(k, 0x1b) || strings.ContainsRune(v, 0x1b) {
			t.Errorf("a map key/value kept an escape: %q=%q", k, v)
		}
	}
	for _, dv := range ar.Methodology.RunBasis.DataVersions {
		if strings.ContainsRune(dv.Source, 0x1b) {
			t.Errorf("a struct inside a map kept an escape: %q", dv.Source)
		}
	}
}

// walkStrings visits every string the exported schema reaches, so the test's denominator is the whole reading
// and not the handful of fields it happens to name. It is its own small reflective walk, written independently
// of SanitizeControls so the assertion does not reuse the code it checks.
func walkStrings(ar *AuditReport, visit func(string)) {
	var walk func(reflect.Value)
	walk = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			visit(v.String())
		case reflect.Pointer, reflect.Interface:
			if !v.IsNil() {
				walk(v.Elem())
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					walk(v.Field(i))
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < v.Len(); i++ {
				walk(v.Index(i))
			}
		case reflect.Map:
			for _, k := range v.MapKeys() {
				walk(k)
				walk(v.MapIndex(k))
			}
		}
	}
	walk(reflect.ValueOf(ar))
}

// A LONE CARRIAGE RETURN MOVES THE CURSOR TO THE START OF THE LINE, so text after it overwrites what a reader
// saw before it — "OK\rCRITICAL" can read as a different verdict. A CRLF pair is a line break, so it becomes one.
func TestSanitizeString_FoldsCRLFAndDropsALoneCR(t *testing.T) {
	for in, want := range map[string]string{
		"a\r\nb":           "a\nb",
		"critical\rOK    ": "criticalOK    ",
		"tab\tand\nnl":     "tab\tand\nnl",
	} {
		if got := SanitizeString(in); got != want {
			t.Errorf("SanitizeString(%q) = %q, want %q", in, got, want)
		}
	}
}

// A LINE OF A JOB LOG IS NOT A REPORT. SanitizeString keeps the newlines a multi-line text needs; a value printed
// inside one line of CI output must not carry one, because a line that starts with `::error::` or `::add-mask::`
// is a GitHub workflow command. SanitizeLine is SanitizeString with every line break made visible.
func TestSanitizeLine_KeepsAValueOnOneLine(t *testing.T) {
	for in, want := range map[string]string{
		"deployer":                 "deployer",
		"system:aggregate-to-view": "system:aggregate-to-view",
		"x\n::error::pwned":        `x\n::error::pwned`,
		"x\r\n::add-mask::y":       `x\n::add-mask::y`,
		"red\x1b[31m":              "red[31m",
		"a\tb":                     "a b",
		"line sep end":             `line\nsep\nend`,
	} {
		if got := SanitizeLine(in); got != want {
			t.Errorf("SanitizeLine(%q) = %q, want %q", in, got, want)
		}
	}
}
