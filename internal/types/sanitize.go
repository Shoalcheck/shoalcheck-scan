package types

import (
	"reflect"
	"strings"
)

// sanitize.go — strip the control bytes a terminal acts on from a reading's text.
//
// A reading carries strings an attacker wrote into the audited cluster: a controller's condition message, an
// image reference, a label value, a resource name. The HTML report and the app escape them; the terminal
// surfaces — `shoalcheck findings`, `explain`, the table — print a finding's title and evidence straight to a
// terminal that INTERPRETS control bytes. A condition message of
//
//	PWN\x1b[2J\x1b[32mNO ISSUES FOUND\x1b]0;hijacked\x07
//
// could clear the screen, paint a fake clean verdict in green, hide the attacker's own finding behind cursor
// moves, or rewrite the terminal's title — spoofing the one tool whose promise is that its reading can be
// trusted. SanitizeControls removes those bytes from every string in a reading, once, before anything renders
// it: at the end of pipeline.Run before Validate, when the CLI parses a reading from a file, and when the
// history store decodes a saved one (after its signature has been checked, in memory — the file on disk is
// never rewritten).
//
// It is a REFLECTIVE walk over every exported string the schema reaches, rather than a list of fields, because
// the schema grows and a hand-written list is a field forgotten in six months. The JSON that leaves the
// product is written from the same sanitised value, so no sink is handled differently: the reading itself is
// clean, not each renderer's copy of it.

// SanitizeControls strips terminal control bytes from every string in ar, in place.
func SanitizeControls(ar *AuditReport) {
	if ar == nil {
		return
	}
	sanitizeValue(reflect.ValueOf(ar))
}

func sanitizeValue(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		if v.CanSet() {
			if s := scrubControls(v.String()); s != v.String() {
				v.SetString(s)
			}
		}
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			sanitizeValue(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			// Unexported fields are skipped: a reading's exported schema is the whole of what a renderer
			// prints, and reflect cannot set an unexported field anyway.
			if v.Type().Field(i).IsExported() {
				sanitizeValue(v.Field(i))
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			sanitizeValue(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		// A map's values are not addressable, so each is recursed through an addressable copy and set back; a
		// string KEY (a section name, a dataset name — some are the operator's own words) is sanitised too,
		// which means deleting the old entry when the key changed. The two maps that matter here are
		// map[string]string (section ledes) and map[string]DataVersion (dataset provenance).
		for _, k := range v.MapKeys() {
			nv := reflect.New(v.Type().Elem()).Elem()
			nv.Set(v.MapIndex(k))
			sanitizeValue(nv)
			nk := k
			if k.Kind() == reflect.String {
				if sk := scrubControls(k.String()); sk != k.String() {
					nk = reflect.New(k.Type()).Elem()
					nk.SetString(sk)
					v.SetMapIndex(k, reflect.Value{}) // remove the entry under the old key
				}
			}
			v.SetMapIndex(nk, nv)
		}
	}
}

// SanitizeString is scrubControls for one string a caller holds outside an AuditReport — the head fields the
// history listing reads (a cluster name, a reading's label) without decoding the whole snapshot.
func SanitizeString(s string) string { return scrubControls(s) }

// SanitizeLine is SanitizeString for a value printed INSIDE one line — of a CI job's log, of a one-line verdict.
// A newline is layout in a report and an injection in a log: a line that starts with `::error::` or
// `::add-mask::` is a GitHub workflow command, and a pull request's author chooses the names `gate --with` prints.
// Every line break — a newline, and the Unicode line and paragraph separators — becomes a visible `\n`, and a tab
// a space, so the value stays on the line it was printed on and a reader can still see something was there.
func SanitizeLine(s string) string {
	s = scrubControls(s)
	if !strings.ContainsAny(s, "\n\t\u2028\u2029") {
		return s
	}
	return strings.NewReplacer("\n", `\n`, "\u2028", `\n`, "\u2029", `\n`, "\t", " ").Replace(s)
}

// SanitizeAny scrubs every exported string reachable from p, a pointer, in place — for values that are not a
// reading but reach a terminal all the same: the pipeline's progress events, which the live workbench draws as
// they arrive, before the reading they come from is scrubbed.
func SanitizeAny(p any) {
	if p == nil {
		return
	}
	sanitizeValue(reflect.ValueOf(p))
}

// scrubControls drops the bytes a terminal interprets, keeping the whitespace a reader needs. A CRLF pair is a
// line break and becomes "\n"; a LONE carriage return moves the cursor to the start of the line, so text after it
// overwrites what came before ("OK\rCRITICAL"), and it is dropped like any other control.
func scrubControls(s string) string {
	if strings.Contains(s, "\r\n") {
		s = strings.ReplaceAll(s, "\r\n", "\n")
	}
	if !strings.ContainsFunc(s, isControl) {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isControl(r) {
			return -1
		}
		return r
	}, s)
}

// isControl reports whether r is a byte a terminal acts on rather than a glyph a reader sees: the C0 controls
// and DEL, the C1 controls, and the Unicode bidirectional overrides and isolates, which can reorder the visible
// text so a benign-looking line reads as something else. Tab and newline are kept — they are layout a report
// legitimately uses; a carriage return is folded or dropped by scrubControls before this is asked.
func isControl(r rune) bool {
	switch {
	case r == '\t' || r == '\n':
		return false
	case r < 0x20 || r == 0x7f: // C0 controls and DEL
		return true
	case r >= 0x80 && r <= 0x9f: // C1 controls
		return true
	case r >= 0x202a && r <= 0x202e: // bidi embeddings and overrides: LRE RLE PDF LRO RLO
		return true
	case r >= 0x2066 && r <= 0x2069: // bidi isolates: LRI RLI FSI PDI
		return true
	}
	return false
}
