package types

import (
	"encoding/json"
	"testing"
)

// garbageInputs are hand-crafted malformed reports. Validate (and the
// json.Unmarshal that precedes it in the real load path) must never PANIC —
// returning an error is the only acceptable failure.
var garbageInputs = []string{
	``,
	`{`,
	`null`,
	`[]`,
	`{"schemaVersion":"v1"}`,
	`{"schemaVersion":"v1","findings":null,"summary":null}`,
	`{"schemaVersion":"v9","findings":[]}`,
	`{"schemaVersion":"v1","findings":[{"id":"","severity":"nope"}]}`,
	`{"schemaVersion":"v1","findings":[{"id":"a","confidence":-5}]}`,
	`{"schemaVersion":"v1","findings":[{"id":"a","confidence":1e308}]}`,
	`{"schemaVersion":"v1","summary":{"bySeverity":{"critical":-1}}}`,
	`{"schemaVersion":"v1","summary":{"estimatedSavingsUsd":1e400}}`,
	`{"schemaVersion":"v1","findings":[{"id":"\ud800"}]}`,
	`{"schemaVersion":"v1","findings":[{"id":"a","dollarImpactMonthly":"notanumber"}]}`,
	`{"schemaVersion":"v1","findings":[` + dupIDs(500) + `]}`,
}

func dupIDs(n int) string {
	s := ""
	for i := 0; i < n; i++ {
		if i > 0 {
			s += ","
		}
		s += `{"id":"dup","severity":"high","category":"cost","estimatedEffort":"low"}`
	}
	return s
}

func TestValidate_NeverPanicsOnGarbage(t *testing.T) {
	for i, in := range garbageInputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input #%d panicked: %v\ninput: %s", i, r, in)
				}
			}()
			var ar AuditReport
			if err := json.Unmarshal([]byte(in), &ar); err != nil {
				return // malformed JSON rejected at parse — fine
			}
			_ = ar.Validate() // may return error; must not panic
		}()
	}
}

// FuzzValidate is the bonus continuous fuzzer. Run manually:
//
//	go test ./internal/types/ -run=Fuzz -fuzz=FuzzValidate -fuzztime=30s
//
// Property: parse-then-Validate never panics on any input.
func FuzzValidate(f *testing.F) {
	for _, in := range garbageInputs {
		f.Add([]byte(in))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var ar AuditReport
		if err := json.Unmarshal(data, &ar); err != nil {
			return
		}
		_ = ar.Validate()
	})
}
