package types

// ComplianceAssessment is the control-by-control view (v1 additive). Unlike
// Compliance (sparse, findings-derived evidence-pointers across CIS/SOC2/PCI),
// this enumerates the scoped CIS-K8s control universe and assigns each control
// PASS|FAIL|MANUAL|NA + a denominator-honest score. SOC2/PCI deliberately stay
// in Compliance only — they cannot be self-scored.
type ComplianceAssessment struct {
	Framework string              `json:"framework"`         // "CIS-K8s"
	Version   string              `json:"version,omitempty"` // "CIS Kubernetes Benchmark v1.9 (Section 5 subset)"
	Controls  []ComplianceControl `json:"controls"`          // sorted by Control
	Score     ComplianceScore     `json:"score"`
}

// ComplianceControl is one enumerated control with its machine verdict.
type ComplianceControl struct {
	Control         string        `json:"control"`                   // "5.1.1" — identity key
	Title           string        `json:"title"`                     // redacted like ComplianceRow.Title
	Status          ControlStatus `json:"status"`                    // PASS|FAIL|MANUAL|NA
	Profile         ProfileLevel  `json:"profile,omitempty"`         // 1|2, optional metadata
	FindingIDs      []string      `json:"findingIds,omitempty"`      // FAIL only, capped via capFindingIDs
	EvidenceRuleIDs []string      `json:"evidenceRuleIds,omitempty"` // PASS+FAIL: what checked it
	Rationale       string        `json:"rationale,omitempty"`       // why MANUAL/NA
}

// ComplianceScore is the denominator-honest rollup: Scored = Pass+Fail only;
// MANUAL/NA are reported but excluded from PassRate so the % can't be inflated.
type ComplianceScore struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
	Manual int `json:"manual"`
	NA     int `json:"na"`
	Scored int `json:"scored"` // Passed + Failed = PassRate denominator
	// Checkable and InScope are BUILD facts, not run facts: how many controls in the universe have an
	// automated check in this build (an evidence rule exists for them), and how many are in scope at all
	// (Total minus the provider-managed NA rows). The report's coverage sentence is derived from them so the
	// number it prints cannot drift from the rule set — it used to be typed by hand and read "about 17 of
	// the ~120" while the code mapped 27. Scored can be lower than Checkable on a run that could not read a
	// kind a check rests on.
	Checkable int                   `json:"checkable"`
	InScope   int                   `json:"inScope"`
	PassRate  float64               `json:"passRate"`         // Passed/Scored, 0 when Scored==0
	Totals    map[ControlStatus]int `json:"totals,omitempty"` // precomputed tally for templates
}
