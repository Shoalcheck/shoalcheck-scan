package types

// UsageConfidence is the methodology grade of a usage source — NOT a finding
// confidence. metrics.k8s.io is an instantaneous snapshot and can never be
// "high"; only a windowed PromQL source can. The zero value "" is Valid so an
// omitempty-absent field never fails Validate.
type UsageConfidence string

const (
	UsageConfidenceHigh UsageConfidence = "high" // windowed p95/max (Tier 1)
	UsageConfidenceLow  UsageConfidence = "low"  // VPA candidate / instantaneous snapshot (Tier 2/3)
	UsageConfidenceNone UsageConfidence = "none" // Tier 4: no source
)

// Valid reports whether c is a recognized usage confidence. "" is Valid.
func (c UsageConfidence) Valid() bool {
	switch c {
	case "", UsageConfidenceHigh, UsageConfidenceLow, UsageConfidenceNone:
		return true
	}
	return false
}

// UsageMethodology is stamped into the report so the reader knows where every
// usage number came from and what it can/can't support. Defined here (not in
// prom) so there is exactly ONE struct; prom aliases it. All fields omitempty.
type UsageMethodology struct {
	Source     string          `json:"source"`            // "prometheus" | "vpa" | "metrics.k8s.io" | "none"
	Backend    string          `json:"backend,omitempty"` // resolved flavour: "thanos" | "mimir" | "amp" | "gmp" | "victoria-metrics" | "prometheus" | ""
	Confidence UsageConfidence `json:"confidence,omitempty"`
	Window     string          `json:"window,omitempty"`  // "7d" for Tier 1; "instant" for Tier 3; "" for none
	Caveats    []string        `json:"caveats,omitempty"` // e.g. "GMP curated subset — container/KSM series absent"
}

// Basis is where the usage came from, in words a basis line prints: "prometheus over 7d", "metrics.k8s.io at one
// moment" — an "instant" window is one moment, not a span anything is over. Empty when no usage was read.
func (u *UsageMethodology) Basis() string {
	if u == nil || u.Source == "" || u.Source == "none" {
		return ""
	}
	switch u.Window {
	case "instant":
		return u.Source + " at one moment"
	case "":
		return u.Source + " over an unstated window"
	}
	return u.Source + " over " + u.Window
}
