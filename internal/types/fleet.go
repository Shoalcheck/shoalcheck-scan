package types

import (
	"errors"
	"fmt"
	"time"
)

// FleetReport is a multi-cluster audit: one document holding the full
// single-cluster AuditReport for each audited cluster. The fleet renderer
// aggregates across Clusters (totals, worst offenders) and lets the reader
// switch between per-cluster reports in place.
//
// SchemaVersion "v1" is a forever commitment, like AuditReport. A FleetReport
// composes AuditReports — it adds no per-cluster fields; Cluster.Name is the
// stable key for the switcher.
type FleetReport struct {
	SchemaVersion string         `json:"schemaVersion"`
	GeneratedAt   time.Time      `json:"generatedAt"`
	Clusters      []*AuditReport `json:"clusters"`

	// Skipped names the contexts that were ASKED for and not audited, with a classified reason.
	//
	// It exists because the alternative is a document that silently shows three clusters when five were
	// requested. A cluster that could not be reached is not a cluster with no problems, and the reader of the
	// HTML has no other way to tell the difference — the skip used to be a line on stderr, which nobody keeps.
	Skipped []SkippedCluster `json:"skipped,omitempty"`

	// Divergence is what the audited clusters DECLARE differently — see divergence.go. Nil below two
	// audited clusters, and nil is the honest rendering of "there is nothing to compare": an empty table
	// under a heading would imply agreement that was never measured.
	Divergence *FleetDivergence `json:"divergence,omitempty"`
}

// SkippedCluster is one context the fleet run could not audit.
type SkippedCluster struct {
	// Context is the kube context as asked for. It is a local name the operator chose, not cluster data.
	Context string `json:"context"`
	// Reason is a classified cause — not permitted, not reachable, timed out, nothing could be read — never
	// the API's own error text, which carries the server URL and the authenticated identity.
	Reason string `json:"reason"`
}

// Validate checks the fleet envelope and every child report. A fleet with a
// single invalid cluster is rejected whole — a partial fleet would misreport
// its aggregates.
func (fr *FleetReport) Validate() error {
	var errs []error
	if fr.SchemaVersion != "v1" {
		errs = append(errs, fmt.Errorf("unsupported fleet schemaVersion %q (want \"v1\")", fr.SchemaVersion))
	}
	if len(fr.Clusters) == 0 {
		errs = append(errs, errors.New("fleet has no clusters"))
	}
	seen := map[string]bool{}
	for i, ar := range fr.Clusters {
		if ar == nil {
			errs = append(errs, fmt.Errorf("fleet cluster %d is nil", i))
			continue
		}
		name := ar.Cluster.Name
		if name == "" {
			errs = append(errs, fmt.Errorf("fleet cluster %d has no name", i))
		} else if seen[name] {
			errs = append(errs, fmt.Errorf("duplicate cluster name %q in fleet", name))
		}
		seen[name] = true
		if err := ar.Validate(); err != nil {
			errs = append(errs, fmt.Errorf("cluster %q: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// FleetSummary aggregates the fleet at a glance — computed from the child
// reports at render time (never trusted from input).
type FleetSummary struct {
	ClusterCount        int
	TotalFindings       int
	BySeverity          map[Severity]int
	EstimatedSavingsUSD float64
	EstimatedSpendUSD   float64
}

// DeriveFleetSummary rolls the child reports up into a fleet-level summary.
func DeriveFleetSummary(fr *FleetReport) FleetSummary {
	s := FleetSummary{BySeverity: map[Severity]int{}}
	for _, ar := range fr.Clusters {
		if ar == nil {
			continue
		}
		s.ClusterCount++
		s.TotalFindings += ar.Summary.TotalFindings
		for sev, n := range ar.Summary.BySeverity {
			s.BySeverity[sev] += n
		}
		s.EstimatedSavingsUSD += ar.Summary.EstimatedSavingsUSD
		s.EstimatedSpendUSD += ar.Cluster.EstimatedMonthlySpend
	}
	return s
}
