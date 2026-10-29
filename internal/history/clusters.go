package history

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// clusters.go — enumerating what is on disk, and loading one reading off it.
//
// Both functions exist because three callers were each doing a piece of this by hand, and one of them was
// getting it wrong: `cmd/shoalcheck/history.go` listed clusters by reading the store's directory names and passing
// each back into List(), so the name a reader saw was the SLUG — `acme-pay-eks-prod` instead of
// `Acme Pay / EKS:prod`. A slug is lossy by design, because it has to be a filename; a name cannot be
// recovered from it and has to be read out of the snapshot.

// ClusterRef is one cluster's timeline as the browser needs to list it, before anything is opened.
//
// IT CARRIES ITS OWN COMPARABILITY. Gate 0 refuses to compare two readings with no ClusterUID
// (diff.go:242), and an operator who picks two runs and only then learns they cannot be compared has been
// made to do work for nothing. So the refusal is on the row, with its reason, before the choice.
type ClusterRef struct {
	// Name is the display name out of the newest snapshot — never the directory slug.
	Name string

	// ClusterUID is the kube-system namespace UID: the only stable cluster identity a read-only snapshot
	// has. A slug collides and a kubeconfig context can be renamed or reused for a rebuilt cluster, so
	// grouping timelines by anything else eventually compares two clusters and calls it a change.
	ClusterUID string

	// Slug is the directory, kept so a caller can address the timeline without re-deriving it.
	Slug string

	Runs           int
	Newest, Oldest time.Time

	// LatestFindings is the newest reading's headline count, read from its Summary rather than by counting
	// findings — a listing must not parse megabytes to render a row.
	LatestFindings int

	// DistinctUIDs is how many different ClusterUIDs this one directory holds.
	//
	// IT IS NORMALLY 1 AND SOMETIMES NOT, and that is why it exists. A slug is lossy by construction, so
	// two genuinely different clusters can share a directory — `Acme Pay / EKS:prod` and
	// `acme-pay-eks-prod` slug identically, and so does a kubeconfig context reused for a rebuilt cluster.
	// Reading the UID off the newest snapshot alone would report them as one cluster with N runs, which is
	// a false statement about the timeline even though Gate 0 would refuse to compare across them. Without
	// this number the row cannot explain its own refusal.
	DistinctUIDs int

	// Comparable is false when this timeline cannot be compared at all, with the reason named.
	Comparable          bool
	NotComparableReason string
}

// snapshotHead is the narrow shape a listing needs. encoding/json ignores everything else for free, so a
// directory of 5 MB snapshots lists without parsing a single finding.
type snapshotHead struct {
	Cluster struct {
		Name string `json:"name"`
	} `json:"cluster"`
	Summary struct {
		TotalFindings int `json:"totalFindings"`
	} `json:"summary"`
	Methodology struct {
		Label    string `json:"label"`
		RunBasis *struct {
			ClusterUID    string `json:"clusterUid"`
			EngineVersion string `json:"engineVersion"`
		} `json:"runBasis"`
	} `json:"methodology"`
}

// Clusters enumerates every timeline in the store, newest-first by their newest reading.
func (s *Store) Clusters() ([]ClusterRef, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // an absent store is "no history", not a failure
		}
		return nil, fmt.Errorf("read history dir %s: %w", s.Dir, err)
	}

	var out []ClusterRef
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// The directory name IS the slug, and slug() is idempotent, so passing it back recovers this
		// timeline's snapshots without pretending the slug is a name.
		snaps, err := s.List(e.Name())
		if err != nil {
			return nil, err
		}
		if len(snaps) == 0 {
			continue
		}
		head, err := readHead(snaps[0].Path) // List is newest-first
		if err != nil {
			return nil, err
		}
		ref := ClusterRef{
			Name:           head.Cluster.Name,
			Slug:           e.Name(),
			Runs:           len(snaps),
			Newest:         snaps[0].At,
			Oldest:         snaps[len(snaps)-1].At,
			LatestFindings: head.Summary.TotalFindings,
		}
		if head.Methodology.RunBasis != nil {
			ref.ClusterUID = head.Methodology.RunBasis.ClusterUID
		}
		// EVERY snapshot's UID, not just the newest. See ClusterRef.DistinctUIDs: the alternative reports
		// two clusters as one timeline, and the listing is the one place an operator decides what to
		// compare with what.
		uids := map[string]bool{}
		for _, snap := range snaps {
			h, err := readHead(snap.Path)
			if err != nil {
				return nil, err
			}
			if h.Methodology.RunBasis != nil && h.Methodology.RunBasis.ClusterUID != "" {
				uids[h.Methodology.RunBasis.ClusterUID] = true
			}
		}
		ref.DistinctUIDs = len(uids)
		if ref.Name == "" {
			ref.Name = e.Name() // nothing better exists; the row says so below
		}
		switch {
		case ref.DistinctUIDs > 1:
			ref.NotComparableReason = fmt.Sprintf("this directory holds readings of %d different clusters "+
				"(their cluster UIDs differ), so its runs are not one timeline", ref.DistinctUIDs)
		case ref.ClusterUID == "":
			ref.NotComparableReason = "this reading does not record a cluster UID, so two of its runs " +
				"cannot be confirmed to come from the same cluster"
		case ref.Runs < 2:
			ref.NotComparableReason = "only one reading has been taken of this cluster, so there is " +
				"nothing to compare it with"
		default:
			ref.Comparable = true
		}
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Newest.After(out[j].Newest) })
	return out, nil
}

func readHead(path string) (snapshotHead, error) {
	var h snapshotHead
	data, err := os.ReadFile(path)
	if err != nil {
		return h, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &h); err != nil {
		return h, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	// The two head fields a listing prints to the terminal — the cluster name and the reading's label — are
	// cluster and operator text, so they get the same control-byte strip loadSnapshot gives the whole reading.
	h.Cluster.Name = types.SanitizeString(h.Cluster.Name)
	h.Methodology.Label = types.SanitizeString(h.Methodology.Label)
	return h, nil
}

// Load reads one snapshot and VALIDATES it.
//
// loadSnapshot does not, and its comment says why: "snapshots are written only from already-validated
// reports, so a stored snapshot is trusted on read." That is true on the day it is written and stops being
// true the moment a snapshot outlives the schema that wrote it — or is edited by hand, which is exactly what
// a customer verifying our re-derivation claim would do.
//
// A snapshot that fails validation is still LISTABLE and still REFUSABLE. What it must never be is rendered:
// types.Validate is what guarantees the headline equals the sum of what is under it, and a document that
// fails it would print a number a reader cannot check.
func (s *Store) Load(path string) (*types.AuditReport, error) {
	ar, err := s.load(path)
	if err != nil {
		return nil, err
	}
	if err := ar.Validate(); err != nil {
		return nil, fmt.Errorf("snapshot %s is internally inconsistent and will not be rendered: %w", path, err)
	}
	return ar, nil
}
