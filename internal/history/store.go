// Package history persists per-cluster audit snapshots on disk and diffs them,
// so a report can show "since last audit" deltas — the recurring-value loop.
//
// It is OSS-side: it imports only shoalcheck/internal/types (the schema) and the
// standard library, no proprietary packages. A snapshot is the full, already-
// validated AuditReport written as pretty JSON; the diff engine (diff.go)
// matches findings by their stable ID across two snapshots.
//
// Layout on disk (DefaultStore):
//
//	~/.shoalcheck/history/<cluster-slug>/<RFC3339-utc>.json
//
// One directory per cluster (name slugged filesystem-safe), one file per audit
// keyed by its UTC timestamp so lexical filename order equals chronological
// order.
package history

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"github.com/Shoalcheck/shoalcheck-scan/internal/statedir"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Shoalcheck/shoalcheck-scan/internal/signing"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// Store persists per-cluster audit snapshots under a base directory.
type Store struct {
	// Dir is the base directory holding one sub-directory per cluster slug.
	Dir string
	// Key is the install's signing key. When set, Save writes a signature sidecar beside every snapshot and
	// Load refuses a snapshot whose sidecar no longer verifies. nil is an unsigned store: snapshots written
	// before keys existed, and every test that builds Store{Dir: …}, keep working unchanged.
	Key *signing.Key
}

// Snapshot is one persisted audit on disk — its cluster, capture time, and path.
type Snapshot struct {
	Cluster string
	At      time.Time
	Path    string
	// Label is the operator's words for the reading (Methodology.Label), read from the snapshot's head.
	Label string
	// Signed is the signature state against the store's key; "" when the store has no key.
	Signed SignState
	// seq orders readings kept in the same second: 1 for the plain stamp, N for "<stamp>-N".
	seq int
	// ClusterUID is the identity of the cluster this snapshot is OF — RunBasis.ClusterUID, the kube-system
	// namespace UID. Empty when the reading could not read it, which is not the same as a different one.
	//
	// A directory is keyed on slug(Cluster.Name), so two clusters reporting the same display name share
	// one. The listing has always said so (ClusterRef.DistinctUIDs), and the SELECTION did not: List
	// returned every file and Latest took the newest, whichever cluster wrote it. Carrying the identity
	// here costs nothing — readHead already runs once per snapshot for the label — and lets a caller that
	// knows which cluster it is asking about get that cluster.
	ClusterUID string
	// ReadWith names the other clusters read in the same run, when this reading was one member of a fleet: the
	// fleet document is one file, and its members are kept one per cluster, so this is what says they were read
	// together. Nil for a reading of one cluster, and for a member whose note could not be read.
	ReadWith []string
}

// readWithSuffix is the sidecar NoteReadWith writes beside a fleet member's snapshot.
const readWithSuffix = ".with"

// NoteReadWith records that the snapshot at path was read together with the clusters named in others.
//
// A SIDECAR, NOT A FIELD IN THE READING. The reading is the schema, signed as written, and "which other clusters
// were read in the same run" is a fact about the run, not about this cluster: a reading of one cluster is the
// same reading whether or not others were read beside it, and its comparison with the next one does not change.
// So the note sits beside the snapshot, like its signature, and a missing or unreadable note costs the listing a
// sentence and nothing else.
func (s *Store) NoteReadWith(path string, others []string) error {
	if len(others) == 0 {
		return nil
	}
	data, err := json.Marshal(others)
	if err != nil {
		return fmt.Errorf("marshal read-with note: %w", err)
	}
	if err := os.WriteFile(path+readWithSuffix, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write read-with note %s%s: %w", path, readWithSuffix, err)
	}
	return nil
}

// readWith is the note NoteReadWith wrote beside path, or nil.
func readWith(path string) []string {
	data, err := os.ReadFile(path + readWithSuffix)
	if err != nil {
		return nil
	}
	var others []string
	if json.Unmarshal(data, &others) != nil {
		return nil
	}
	return others
}

// snapshotTimeFormat is the per-file timestamp format. It is RFC3339 in UTC with
// colons replaced by dashes so the name is filesystem-safe on every OS while
// staying lexically sortable (newest filename sorts last).
const snapshotTimeFormat = "2006-01-02T15-04-05Z"

// TWO READINGS IN ONE SECOND ARE TWO FILES. The name was the second alone and the write replaced whatever was there,
// so a second reading of one cluster in the same second — two windows, the window and the CLI, a schedule that fired
// twice — overwrote the first without a word. The first reading of a second keeps the plain stamp every earlier
// reading carries; the next takes "<stamp>-2", then "-3", created exclusively so two processes cannot both take one
// name. The suffix orders readings within their second; the stamp still orders everything else.
const maxSameSecond = 999

// parseSnapshotName reads a snapshot's base name: its second, and its place within that second.
func parseSnapshotName(base string) (time.Time, int, bool) {
	stamp, seq := base, 1
	if i := strings.LastIndex(base, "Z-"); i > 0 {
		n, err := strconv.Atoi(base[i+2:])
		if err != nil || n < 2 || n > maxSameSecond {
			return time.Time{}, 0, false
		}
		stamp, seq = base[:i+1], n
	}
	at, err := time.Parse(snapshotTimeFormat, stamp)
	if err != nil {
		return time.Time{}, 0, false
	}
	return at, seq, true
}

// createSnapshotFile creates the first free name for a reading taken at stamp in dir, exclusively.
func createSnapshotFile(dir, stamp string) (*os.File, error) {
	for n := 1; n <= maxSameSecond; n++ {
		name := stamp
		if n > 1 {
			name += "-" + strconv.Itoa(n)
		}
		f, err := os.OpenFile(filepath.Join(dir, name+".json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil || !errors.Is(err, fs.ErrExist) {
			return f, err
		}
	}
	return nil, fmt.Errorf("%d readings are already kept for %s", maxSameSecond, stamp)
}

// DefaultStore returns a Store rooted at ~/.shoalcheck/history. The directory is not
// created until the first Save.
func DefaultStore() (*Store, error) {
	base, err := ShoalcheckHome()
	if err != nil {
		return nil, err
	}
	s := &Store{Dir: filepath.Join(base, "history")}
	// The install's key lives beside the history it signs. A key that cannot be created leaves the store
	// unsigned rather than failing the audit: signing is a property of the file, not a condition of the reading.
	if k, err := signing.LoadOrCreate(filepath.Join(base, "keys")); err == nil {
		s.Key = k
	}
	return s, nil
}

// EnvHome names the directory that holds history/ and keys/ when set; ~/.shoalcheck otherwise. A CI job or a test
// points it somewhere writable and gets exactly the paths the operator's machine would have.
const EnvHome = "SHOALCHECK_HOME"

// ShoalcheckHome is where this install keeps its state.
func ShoalcheckHome() (string, error) {
	return statedir.Home()
}

// slug makes a cluster name safe to use as a single path segment: lowercase,
// with any run of non-alphanumeric characters collapsed to a single dash and
// leading/trailing dashes trimmed. Empty or all-symbol names fall back to
// "cluster" so a directory always exists.
// Slug is the exported form. Both the app's report filenames and the CLI's listing need to address a
// timeline by its directory, and a second implementation of this would be a second answer to "is this the
// same cluster" — the question the whole comparison layer exists to answer once.
func Slug(name string) string { return slug(name) }

func slug(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		return "cluster"
	}
	// A LONG NAME IS CUT, AND KEEPS A DIGEST OF ITSELF. The slug is a directory, and a 283-character kubeconfig
	// context made one no filesystem accepts: the save failed, the reading was not kept, and the comparison blamed
	// "an earlier snapshot". Cut at maxSlug with a digest of the whole name, two long names that share a beginning
	// stay two directories; a name that fits is untouched, so every existing directory keeps its name.
	if len(s) > maxSlug {
		sum := sha256.Sum256([]byte(name))
		s = strings.TrimRight(s[:maxSlug-13], "-") + "-" + hex.EncodeToString(sum[:])[:12]
	}
	return s
}

// maxSlug is the longest a history directory name gets: well under the 255 bytes a file name may take, with room
// for the document names built from it.
const maxSlug = 120

// Save writes ar as pretty JSON under <Dir>/<cluster-slug>/<at-utc>.json and
// returns the written path. The cluster slug comes from ar.Cluster.Name; at is
// normalized to UTC for the filename. Parent directories are created as needed.
func (s *Store) Save(ar *types.AuditReport, at time.Time) (string, error) {
	if ar == nil {
		return "", fmt.Errorf("save: nil report")
	}
	// Snapshots hold cluster internals (node/namespace/RBAC names) — keep the
	// store user-only, like ~/.kube and ~/.aws. 0o700 dirs, 0o600 files; and
	// tighten s.Dir even if it pre-exists with a looser mode (MkdirAll won't).
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return "", fmt.Errorf("create history root %s: %w", s.Dir, err)
	}
	_ = os.Chmod(s.Dir, 0o700) // best-effort: tighten an upgraded 0o755 root
	dir := filepath.Join(s.Dir, slug(ar.Cluster.Name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create history dir %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(ar, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal snapshot: %w", err)
	}
	f, err := createSnapshotFile(dir, at.UTC().Format(snapshotTimeFormat))
	if err != nil {
		return "", fmt.Errorf("create snapshot in %s: %w", dir, err)
	}
	path := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return "", fmt.Errorf("write snapshot %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("write snapshot %s: %w", path, err)
	}
	if s.Key != nil {
		// The sidecar: the signature over the file's exact bytes, then the signer's fingerprint. A sidecar rather
		// than a field inside the JSON, so the schema stays the report and an auditor can check the file with
		// ordinary tooling.
		sidecar := signing.EncodeSignature(s.Key.Sign(data)) + "\n" + signing.Fingerprint(s.Key.Public()) + "\n"
		if err := os.WriteFile(path+".sig", []byte(sidecar), 0o600); err != nil {
			return "", fmt.Errorf("write signature %s.sig: %w", path, err)
		}
	}
	return path, nil
}

// SignState is what a signature check says about one snapshot. "Verified" alone is not a state, because a file can
// be unsigned without being wrong.
//
// FOUR STATES, BECAUSE "ANOTHER KEY SIGNED IT" IS NOT "IT WAS EDITED". Tampered used to cover both, and the second
// is ordinary: a history directory copied to a new machine, an install whose keys/ was removed, and — every run —
// the CI job `schedule render --ci` prints, which restores history from its cache and creates a fresh install key.
// Each genuine snapshot was then branded TAMPERED, LatestOf refused it, and `--save-history` stopped saving at all.
// The sidecar names the key that signed it, so the two are told apart. A signature by another key is a fact this
// install cannot check, and it is treated exactly as an unsigned file is — no more trusted and no less: a forger who
// re-signs with a key of their own gains nothing over one who deletes the sidecar, which was always possible.
type SignState string

const (
	Signed   SignState = "signed"    // sidecar present and valid for the key
	Unsigned SignState = "unsigned"  // no sidecar: written before keys existed, or by an install without one
	OtherKey SignState = "other-key" // sidecar names a key this install does not hold: not verifiable here
	Tampered SignState = "tampered"  // this install's own signature, over bytes that have changed since — or a sidecar that names no key
)

// Verify checks path's sidecar against pub.
func Verify(path string, pub ed25519.PublicKey) (SignState, error) {
	sig, err := os.ReadFile(path + ".sig")
	if err != nil {
		if os.IsNotExist(err) {
			return Unsigned, nil
		}
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, rest, _ := strings.Cut(string(sig), "\n")
	raw, err := signing.DecodeSignature(line)
	if err == nil && signing.Verify(pub, data, raw) {
		return Signed, nil
	}
	// The second line is the signer's fingerprint (see Save). One that names a different key is a reading this
	// install cannot verify, not a reading that changed. A sidecar that names no key, or names ours, is tampering.
	if signer := strings.TrimSpace(strings.SplitN(rest, "\n", 2)[0]); signer != "" && signer != signing.Fingerprint(pub) {
		return OtherKey, nil
	}
	return Tampered, nil
}

// stateOf is Verify against the store's own key; "" when the store has none.
func (s *Store) stateOf(path string) SignState {
	if s.Key == nil {
		return ""
	}
	st, err := Verify(path, s.Key.Public())
	if err != nil {
		return ""
	}
	return st
}

// load reads a snapshot after refusing a tampered one, and does NOT re-Validate — see loadSnapshot for why
// that is written as a difference rather than as trust, and which callers may rely on which.
//
// An unsigned snapshot is read: history written before keys existed is not made worthless by their arrival.
// That is also the boundary of what a signature can do here — removing the `.sig` sidecar makes a file
// unsigned rather than tampered, so the signature is evidence about a file that HAS one, never a gate on
// every file in the store.
func (s *Store) load(path string) (*types.AuditReport, error) {
	if s.stateOf(path) == Tampered {
		return nil, &TamperedError{Path: path}
	}
	return loadSnapshot(path)
}

// TamperedError is the refusal of a snapshot this install signed and whose bytes have changed since. A type, so
// a caller holding a reading of its own can refuse the comparison and still keep that reading — `--save-history`
// used to stop at this error and save nothing.
type TamperedError struct{ Path string }

func (e *TamperedError) Error() string {
	return fmt.Sprintf("snapshot %s does not verify against this install's key — it changed after this install signed it; it is listed and never compared or rendered", e.Path)
}

// List returns every snapshot for cluster, sorted newest-first. A cluster with
// no history yet (missing directory) returns an empty slice and no error —
// "no snapshots" is a normal state, not a failure.
func (s *Store) List(cluster string) ([]Snapshot, error) {
	dir := filepath.Join(s.Dir, slug(cluster))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read history dir %s: %w", dir, err)
	}
	var snaps []Snapshot
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		base := strings.TrimSuffix(e.Name(), ".json")
		at, seq, ok := parseSnapshotName(base)
		if !ok {
			// Ignore files that don't match the snapshot naming convention
			// rather than failing the whole listing.
			continue
		}
		snap := Snapshot{Cluster: cluster, At: at, Path: filepath.Join(dir, e.Name()), seq: seq}
		// The label is the one head field a listing shows; readHead parses only the head fields, so this is a
		// small read per snapshot, not a full decode.
		if h, err := readHead(snap.Path); err == nil {
			snap.Label = h.Methodology.Label
			if h.Methodology.RunBasis != nil {
				snap.ClusterUID = h.Methodology.RunBasis.ClusterUID
			}
		}
		snap.Signed = s.stateOf(snap.Path)
		snap.ReadWith = readWith(snap.Path)
		snaps = append(snaps, snap)
	}
	sort.Slice(snaps, func(i, j int) bool {
		if !snaps[i].At.Equal(snaps[j].At) {
			return snaps[i].At.After(snaps[j].At)
		}
		return snaps[i].seq > snaps[j].seq
	})
	return snaps, nil
}

// LatestOf returns the newest reading of ONE CLUSTER strictly before `before`.
//
// WHY IT EXISTS. A history directory is keyed on the cluster's display NAME, so two clusters that report
// the same name — "production" in two organisations, "kind" on two machines whose dotfiles sync — write
// into one directory. Taking the newest file there returns whichever cluster wrote it. Downstream that
// reading is handed to the comparison gates, which refuse on a ClusterUID mismatch, so no wrong diff is
// produced — what is produced is a refusal whose reason is somebody else's cluster, and a caller that does
// not run the gates gets a stranger's reading outright.
//
// AN UNKNOWN IDENTITY IS NOT A DIFFERENT ONE. uid == "" means the caller has nothing to match on — a
// reading whose kube-system UID could not be read — so this takes the newest reading in the
// directory rather than
// answering "no prior", which would turn an absence into a fact. There is no Latest beside this: a
// caller with no identity passes "" and that choice is visible where it is made. Snapshots whose own UID is empty are
// eligible for the same reason: they cannot be shown to be a different cluster.
func (s *Store) LatestOf(cluster, uid string, before time.Time) (*types.AuditReport, time.Time, bool, error) {
	snaps, err := s.List(cluster)
	if err != nil {
		return nil, time.Time{}, false, err
	}
	for _, snap := range snaps { // newest-first
		if !snap.At.Before(before) {
			continue
		}
		if uid != "" && snap.ClusterUID != "" && snap.ClusterUID != uid {
			continue
		}
		ar, err := s.load(snap.Path)
		if err != nil {
			// The prior's time travels with the refusal, so a caller can say WHICH reading it did not compare.
			return nil, snap.At, false, err
		}
		return ar, snap.At, true, nil
	}
	return nil, time.Time{}, false, nil
}

// loadSnapshot reads and unmarshals a snapshot file into an AuditReport, and DOES NOT VALIDATE IT.
//
// THE SENTENCE THAT USED TO BE HERE WAS "a stored snapshot is trusted on read", and it licensed a copy of
// this function in cmd/shoalcheck whose own comment repeated it — which `shoalcheck history diff` then used to compare
// a snapshot that had been edited after it was signed, reporting the forgery as a 191-finding improvement at
// exit 0 (M-85). A file on the operator's disk outlives the reasoning that it was validated once when it was
// written.
//
// So the contract is stated as a difference rather than as trust:
//
//   - Store.Load    refuses a TAMPERED snapshot and re-runs types.Validate. Anything that RENDERS a reading
//     uses this, because Validate is what guarantees the headline equals the sum beneath it.
//   - Store.load    refuses a tampered snapshot and stops there. LatestOf uses it, and the surfaces that
//     reach a reading through LatestOf — `shoalcheck findings`, `explain`, `browse` — print only
//     ar.Findings and never Summary, so an inconsistent summary emits no figure there.
//
// Both halves are asserted in TestLoaderContracts, so the difference stays a decision on the record. A
// caller that will print a summary must use Store.Load.
func loadSnapshot(path string) (*types.AuditReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot %s: %w", path, err)
	}
	var ar types.AuditReport
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, fmt.Errorf("parse snapshot %s: %w", path, err)
	}
	// A saved reading is cluster data on disk, and the terminal surfaces (`diff`, `browse`, the app's open)
	// print it. Strip the control bytes a terminal acts on from the in-memory reading. This runs AFTER the
	// caller has checked the file's signature (load() refuses a tampered snapshot before reaching here), so the
	// bytes the signature covers are never altered — only the value this process goes on to render is.
	types.SanitizeControls(&ar)
	return &ar, nil
}
