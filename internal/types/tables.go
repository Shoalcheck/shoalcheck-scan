package types

// The diagram tables (ENG-35, ENG-36, ENG-38; decision D2). Each is the data one picture needs, so a surface draws
// from a field instead of parsing sentences: where a workload's replicas sit, what images run, which nodes a drain
// stops at, who holds which permission, how full each pool is. Each carries the rows it kept, how many there were,
// and whether it was cut at its cap; a cut table says so, and is never read as the whole.

// PlacementTable is where each workload's pods run: per zone and per node (ENG-35, the zone × workload matrix).
type PlacementTable struct {
	Rows      []PlacementRow `json:"rows"`
	Total     int            `json:"total"`
	Truncated bool           `json:"truncated,omitempty"`
}

// PlacementRow is one workload.
type PlacementRow struct {
	Kind      string      `json:"kind"`
	Namespace string      `json:"namespace"`
	Name      string      `json:"name"`
	Replicas  int         `json:"replicas"`
	Zones     []ZoneCount `json:"zones"`
	Nodes     int         `json:"nodes"`
	// Skew is the most pods in one zone minus the fewest, over the zones the cluster's nodes are in: a zone with
	// none of them counts as zero.
	Skew int `json:"skew"`
}

// ZoneCount is a zone and how many of a workload's pods run there.
type ZoneCount struct {
	Zone string `json:"zone"`
	Pods int    `json:"pods"`
}

// ImageTable is every image the reading's pods run (ENG-36).
type ImageTable struct {
	Rows      []ImageRow `json:"rows"`
	Total     int        `json:"total"`
	Truncated bool       `json:"truncated,omitempty"`
}

// ImageRow is one image reference as the pod specs write it.
type ImageRow struct {
	Registry   string `json:"registry"`
	Repository string `json:"repository"`
	// Ref is the tag or the digest; "" when the reference names neither, which means "latest".
	Ref       string `json:"ref"`
	Digest    bool   `json:"digest,omitempty"`
	Pods      int    `json:"pods"`
	Workloads int    `json:"workloads"`
}

// NodeVerdictTable is each node's drain verdict with what blocks it (ENG-38, the drain map).
type NodeVerdictTable struct {
	Rows      []NodeVerdictRow `json:"rows"`
	Total     int              `json:"total"`
	Truncated bool             `json:"truncated,omitempty"`
}

// NodeVerdictRow is one node. Verdict is "blocked" (a finding says a drain stops here), "serialized" (a budget
// forces rounds) or "no blocker found" — never "drains", which this model cannot establish.
type NodeVerdictRow struct {
	Node     string   `json:"node"`
	Zone     string   `json:"zone,omitempty"`
	Pool     string   `json:"pool,omitempty"`
	Verdict  string   `json:"verdict"`
	Findings []string `json:"findings,omitempty"`
}

// RBACGraph is who holds which permission: subject → binding → role, with the verbs the role allows (ENG-38).
type RBACGraph struct {
	Edges     []RBACEdge `json:"edges"`
	Total     int        `json:"total"`
	Truncated bool       `json:"truncated,omitempty"`
}

// RBACEdge is one subject bound to one role by one binding.
type RBACEdge struct {
	SubjectKind      string   `json:"subjectKind"`
	SubjectNamespace string   `json:"subjectNamespace,omitempty"`
	SubjectName      string   `json:"subjectName"`
	BindingKind      string   `json:"bindingKind"`
	BindingNamespace string   `json:"bindingNamespace,omitempty"`
	BindingName      string   `json:"bindingName"`
	RoleKind         string   `json:"roleKind"`
	RoleName         string   `json:"roleName"`
	Verbs            []string `json:"verbs"`
	// Finding is the dangerous-grant finding about this role, when there is one.
	Finding string `json:"finding,omitempty"`
}

// CapacityTable is each node pool's allocatable, requested and (once usage is read per pool) used capacity (ENG-38,
// ENG-51), with its memory overcommit.
type CapacityTable struct {
	Rows []CapacityRow `json:"rows"`
}

// CapacityRow is one pool: an instance type and a capacity type.
type CapacityRow struct {
	Pool             string  `json:"pool"`
	Nodes            int     `json:"nodes"`
	AllocatableCPU   float64 `json:"allocatableCpu"`   // millicores
	AllocatableMem   float64 `json:"allocatableMem"`   // bytes
	RequestedCPU     float64 `json:"requestedCpu"`     // millicores
	RequestedMem     float64 `json:"requestedMem"`     // bytes
	LimitsMem        float64 `json:"limitsMem"`        // bytes
	MemoryOvercommit float64 `json:"memoryOvercommit"` // limits over allocatable
	// The third layer (ENG-51): what the pool's pods used, from the reading's usage source. Absent when there was
	// none. UsedBasis says what the figure is — a sum of per-container p95s is an upper bound on the pool's own
	// p95, since containers rarely peak together.
	UsedCPU   float64 `json:"usedCpu,omitempty"` // millicores
	UsedMem   float64 `json:"usedMem,omitempty"` // bytes
	UsedBasis string  `json:"usedBasis,omitempty"`
}
