package types

import (
	"fmt"
	"math"
	"sort"
)

// Fact is one value a finding states, typed and keyed, beside the sentence that states it (M-172, ENG-20a).
// docs/engine/facts.md is the design. Evidence stays the printed form; for a rule that has moved to facts its
// sentences are rendered from these, so the two cannot disagree.
type Fact struct {
	// Key is from FactKeys. Never renamed: a key whose meaning changes is a new key.
	Key string `json:"key"`
	// Value is a number (float64), a string or a bool, as the key's definition says.
	Value any `json:"value"`
	// Unit is the key's unit, copied from its definition so a reader of the JSON needs no table: "USD/mo",
	// "millicores", "bytes", "replicas", "pods".
	Unit string `json:"unit,omitempty"`
	// Subject is the object the value is about, when it is not the finding's own subject.
	Subject *ResourceRef `json:"subject,omitempty"`
	// Basis is where the value came from: "prometheus over 7d", "on-demand list price".
	Basis string `json:"basis,omitempty"`
}

// FactType is the JSON type a key's value has.
type FactType string

const (
	FactNumber FactType = "number"
	FactString FactType = "string"
	FactBool   FactType = "bool"
)

// FactClass is what --redact does with a key's value: keep it, tokenize it as an identifier, or withhold it.
type FactClass string

const (
	// FactSafe is a number, a unit, a closed set of words this product chose. Kept.
	FactSafe FactClass = "safe"
	// FactIdentifier is a name of the cluster's: an object, a namespace, a node, a zone label value. Tokenized.
	FactIdentifier FactClass = "identifier"
	// FactText is anything a cluster's users wrote. Withheld.
	FactText FactClass = "text"
)

// FactDef is one registered key.
type FactDef struct {
	Type  FactType
	Unit  string
	Class FactClass
	// Means is one sentence: what the value is, in the words a reader of the JSON needs.
	Means string
	// Deprecated marks a key no build writes any more; readings that carry it still validate.
	Deprecated bool
}

// FactKeys is the registry. A key is added here before any rule writes it, with its type, unit, redaction class and
// meaning, and is never renamed or removed.
var FactKeys = map[string]FactDef{
	// Rightsizing (k8s.cost.overprovisioned-resources).
	"rightsizing.replicas":        {FactNumber, "replicas", FactSafe, "the replica count the dollar is stated over", false},
	"rightsizing.replicas.priced": {FactNumber, "replicas", FactSafe, "the replicas running on a node the price table knows", false},
	"rightsizing.reclaim.cpu":     {FactNumber, "millicores", FactSafe, "CPU request reclaimed per replica, summed over the flagged containers", false},
	"rightsizing.reclaim.memory":  {FactNumber, "bytes", FactSafe, "memory request reclaimed per replica, summed over the flagged containers", false},
	"rightsizing.usd.cpu":         {FactNumber, "USD/mo", FactSafe, "the CPU reclaim priced on each replica's node, before the larger dimension is taken", false},
	"rightsizing.usd.memory":      {FactNumber, "USD/mo", FactSafe, "the memory reclaim priced on each replica's node, before the larger dimension is taken", false},
	"rightsizing.bound":           {FactString, "", FactSafe, "the dimension the dollar is: CPU or memory", false},
	"rightsizing.banked":          {FactBool, "", FactSafe, "whether the usage proves a window, so the dollar is banked (false: a candidate at $0)", false},
	"rightsizing.withheld":        {FactString, "", FactSafe, "a dimension an autoscaler governs, withheld: CPU or memory", false},
	// Zone loss (k8s.reliability.zone-loss-feasibility).
	"zone.name":          {FactString, "", FactIdentifier, "the zone the scenario removes, as its nodes' zone label names it", false},
	"zone.nodes":         {FactNumber, "nodes", FactSafe, "the nodes in the zone", false},
	"zone.pods.stranded": {FactNumber, "pods", FactSafe, "pods with no remaining node the model accepts, one by one", false},
	"zone.pods.moving":   {FactNumber, "pods", FactSafe, "pods with a candidate node one by one, checked together in the aggregate", false},
	"zone.ask.cpu":       {FactNumber, "millicores", FactSafe, "CPU the moving pods request in total", false},
	"zone.ask.memory":    {FactNumber, "bytes", FactSafe, "memory the moving pods request in total", false},
	"zone.free.cpu":      {FactNumber, "millicores", FactSafe, "CPU free on the surviving nodes that admit any moving pod", false},
	"zone.free.memory":   {FactNumber, "bytes", FactSafe, "memory free on the surviving nodes that admit any moving pod", false},
	"zone.short":         {FactBool, "", FactSafe, "whether the moving pods ask more in total than the admitting survivors hold", false},
	// Node drain budget (k8s.reliability.node-drain-budget).
	"drain.pods.covered":        {FactNumber, "pods", FactSafe, "live pods on the node the budget covers", false},
	"drain.disruptions.allowed": {FactNumber, "disruptions", FactSafe, "the budget's status.disruptionsAllowed at the reading", false},
	"drain.pods.expected":       {FactNumber, "pods", FactSafe, "the budget's status.expectedPods", false},
	"drain.grace.max":           {FactNumber, "seconds", FactSafe, "the longest terminationGracePeriodSeconds among the pods a drain of the node evicts", false},
	"drain.pods.behind.service": {FactNumber, "pods", FactSafe, "pods on the node a Service selects", false},
	"drain.prestop.missing":     {FactNumber, "pods", FactSafe, "of those, pods with no preStop hook on any container", false},
	"drain.rounds":              {FactNumber, "rounds", FactSafe, "budget-limited rounds a drain of the node takes at least", false},
	// Dangerous grant (k8s.rbac.dangerous-grant).
	"rbac.pattern":  {FactString, "", FactSafe, "the dangerous permission the grant matches, by this product's pattern key", false},
	"rbac.bindings": {FactNumber, "bindings", FactSafe, "bindings that name subjects for the role", false},
	"rbac.reach":    {FactString, "", FactSafe, "how far the grant reaches: cluster-wide or within one namespace", false},
	"rbac.names":    {FactNumber, "objects", FactSafe, "object names the matching rules are restricted to; 0 is every object", false},
	// Container OOM kills (k8s.reliability.container-oom-killed); per kill, with the pod as the subject.
	"oom.containers":   {FactNumber, "containers", FactSafe, "containers whose last life ended OOMKilled", false},
	"oom.limit.memory": {FactNumber, "bytes", FactSafe, "the killed container's memory limit; 0 is no limit", false},
	"oom.restarts":     {FactNumber, "restarts", FactSafe, "the killed container's restart total", false},
	"oom.finished":     {FactString, "", FactSafe, "when the OOM-killed life ended, RFC 3339 UTC", false},
	// Node memory overcommit (k8s.reliability.node-memory-overcommit).
	"node.memory.limits":        {FactNumber, "bytes", FactSafe, "the memory limits of the node's running pods, summed", false},
	"node.memory.allocatable":   {FactNumber, "bytes", FactSafe, "the node's allocatable memory", false},
	"node.memory.overcommit":    {FactNumber, "ratio", FactSafe, "memory limits over allocatable", false},
	"node.containers.unlimited": {FactNumber, "containers", FactSafe, "containers on the node with no memory limit", false},
	"node.pods.guaranteed":      {FactNumber, "pods", FactSafe, "running pods of QoS class Guaranteed", false},
	"node.pods.burstable":       {FactNumber, "pods", FactSafe, "running pods of QoS class Burstable", false},
	"node.pods.besteffort":      {FactNumber, "pods", FactSafe, "running pods of QoS class BestEffort", false},
	// Under-provisioned requests (k8s.reliability.under-provisioned-requests), each with its container as subject.
	"underprov.cpu.used":       {FactNumber, "millicores", FactSafe, "a container's CPU usage figure (p95, a sample or a VPA target) above its request", false},
	"underprov.cpu.request":    {FactNumber, "millicores", FactSafe, "that container's CPU request", false},
	"underprov.memory.used":    {FactNumber, "bytes", FactSafe, "a container's memory usage figure above its request", false},
	"underprov.memory.request": {FactNumber, "bytes", FactSafe, "that container's memory request", false},
	"underprov.memory.max":     {FactNumber, "bytes", FactSafe, "a container's memory max over the window, at 90% of its limit or more", false},
	"underprov.memory.limit":   {FactNumber, "bytes", FactSafe, "that container's memory limit", false},
	// Volume fill (k8s.observed.volume-filling, k8s.cost.volume-oversized), from kubelet volume stats.
	"volume.capacity":   {FactNumber, "bytes", FactSafe, "the volume's size, as the kubelet reports it", false},
	"volume.used":       {FactNumber, "bytes", FactSafe, "what it holds now", false},
	"volume.used.max":   {FactNumber, "bytes", FactSafe, "the most it held over the window", false},
	"volume.growth.day": {FactNumber, "bytes/day", FactSafe, "the slope of its used bytes over the window, per day; 0 when not growing", false},
	"volume.days.full":  {FactNumber, "days", FactSafe, "days until full at that slope", false},
	// Autoscaler behaviour (k8s.observed.autoscaler-behaviour), from kube-state-metrics.
	"hpa.at.max":  {FactNumber, "share", FactSafe, "share of the window's 5-minute steps at maxReplicas", false},
	"hpa.at.min":  {FactNumber, "share", FactSafe, "share of the window's 5-minute steps at minReplicas", false},
	"hpa.changes": {FactNumber, "changes", FactSafe, "how many times the current replica count changed over the window", false},
	// Webhook backing (k8s.reliability.webhook-unbacked).
	"webhook.endpoints.ready": {FactNumber, "endpoints", FactSafe, "ready endpoints the webhook's Service publishes", false},
	"webhook.nodes":           {FactNumber, "nodes", FactSafe, "nodes those ready endpoints are on", false},
	// Node scale-down blocked (k8s.cost.node-scale-down-blocked).
	"scaledown.autoscaler":                  {FactString, "", FactSafe, "the autoscaler detected: cluster-autoscaler or karpenter", false},
	"scaledown.billed":                      {FactNumber, "USD/mo", FactSafe, "the node's monthly list price: what it bills while blocked, never a saving", false},
	"scaledown.blocker.safe-to-evict-false": {FactNumber, "pods", FactSafe, "pods annotated cluster-autoscaler.kubernetes.io/safe-to-evict: false", false},
	"scaledown.blocker.unmanaged":           {FactNumber, "pods", FactSafe, "pods no controller manages", false},
	"scaledown.blocker.local-storage":       {FactNumber, "pods", FactSafe, "pods with emptyDir or hostPath volumes", false},
	"scaledown.blocker.kube-system-no-pdb":  {FactNumber, "pods", FactSafe, "kube-system pods with no PodDisruptionBudget", false},
	"scaledown.blocker.pdb-zero":            {FactNumber, "pods", FactSafe, "pods covered by a budget that allows no disruption", false},
	"scaledown.blocker.do-not-disrupt":      {FactNumber, "pods", FactSafe, "pods annotated karpenter.sh/do-not-disrupt: true", false},
	"scaledown.blocker.node-do-not-disrupt": {FactNumber, "nodes", FactSafe, "the node annotated karpenter.sh/do-not-disrupt: true", false},
	// Idle LoadBalancer (k8s.cost.idle-loadbalancer).
	"lb.pods.matched": {FactNumber, "pods", FactSafe, "pods the Service's selector matches, any phase", false},
	"lb.usd":          {FactNumber, "USD/mo", FactSafe, "the load balancer's fixed monthly base price at list", false},
	// Spread, pools, contradictions, dangling references, declarations (ENG-20c)
	"spread.replicas":            {FactNumber, "replicas", FactSafe, "the replica count of a multi-replica workload that declares no spread", false},
	"spread.pdb.bounded":         {FactBool, "", FactSafe, "whether a PodDisruptionBudget already bounds voluntary drains of the workload", false},
	"spread.nodes":               {FactNumber, "nodes", FactSafe, "schedulable nodes observed", false},
	"spread.zones":               {FactNumber, "zones", FactSafe, "distinct zones among those nodes", false},
	"pool.instance-type":         {FactString, "", FactSafe, "the cloud instance type of a node pool, a public catalogue name", false},
	"pool.region":                {FactString, "", FactIdentifier, "the cloud region of a node pool; tokenized like Cluster.Region, because a region locates the customer", false},
	"pool.nodes":                 {FactNumber, "nodes", FactSafe, "nodes in the pool", false},
	"commitment.list.node":       {FactNumber, "USD/mo", FactSafe, "one on-demand node's monthly list price", false},
	"commitment.rate.1yr":        {FactNumber, "USD/h", FactSafe, "the published 1-year No Upfront Compute Savings Plan hourly rate per node", false},
	"commitment.rate.3yr":        {FactNumber, "USD/h", FactSafe, "the published 3-year No Upfront Compute Savings Plan hourly rate per node", false},
	"rwo.pods":                   {FactNumber, "pods", FactSafe, "pods the workload runs, or one per selected node for a DaemonSet, against single-node volumes", false},
	"rwo.claims":                 {FactNumber, "claims", FactSafe, "claims the pod template names that permit one node at a time", false},
	"hpa.min-replicas":           {FactNumber, "replicas", FactSafe, "the autoscaler's minReplicas floor", false},
	"pdb.min-available":          {FactNumber, "pods", FactSafe, "the budget's integer minAvailable", false},
	"dangling.read":              {FactNumber, "objects", FactSafe, "objects of the referenced kind read, none of which carries the referenced name", false},
	"dangling.read.clusterroles": {FactNumber, "objects", FactSafe, "ClusterRoles read in the reading", false},
	"dangling.read.roles":        {FactNumber, "objects", FactSafe, "Roles read in the reading", false},
	"dangling.target":            {FactString, "", FactIdentifier, "the name the reference points at and no object carries", false},
	"dangling.unassessed":        {FactNumber, "targets", FactSafe, "autoscaler targets not assessed because their kind is not collected", false},
	"declaration.mismatches":     {FactNumber, "declarations", FactSafe, "declarations in the object that disagree with another declaration", false},
	// gp2 to gp3
	"gp2.volumes":                {FactNumber, "volumes", FactSafe, "EBS volumes on a gp2 StorageClass", false},
	"gp2.gib":                    {FactNumber, "GiB", FactSafe, "the provisioned size of those volumes, summed", false},
	"gp2.iops-crossover.volumes": {FactNumber, "volumes", FactSafe, "of those, volumes large enough that gp2 baseline IOPS exceed gp3's free baseline", false},
	"gp2.rate":                   {FactNumber, "USD/GB-mo", FactSafe, "gp2 list price per GB-month in the region", false},
	"gp3.rate":                   {FactNumber, "USD/GB-mo", FactSafe, "gp3 list price per GB-month in the region", false},
	// image hygiene
	"image.references": {FactNumber, "references", FactSafe, "mutable image references the workload's containers carry", false},
	// hpa burst, jobs
	"burst.autoscalers":          {FactNumber, "autoscalers", FactSafe, "autoscalers whose maxReplicas headroom is summed", false},
	"burst.autoscalers.excluded": {FactNumber, "autoscalers", FactSafe, "autoscalers left out of the sum because their target or its requests could not be resolved", false},
	"burst.ask.cpu":              {FactNumber, "millicores", FactSafe, "CPU the additional pods would request if every autoscaler reached maxReplicas", false},
	"burst.ask.memory":           {FactNumber, "bytes", FactSafe, "memory the additional pods would request if every autoscaler reached maxReplicas", false},
	"burst.free.cpu":             {FactNumber, "millicores", FactSafe, "allocatable CPU on the current nodes not yet requested", false},
	"burst.free.memory":          {FactNumber, "bytes", FactSafe, "allocatable memory on the current nodes not yet requested", false},
	"jobs.finished":              {FactNumber, "jobs", FactSafe, "finished Jobs in the namespace with no ttlSecondsAfterFinished", false},
	"jobs.truncated":             {FactBool, "", FactSafe, "whether the Job list was truncated, so the count is a floor", false},
	// missing requests
	"requests.containers": {FactNumber, "containers", FactSafe, "containers with no effective CPU or memory request", false},
	// pool generation lag
	"pool.capacity":           {FactString, "", FactSafe, "the pool's capacity type: on-demand, spot or reserved, a closed set", false},
	"pool.shape.vcpu":         {FactNumber, "vCPU", FactSafe, "vCPUs of one node of the pool, from the catalogue", false},
	"pool.shape.memory":       {FactNumber, "GiB", FactSafe, "memory of one node of the pool, from the catalogue", false},
	"pool.list.node":          {FactNumber, "USD/mo", FactSafe, "one node's monthly list price at the pool's capacity type", false},
	"candidate.instance-type": {FactString, "", FactSafe, "the cheaper equivalent instance type the priced tier names", false},
	"candidate.list.node":     {FactNumber, "USD/mo", FactSafe, "that type's monthly list price per node", false},
	"arm64.instance-type":     {FactString, "", FactSafe, "the arm64 equivalent instance type, stated and not banked", false},
	"arm64.list.node":         {FactNumber, "USD/mo", FactSafe, "that type's monthly list price per node", false},
	// namespaces, unready pods
	"ns.workloads":                {FactNumber, "workloads", FactSafe, "long-running workloads counted in the namespace", false},
	"ns.quotas":                   {FactNumber, "objects", FactSafe, "ResourceQuota objects observed in the namespace", false},
	"ns.limitranges":              {FactNumber, "objects", FactSafe, "LimitRange objects observed in the namespace", false},
	"ns.containers.unrequested":   {FactNumber, "containers", FactSafe, "containers in the namespace declaring no explicit CPU or memory request", false},
	"unready.pods":                {FactNumber, "pods", FactSafe, "pods of the workload reporting Ready=False", false},
	"unready.containers.reasoned": {FactNumber, "containers", FactSafe, "containers in those pods whose state carries a kubelet reason", false},
	// network policy
	"netpol.namespaces.unassessed": {FactNumber, "namespaces", FactSafe, "workload-bearing namespaces whose NetworkPolicy coverage could not be assessed", false},
	"netpol.workloads":             {FactNumber, "workloads", FactSafe, "workloads the namespace runs", false},
	"netpol.policies":              {FactNumber, "objects", FactSafe, "upstream NetworkPolicy objects in the namespace", false},
	"netpol.cni":                   {FactString, "", FactSafe, "the detected CNI, one of this product's own names for it", false},
	// node headroom
	"headroom.removable":          {FactNumber, "nodes", FactSafe, "the aggregate-slack ceiling of nodes the pool could shed, never below two left", false},
	"headroom.requests.cpu":       {FactNumber, "millicores", FactSafe, "summed pod CPU requests in the pool, DaemonSet pods excluded", false},
	"headroom.requests.memory":    {FactNumber, "bytes", FactSafe, "summed pod memory requests in the pool, DaemonSet pods excluded", false},
	"headroom.allocatable.cpu":    {FactNumber, "millicores", FactSafe, "the pool's allocatable CPU", false},
	"headroom.allocatable.memory": {FactNumber, "bytes", FactSafe, "the pool's allocatable memory", false},
	// host access
	"host-access.items":               {FactNumber, "items", FactSafe, "privileged or host-level settings the workload's template carries", false},
	"host-access.node-infrastructure": {FactBool, "", FactSafe, "whether the workload matches a known node-infrastructure pattern, which lowers severity", false},
	// pdb blocks drains
	"pdb.workloads.matched": {FactNumber, "workloads", FactSafe, "workloads whose pods the budget selects", false},
	"pdb.pods.healthy":      {FactNumber, "pods", FactSafe, "the budget's status.currentHealthy", false},
	"pdb.pods.desired":      {FactNumber, "pods", FactSafe, "the budget's status.desiredHealthy", false},
	// cluster-admin bindings
	"cluster-admin.subjects": {FactNumber, "subjects", FactSafe, "subjects the binding grants cluster-admin to", false},
	// secrets in env, SA automount
	"secretenv.values":       {FactNumber, "references", FactSafe, "secret references the pod template turns into environment variables", false},
	"secretenv.secrets":      {FactNumber, "secrets", FactSafe, "distinct Secrets those references name", false},
	"secretenv.whole-secret": {FactNumber, "references", FactSafe, "of those, envFrom references that import every key of a Secret", false},
	"automount.roles":        {FactNumber, "roles", FactSafe, "roles bound to the namespace's default ServiceAccount", false},
	// ghost subjects
	"ghost.subjects.missing":  {FactNumber, "subjects", FactSafe, "ServiceAccount subjects the binding names that are absent from the reading", false},
	"ghost.subjects.unjudged": {FactNumber, "subjects", FactSafe, "User or Group subjects the binding names, not judged because no object represents them", false},
	// replica health, restarts
	"replicas.desired": {FactNumber, "replicas", FactSafe, "replicas the controller's spec asks for", false},
	"replicas.ready":   {FactNumber, "replicas", FactSafe, "replicas the controller's status reports ready", false},
	"restarts.worst":   {FactNumber, "restarts", FactSafe, "the highest container restart total among the workload's pods", false},
	"restarts.pods":    {FactNumber, "pods", FactSafe, "pods with a container at or above the restart floor", false},
	"restarts.floor":   {FactNumber, "restarts", FactSafe, "the restart total at or above which a container is listed", false},
	// stuck status
	"condition.type":         {FactString, "", FactSafe, "the status condition's type, a word the controller writes from Kubernetes' own vocabulary", false},
	"condition.status":       {FactString, "", FactSafe, "the condition's status: True, False or Unknown", false},
	"condition.since":        {FactString, "", FactSafe, "the oldest lastTransitionTime among the objects in the group, RFC 3339 UTC", false},
	"condition.objects":      {FactNumber, "objects", FactSafe, "objects in the group reading the same way", false},
	"daemonset.misscheduled": {FactNumber, "pods", FactSafe, "the DaemonSet controller's numberMisscheduled", false},
	"daemonset.desired":      {FactNumber, "pods", FactSafe, "the DaemonSet's desiredNumberScheduled", false},
	"daemonset.ready":        {FactNumber, "pods", FactSafe, "the DaemonSet's numberReady", false},
	"pvc.requested":          {FactNumber, "bytes", FactSafe, "the claim's spec.resources.requests.storage", false},
	"pvc.capacity":           {FactNumber, "bytes", FactSafe, "the claim's status.capacity.storage as its controller wrote it", false},
	// rollout strategy
	"rollout.strategy": {FactString, "", FactSafe, "the Deployment's strategy.type, a closed Kubernetes word; empty when unset", false},
	"rollout.fronted":  {FactBool, "", FactSafe, "whether a Service in the namespace selects the Deployment's pods", false},
	// traffic policy
	"traffic.services": {FactNumber, "services", FactSafe, "Services explicitly setting the externalTrafficPolicy the finding names", false},
	// version support
	"version.provider":         {FactString, "", FactSafe, "the cloud provider the nodes show: eks, aks or gke, a closed set", false},
	"version.minor":            {FactString, "", FactSafe, "the Kubernetes minor version the API server reports", false},
	"version.status":           {FactString, "", FactSafe, "the version's support state on the snapshot date: extended or unsupported", false},
	"version.released":         {FactString, "", FactSafe, "the version's release date in the provider's published table, YYYY-MM-DD", false},
	"version.standard-ends":    {FactString, "", FactSafe, "the date ordinary support ends, YYYY-MM-DD", false},
	"version.extended-ends":    {FactString, "", FactSafe, "the date extended support ends, YYYY-MM-DD; absent when none is published", false},
	"version.surcharge.hourly": {FactNumber, "USD/h", FactSafe, "the extended-support surcharge per cluster-hour", false},
	"version.surcharge":        {FactNumber, "USD/mo", FactSafe, "that surcharge over a month, the sole figure the finding states", false},
	// topology posture
	"controlplane.nodes":  {FactNumber, "nodes", FactSafe, "nodes in the reading", false},
	"controlplane.node":   {FactString, "", FactIdentifier, "the one node carrying a control-plane role label", false},
	"unmanaged.pods":      {FactNumber, "pods", FactSafe, "pods in the namespace with no controller ownerReference", false},
	"pdb.overlap.pods":    {FactNumber, "pods", FactSafe, "pods selected by more than one PodDisruptionBudget", false},
	"pdb.overlap.budgets": {FactNumber, "budgets", FactSafe, "distinct PodDisruptionBudgets that overlap on those pods", false},
	// unattached volume
	"pv.capacity": {FactNumber, "bytes", FactSafe, "the PersistentVolume's spec.capacity.storage", false},
	"pv.phase":    {FactString, "", FactSafe, "the PersistentVolume's status.phase, a closed Kubernetes word", false},
	"pv.reclaim":  {FactString, "", FactSafe, "its reclaim policy, a closed Kubernetes word, or 'not set'", false},
	// temporal rules
	"alerts.rules":         {FactNumber, "rules", FactSafe, "distinct alerting rules firing in the cluster's own Prometheus", false},
	"alerts.series":        {FactNumber, "series", FactSafe, "series firing across those rules", false},
	"throttle.containers":  {FactNumber, "containers", FactSafe, "containers throttled in at least the floor share of their CPU periods", false},
	"throttle.worst":       {FactNumber, "share", FactSafe, "the largest share of CPU periods any listed container was throttled in", false},
	"throttle.floor":       {FactNumber, "share", FactSafe, "the share of periods at or above which a container is listed", false},
	"throttle.periods.min": {FactNumber, "periods", FactSafe, "the fewest CFS periods a container must have run for its share to count", false},
	"throttle.unlimited":   {FactNumber, "containers", FactSafe, "containers with throttling series and no CPU limit, not reported", false},
	"scrape.down":          {FactNumber, "targets", FactSafe, "scrape targets reporting up=0", false},
	"scrape.up":            {FactNumber, "targets", FactSafe, "scrape targets reporting up=1", false},
	// oblique: digest drift, version skew
	"drift.digests":     {FactNumber, "digests", FactSafe, "distinct image digests the pods of one spec image report", false},
	"drift.pods":        {FactNumber, "pods", FactSafe, "pods reporting those digests", false},
	"skew.minors":       {FactNumber, "versions", FactSafe, "distinct kubelet minor versions across the nodes", false},
	"skew.nodes":        {FactNumber, "nodes", FactSafe, "nodes whose kubelet version could be parsed", false},
	"skew.allowed":      {FactNumber, "versions", FactSafe, "how many minor versions older than the API server a kubelet may be at the server's version", false},
	"skew.nodes.behind": {FactNumber, "nodes", FactSafe, "nodes further behind the API server than the window allows", false},
	"skew.nodes.ahead":  {FactNumber, "nodes", FactSafe, "nodes newer than the API server", false},
	// pod security
	"pss.containers.flagged": {FactNumber, "containers", FactSafe, "containers whose securityContext does not assert the control", false},
	"pss.containers":         {FactNumber, "containers", FactSafe, "containers and init containers in the pod template", false},
	"psa.enforce":            {FactString, "", FactText, "the namespace's pod-security enforce label, as written; <unset> when absent", false},
	"psa.warn":               {FactString, "", FactText, "the namespace's pod-security warn label, as written; <unset> when absent", false},
	"psa.audit":              {FactString, "", FactText, "the namespace's pod-security audit label, as written; <unset> when absent", false},
	// rollout preflight
	"rollout.updated":         {FactNumber, "replicas", FactSafe, "the StatefulSet's status.updatedReplicas", false},
	"rollout.partition":       {FactNumber, "ordinals", FactSafe, "the StatefulSet's rollingUpdate partition", false},
	"rollout.held-back":       {FactNumber, "pods", FactSafe, "pods the partition holds on the previous revision", false},
	"rollout.max-unavailable": {FactNumber, "pods", FactSafe, "the Deployment's maxUnavailable resolved against its replicas", false},
	"rollout.available":       {FactNumber, "pods", FactSafe, "pods left available during an update at that maxUnavailable", false},
	"surge.pods":              {FactNumber, "pods", FactSafe, "additional pods a rolling update with maxUnavailable=0 must be able to add", false},
	"surge.ask.cpu":           {FactNumber, "millicores", FactSafe, "CPU the surge pods request in total", false},
	"surge.ask.memory":        {FactNumber, "bytes", FactSafe, "memory the surge pods request in total", false},
	"surge.free.cpu":          {FactNumber, "millicores", FactSafe, "requested CPU headroom across the eligible nodes", false},
	"surge.free.memory":       {FactNumber, "bytes", FactSafe, "requested memory headroom across the eligible nodes", false},
	"surge.nodes":             {FactNumber, "nodes", FactSafe, "schedulable Ready nodes the headroom is summed over", false},
	// service endpoints
	"endpoints.slices":      {FactNumber, "slices", FactSafe, "EndpointSlices listed for the Service", false},
	"endpoints.published":   {FactNumber, "addresses", FactSafe, "addresses the slices publish in the counted family", false},
	"endpoints.ready.false": {FactNumber, "addresses", FactSafe, "published entries with conditions.ready=false", false},
	"endpoints.ready.unset": {FactNumber, "addresses", FactSafe, "published entries with conditions.ready unset, which the API defines as unknown", false},
	"endpoints.terminating": {FactNumber, "addresses", FactSafe, "published entries with conditions.terminating=true", false},
	"endpoints.ready":       {FactNumber, "addresses", FactSafe, "published entries with conditions.ready=true", false},
	"endpoints.node":        {FactString, "", FactIdentifier, "the one node every ready address names", false},
	"endpoints.selected":    {FactNumber, "pods", FactSafe, "pods the Service selects that have been Ready for the grace period", false},
	"endpoints.unpublished": {FactNumber, "pods", FactSafe, "of those, pods listed in no EndpointSlice of the Service", false},
	// silent failures
	"hpa.replicas.current":        {FactNumber, "replicas", FactSafe, "the autoscaler's status.currentReplicas", false},
	"hpa.replicas.max":            {FactNumber, "replicas", FactSafe, "the autoscaler's spec.maxReplicas", false},
	"hpa.replicas.desired":        {FactNumber, "replicas", FactSafe, "the autoscaler's status.desiredReplicas; 0 when unset", false},
	"pvc.consumers.pending":       {FactNumber, "pods", FactSafe, "Pending pods that reference the Pending claim", false},
	"ingress.backends.unresolved": {FactNumber, "references", FactSafe, "backend references of the Ingress that resolve to no Service or to no ready address", false},
	// cronjob success
	"cronjob.never":        {FactBool, "", FactSafe, "whether the CronJob has been scheduled and never recorded a successful completion", false},
	"cronjob.window":       {FactNumber, "seconds", FactSafe, "the observation window inside which a success is expected", false},
	"cronjob.last-success": {FactString, "", FactSafe, "the CronJob's status.lastSuccessfulTime, RFC 3339 UTC", false},
	"cronjob.success.age":  {FactNumber, "seconds", FactSafe, "how long before the reading that last success was", false},
	// self-contradicting declarations
	"placement.offenders":  {FactNumber, "declarations", FactSafe, "placement declarations (topology keys or node labels) no node satisfies", false},
	"placement.nodes":      {FactNumber, "nodes", FactSafe, "nodes read", false},
	"placement.hard":       {FactBool, "", FactSafe, "whether any of the offending declarations is a hard requirement", false},
	"placement.bound":      {FactNumber, "pods", FactSafe, "pods of the workload already bound to a node", false},
	"quota.resources.over": {FactNumber, "resources", FactSafe, "resources whose status.used is above status.hard", false},
	"netpol.peers.dead":    {FactNumber, "peers", FactSafe, "NetworkPolicy peers whose namespaceSelector matches no namespace", false},
	"netpol.namespaces":    {FactNumber, "namespaces", FactSafe, "namespaces read", false},
	// upgrade preflight
	"api.served":            {FactNumber, "versions", FactSafe, "group/versions the API server enumerated", false},
	"api.removed.future":    {FactNumber, "versions", FactSafe, "served group/versions the deprecation guide records as removed in a later release", false},
	"api.removed.past":      {FactNumber, "versions", FactSafe, "served group/versions recorded as removed at or before the cluster's version", false},
	"api.removed.earliest":  {FactString, "", FactSafe, "the earliest Kubernetes minor in which a served group/version is removed", false},
	"api.server-version":    {FactString, "", FactSafe, "the version string the API server reports", false},
	"crd.webhooks.unbacked": {FactNumber, "crds", FactSafe, "CRDs whose conversion webhook names a Service that publishes no ready address", false},
	"crd.webhooks.unjudged": {FactNumber, "crds", FactSafe, "conversion webhooks not judged: addressed by URL or by a Service not read", false},
	"roll.nodes.blocked":    {FactNumber, "nodes", FactSafe, "nodes a drain cannot evacuate, per the drain rules together", false},
	"roll.nodes":            {FactNumber, "nodes", FactSafe, "nodes in the reading", false},
	"roll.findings":         {FactNumber, "findings", FactSafe, "per-node drain findings the roll finding rests on", false},
	// node drain, other stops
	"drain.pods.unmanaged": {FactNumber, "pods", FactSafe, "pods on the node with no controller ownerReference", false},
	"placement.colocated":  {FactNumber, "pods", FactSafe, "pods of one workload bound to the node", false},
	"placement.live":       {FactNumber, "pods", FactSafe, "live pods of that workload in total", false},
	"pin.pods":             {FactNumber, "pods", FactSafe, "pods mounting a volume whose nodeAffinity pins it to one node", false},
	"pin.statefulset":      {FactBool, "", FactSafe, "whether any mounting pod is owned by a StatefulSet", false},
	// analyzers: HPA, cert-manager, monitoring stack
	"hpa.replicas.min":              {FactNumber, "replicas", FactSafe, "the autoscaler's minReplicas, one when unset", false},
	"cert.not-after":                {FactString, "", FactSafe, "the certificate's status.notAfter as cert-manager wrote it, RFC 3339", false},
	"cert.days-left":                {FactNumber, "days", FactSafe, "whole days between the reading and notAfter", false},
	"cert.window":                   {FactNumber, "days", FactSafe, "the expiry window inside which a certificate is reported", false},
	"cert.issuer-kind":              {FactString, "", FactSafe, "the kind of the certificate's issuerRef; the issuer's name is not carried", false},
	"monitor.candidates":            {FactNumber, "objects", FactSafe, "Services or Pods in the namespaces a monitor covers", false},
	"monitor.matched":               {FactNumber, "objects", FactSafe, "of those, the objects its selector matched", false},
	"alertroute.receivers.missing":  {FactNumber, "receivers", FactSafe, "routes naming a receiver the object does not declare", false},
	"alertroute.receivers.declared": {FactNumber, "receivers", FactSafe, "receivers the object declares", false},
	"prometheus.retention":          {FactString, "", FactText, "the retention a Prometheus object writes, as written", false},
}

// ValidateFacts checks one finding's facts against the registry: a known key, a value of its type, a finite number.
func ValidateFacts(fs []Fact) []error {
	var errs []error
	for _, f := range fs {
		d, ok := FactKeys[f.Key]
		if !ok {
			errs = append(errs, fmt.Errorf("fact %q is not a registered key", f.Key))
			continue
		}
		switch v := f.Value.(type) {
		case float64:
			if d.Type != FactNumber {
				errs = append(errs, fmt.Errorf("fact %s: a number, registered as %s", f.Key, d.Type))
			} else if math.IsNaN(v) || math.IsInf(v, 0) {
				errs = append(errs, fmt.Errorf("fact %s: %v is not a finite number", f.Key, v))
			}
		case string:
			if d.Type != FactString {
				errs = append(errs, fmt.Errorf("fact %s: a string, registered as %s", f.Key, d.Type))
			}
		case bool:
			if d.Type != FactBool {
				errs = append(errs, fmt.Errorf("fact %s: a bool, registered as %s", f.Key, d.Type))
			}
		default:
			errs = append(errs, fmt.Errorf("fact %s: value of type %T; a fact is a number, a string or a bool", f.Key, f.Value))
		}
	}
	return errs
}

// NewFact builds a fact with its registered unit. An unregistered key panics: the fact would fail validation the
// moment it was written, and every test that renders the rule finds it first.
func NewFact(key string, value any) Fact {
	d, ok := FactKeys[key]
	if !ok {
		panic("types: fact key " + key + " is not registered in FactKeys")
	}
	switch v := value.(type) {
	case int:
		value = float64(v)
	case int32:
		value = float64(v)
	case int64:
		value = float64(v)
	}
	return Fact{Key: key, Value: value, Unit: d.Unit}
}

// FactValue returns the value of key among fs, and whether it is there.
func FactValue(fs []Fact, key string) (any, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f.Value, true
		}
	}
	return nil, false
}

// FactNum is FactValue for a number; 0 when absent.
func FactNum(fs []Fact, key string) float64 {
	v, _ := FactValue(fs, key)
	n, _ := v.(float64)
	return n
}

// FactStr is FactValue for a string; "" when absent.
func FactStr(fs []Fact, key string) string {
	v, _ := FactValue(fs, key)
	s, _ := v.(string)
	return s
}

// SortedFactKeys is the registry's keys in order, for a test or a document that lists them.
func SortedFactKeys() []string {
	out := make([]string, 0, len(FactKeys))
	for k := range FactKeys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
