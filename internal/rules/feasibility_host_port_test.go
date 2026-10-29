package rules

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// A HOST PORT IS A SCHEDULER FILTER. The scheduler's NodePorts filter places a pod only on a node where no pod
// already bound there holds a host port the pod asks for, and a hostNetwork pod asks for every container port it
// declares (the API server defaults hostPort to containerPort for it). The model did not read ports at all, so an
// ingress controller run as a Deployment with one replica per worker was a pod with somewhere to go when a worker
// was drained — every other worker already held the port, and the evicted replica sat Pending. That is the one
// direction this model may not be wrong in.

// ingressFixture is setFixture with a third replica on the spare worker: api-1 on w1 asks for `asked`, and api-2
// on w2 and api-3 on w3 hold `held`. Losing w1 leaves the tainted control plane, w2 and w3.
func ingressFixture(asked, held corev1.ContainerPort, hostNetwork bool) *collect.Inventory {
	inv := setFixture("4", "500m")
	third := inv.Pods[1]
	third.Name, third.Spec.NodeName = "api-3", "w3"
	inv.Pods = append(inv.Pods, third)
	for i := range inv.Pods {
		port := held
		if i == 0 {
			port = asked
		}
		containers := append([]corev1.Container(nil), inv.Pods[i].Spec.Containers...)
		containers[0].Ports = []corev1.ContainerPort{port}
		inv.Pods[i].Spec.Containers = containers
		inv.Pods[i].Spec.HostNetwork = hostNetwork
	}
	return inv
}

func hostPort(port int32) corev1.ContainerPort {
	return corev1.ContainerPort{ContainerPort: port, HostPort: port, Protocol: corev1.ProtocolTCP}
}

func strandsAPI1(t *testing.T, inv *collect.Inventory) bool {
	t.Helper()
	out := realFindings((NodeLossFeasibility{}).Evaluate(inv, Options{}))
	return findingFor(out, "shop", "api-1") != nil
}

// Every surviving worker holds the port, the control plane is tainted: the replica drained off w1 has nowhere, and
// the finding names the port it asks for.
func TestFeasibility_AHostPortHeldOnEverySurvivorStrandsThePod(t *testing.T) {
	inv := ingressFixture(hostPort(8080), hostPort(8080), false)
	out := realFindings((NodeLossFeasibility{}).Evaluate(inv, Options{}))
	f := findingFor(out, "shop", "api-1")
	if f == nil {
		t.Fatal("losing w1 does not name shop/api-1, though w2 and w3 each hold host port 8080 and the control plane is tainted")
	}
	if !strings.Contains(f.Title, "w1") {
		t.Errorf("the finding is not about w1: %s", f.Title)
	}
	if blob := strings.Join(f.Evidence, "\n"); !strings.Contains(blob, "8080/TCP") {
		t.Errorf("the finding does not name the host port the pod asks for:\n%s", blob)
	}
}

// A hostNetwork pod declares no hostPort and holds its container ports all the same.
func TestFeasibility_AHostNetworkPodHoldsItsContainerPorts(t *testing.T) {
	bare := corev1.ContainerPort{ContainerPort: 10254, Protocol: corev1.ProtocolTCP}
	if !strandsAPI1(t, ingressFixture(bare, bare, true)) {
		t.Fatal("three hostNetwork replicas on port 10254 and w1 lost: shop/api-1 is not named")
	}
	if strandsAPI1(t, ingressFixture(bare, bare, false)) {
		t.Fatal("a container port with no hostPort and no hostNetwork holds nothing on the node, and it stranded the pod")
	}
}

// The scheduler keys a host port by address, protocol and number, with an empty address meaning every address and
// an empty protocol meaning TCP. Stricter than that is wrong in the direction the model may not be.
func TestFeasibility_AHostPortConflictIsKeyedAsTheSchedulerKeysIt(t *testing.T) {
	at := func(ip string, port int32, proto corev1.Protocol) corev1.ContainerPort {
		return corev1.ContainerPort{ContainerPort: port, HostPort: port, HostIP: ip, Protocol: proto}
	}
	for _, tc := range []struct {
		name        string
		asked, held corev1.ContainerPort
		conflict    bool
	}{
		{"another number", hostPort(8080), hostPort(8081), false},
		{"another protocol", at("", 53, corev1.ProtocolUDP), at("", 53, corev1.ProtocolTCP), false},
		{"two specific addresses", at("10.0.0.1", 8080, "TCP"), at("10.0.0.2", 8080, "TCP"), false},
		{"empty protocol is TCP", at("", 8080, ""), at("", 8080, corev1.ProtocolTCP), true},
		{"a specific address against every address", at("10.0.0.1", 8080, "TCP"), at("", 8080, "TCP"), true},
		{"every address against a specific one", at("0.0.0.0", 8080, "TCP"), at("10.0.0.2", 8080, "TCP"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := strandsAPI1(t, ingressFixture(tc.asked, tc.held, false)); got != tc.conflict {
				t.Errorf("asked %+v, held %+v: stranded=%v, want %v", tc.asked, tc.held, got, tc.conflict)
			}
		})
	}
}

// A port bound to one host address strands the pod as any other does, and the address stays out of the finding:
// it is a node's IP, and redaction tokenises names, not addresses.
func TestFeasibility_AHostPortFindingNeverPrintsTheAddress(t *testing.T) {
	asked := corev1.ContainerPort{ContainerPort: 8080, HostPort: 8080, HostIP: "10.20.30.40", Protocol: corev1.ProtocolTCP}
	out := realFindings((NodeLossFeasibility{}).Evaluate(ingressFixture(asked, hostPort(8080), false), Options{}))
	f := findingFor(out, "shop", "api-1")
	if f == nil {
		t.Fatal("a port on one address, held on every address by every survivor, did not strand the pod")
	}
	blob := f.Title + "\n" + f.Description + "\n" + strings.Join(f.Evidence, "\n")
	if strings.Contains(blob, "10.20.30.40") {
		t.Errorf("the finding prints the host address:\n%s", blob)
	}
	if !strings.Contains(blob, "8080/TCP on one host address") {
		t.Errorf("the finding does not say the port is bound to one address:\n%s", blob)
	}
}

// A finished pod is not in the scheduler's cache and holds no port, as it holds no room (holdsRoom).
func TestFeasibility_AFinishedPodHoldsNoHostPort(t *testing.T) {
	inv := ingressFixture(hostPort(8080), hostPort(8080), false)
	inv.Pods[1].Status.Phase = corev1.PodSucceeded
	if strandsAPI1(t, inv) {
		t.Fatal("w2's only port holder has Succeeded, and shop/api-1 was still reported with nowhere to go")
	}
}

// The boundary moves with the model: host ports are named as modelled, and the case the model does not see —
// two leaving pods asking for the same port, against each other — is named as not.
func TestFeasibility_PublishesItsHostPortBoundary(t *testing.T) {
	out := realFindings((NodeLossFeasibility{}).Evaluate(ingressFixture(hostPort(8080), hostPort(8080), false), Options{}))
	f := findingFor(out, "shop", "api-1")
	if f == nil {
		t.Fatal("no finding")
	}
	var modelled, unmodelled string
	for _, e := range f.Evidence {
		switch {
		case strings.HasPrefix(e, "modelled here: "):
			modelled = e
		case strings.HasPrefix(e, "not modelled: "):
			unmodelled = e
		}
	}
	if !strings.Contains(modelled, "host port") {
		t.Errorf("host ports are not named among the modelled predicates: %s", modelled)
	}
	if !strings.Contains(unmodelled, "same host port") {
		t.Errorf("two leaving pods asking for the same host port is not named as unmodelled: %s", unmodelled)
	}
}
