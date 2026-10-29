package rules

import (
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
	"github.com/Shoalcheck/shoalcheck-scan/internal/types"
)

// A PRIVILEGED POD IS PRIVILEGED WHOEVER CREATED IT. The pod-security rules read the templates of Deployments,
// StatefulSets and DaemonSets and nothing else, so a privileged bare Pod, a Job mounting the node's filesystem or a
// CronJob that runs privileged every night was judged by no rule at all — on a live audit as much as on paper. Found
// by the gate agent's review; the bench now plants all three.
//
// podTemplatesFixture is one namespace holding every way a pod spec reaches a node: the three workload kinds, a
// CronJob with the Job and pod it spawned, a standalone Job and its pod, a bare Pod, a ReplicaSet with no
// Deployment, and two pods of an operator's custom controller. Each runnable spec must be judged exactly once.
func podTemplatesFixture() *collect.Inventory {
	priv := func() corev1.PodSpec {
		t := true
		return corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "app:1.0",
			SecurityContext: &corev1.SecurityContext{Privileged: &t}}}}
	}
	hostPath := func() corev1.PodSpec {
		s := corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "app:1.0",
			VolumeMounts: []corev1.VolumeMount{{Name: "root", MountPath: "/host"}}}}}
		s.Volumes = []corev1.Volume{{Name: "root", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}}}
		return s
	}
	owned := func(kind, name string) []metav1.OwnerReference {
		t := true
		return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &t}}
	}
	pod := func(name string, owners []metav1.OwnerReference, spec corev1.PodSpec) corev1.Pod {
		return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "jobs", Name: name, OwnerReferences: owners},
			Spec: spec, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	}
	one := int32(1)
	inv := &collect.Inventory{
		Deployments: []appsv1.Deployment{{ObjectMeta: metav1.ObjectMeta{Namespace: "jobs", Name: "web"},
			Spec: appsv1.DeploymentSpec{Replicas: &one, Template: corev1.PodTemplateSpec{Spec: priv()}}}},
		CronJobs: []batchv1.CronJob{{ObjectMeta: metav1.ObjectMeta{Namespace: "jobs", Name: "nightly"},
			Spec: batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
				Template: corev1.PodTemplateSpec{Spec: priv()}}}}}},
		Jobs: []batchv1.Job{
			{ObjectMeta: metav1.ObjectMeta{Namespace: "jobs", Name: "nightly-29001", OwnerReferences: owned("CronJob", "nightly")},
				Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: priv()}}},
			{ObjectMeta: metav1.ObjectMeta{Namespace: "jobs", Name: "backup"},
				Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: hostPath()}}},
		},
		Pods: []corev1.Pod{
			pod("web-5d8c7b9f4-abcde", owned("ReplicaSet", "web-5d8c7b9f4"), priv()),
			pod("nightly-29001-xk2p9", owned("Job", "nightly-29001"), priv()),
			pod("backup-q8w2e", owned("Job", "backup"), hostPath()),
			pod("rogue", nil, priv()),
			pod("orphan-rs-7f9c-zz1", owned("ReplicaSet", "orphan-rs-7f9c"), priv()),
			pod("ingest-0", owned("Rollout", "ingest"), priv()),
			pod("ingest-1", owned("Rollout", "ingest"), priv()),
		},
	}
	inv.Meta.Collected = []string{"deployments", "statefulsets", "daemonsets", "cronjobs", "jobs", "pods"}
	return inv
}

func subjectsOf(fs []types.Finding) []string {
	var out []string
	for _, f := range fs {
		r := f.AffectedResources[0]
		out = append(out, r.Kind+"/"+r.Name)
	}
	sort.Strings(out)
	return out
}

func TestPodSecurity_ReachesEveryPodTheClusterRuns(t *testing.T) {
	inv := podTemplatesFixture()
	// A pod whose controller this product never reads (a ReplicaSet with no Deployment, an operator's Rollout) is
	// named as the POD — the object that was read — once per controller, never as the controller: a sentence about
	// "Rollout jobs/ingest" would claim a provenance no reading supports (B-141).
	want := "CronJob/nightly,Deployment/web,Job/backup,Pod/ingest-0,Pod/orphan-rs-7f9c-zz1,Pod/rogue"
	if got := strings.Join(subjectsOf(PrivilegedHostAccess{}.Evaluate(inv, Options{})), ","); got != want {
		t.Errorf("privileged-host-access judged %s\nwant once each: %s", got, want)
	}
	// The PSS table reads the same specs: the pods without a securityContext run as root wherever they came from.
	for _, r := range pssRules() {
		if r.ID() != "k8s.workload.runs-as-root" {
			continue
		}
		if got := strings.Join(subjectsOf(r.Evaluate(inv, Options{})), ","); got != want {
			t.Errorf("runs-as-root judged %s\nwant once each: %s", got, want)
		}
	}
}
