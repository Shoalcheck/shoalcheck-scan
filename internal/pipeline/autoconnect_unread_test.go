package pipeline

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"k8s.io/client-go/rest"

	"github.com/Shoalcheck/shoalcheck-scan/internal/collect"
)

// A SERVICE LIST THAT WAS NOT READ IS NOT A CLUSTER WITHOUT A PROMETHEUS.
//
// Every run against an unreachable cluster printed "auto-connect: no in-cluster Prometheus Service found" — a
// statement about the cluster's monitoring, from a run that never saw one of its Services. An absence needs its
// cause: the services list was not read, so no Prometheus was looked for.
func TestFetchUsage_AnUnreadServiceListIsNotAnAbsentPrometheus(t *testing.T) {
	inv := &collect.Inventory{Meta: collect.Meta{Denied: []string{"services: dial tcp 127.0.0.1:1: connect: connection refused"}}}
	var log bytes.Buffer
	if _, err := fetchUsage(context.Background(), Options{AutoConnect: true, RESTConfig: &rest.Config{Host: "http://127.0.0.1:1"}}, inv, &log); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), "no in-cluster Prometheus Service found") {
		t.Errorf("a run that never read a Service says the cluster has no Prometheus:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "services were not read") {
		t.Errorf("the log does not say why no Prometheus was looked for:\n%s", log.String())
	}
}
