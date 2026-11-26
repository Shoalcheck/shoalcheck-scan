package prom

import (
	"context"
	"fmt"
)

// VOLUME FILL AND AUTOSCALER BEHAVIOUR OVER THE WINDOW (ENG-50, ENG-54). Two more things a week of Prometheus holds
// that a snapshot does not: how full each claim's volume got and how fast it grows, from the kubelet's volume stats;
// and where each HorizontalPodAutoscaler spent the week — at its floor, at its ceiling, or changing every few minutes —
// from kube-state-metrics. Both are read only from a source proven to be this cluster's (FetchTemporal).

// VolumeFill is one PersistentVolumeClaim's volume over the window.
type VolumeFill struct {
	Namespace, Claim string
	CapacityBytes    float64
	UsedNowBytes     float64
	UsedMaxBytes     float64 // the most it held at any point in the window
	// GrowthPerDay is the least-squares slope of the used bytes over the window, per day. Negative or zero when the
	// volume is not growing.
	GrowthPerDay float64
}

// AutoscalerHistory is one HorizontalPodAutoscaler over the window.
type AutoscalerHistory struct {
	Namespace, Name string
	AtMinShare      float64 // share of the window's 5-minute steps at minReplicas
	AtMaxShare      float64 // share at maxReplicas
	Changes         float64 // how many times the current replica count changed
}

const (
	queryVolumeCapacity = `max by (namespace, persistentvolumeclaim) (kubelet_volume_stats_capacity_bytes)`
	queryVolumeUsedNow  = `max by (namespace, persistentvolumeclaim) (kubelet_volume_stats_used_bytes)`
	queryVolumeUsedMax  = `max by (namespace, persistentvolumeclaim) (max_over_time(kubelet_volume_stats_used_bytes[7d]))`
	queryVolumeGrowth   = `max by (namespace, persistentvolumeclaim) (deriv(kubelet_volume_stats_used_bytes[7d]))`

	queryHPAAtMax   = `avg_over_time((kube_horizontalpodautoscaler_status_current_replicas >= bool on (namespace, horizontalpodautoscaler) kube_horizontalpodautoscaler_spec_max_replicas)[7d:5m])`
	queryHPAAtMin   = `avg_over_time((kube_horizontalpodautoscaler_status_current_replicas <= bool on (namespace, horizontalpodautoscaler) kube_horizontalpodautoscaler_spec_min_replicas)[7d:5m])`
	queryHPAChanges = `changes(kube_horizontalpodautoscaler_status_current_replicas[7d])`
)

// VolumeFill7d reads every claim's volume stats. A claim with no capacity series is left out: a fill without its
// denominator is not a fill.
func (c *Client) VolumeFill7d(ctx context.Context) (map[string]VolumeFill, error) {
	rows := [4][]Sample{}
	for i, q := range []string{queryVolumeCapacity, queryVolumeUsedNow, queryVolumeUsedMax, queryVolumeGrowth} {
		r, err := c.Query(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("prom: volume stats: %w", err)
		}
		rows[i] = r
	}
	key := func(m map[string]string) (string, string, string) {
		ns, pvc := m["namespace"], m["persistentvolumeclaim"]
		if ns == "" || pvc == "" {
			return "", "", ""
		}
		return ns + "/" + pvc, ns, pvc
	}
	out := map[string]VolumeFill{}
	for _, s := range rows[0] {
		if k, ns, pvc := key(s.Metric); k != "" && s.Value > 0 {
			out[k] = VolumeFill{Namespace: ns, Claim: pvc, CapacityBytes: s.Value}
		}
	}
	for i, set := range []func(*VolumeFill, float64){
		func(v *VolumeFill, x float64) { v.UsedNowBytes = x },
		func(v *VolumeFill, x float64) { v.UsedMaxBytes = x },
		func(v *VolumeFill, x float64) { v.GrowthPerDay = x * 86400 },
	} {
		for _, s := range rows[i+1] {
			if k, _, _ := key(s.Metric); k != "" {
				if v, ok := out[k]; ok {
					set(&v, s.Value)
					out[k] = v
				}
			}
		}
	}
	return out, nil
}

// AutoscalerHistory7d reads where each HorizontalPodAutoscaler spent the window.
func (c *Client) AutoscalerHistory7d(ctx context.Context) (map[string]AutoscalerHistory, error) {
	out := map[string]AutoscalerHistory{}
	for i, q := range []string{queryHPAAtMax, queryHPAAtMin, queryHPAChanges} {
		rows, err := c.Query(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("prom: autoscaler history: %w", err)
		}
		for _, s := range rows {
			ns, name := s.Metric["namespace"], s.Metric["horizontalpodautoscaler"]
			if ns == "" || name == "" {
				continue
			}
			h := out[ns+"/"+name]
			h.Namespace, h.Name = ns, name
			switch i {
			case 0:
				h.AtMaxShare = s.Value
			case 1:
				h.AtMinShare = s.Value
			case 2:
				h.Changes = s.Value
			}
			out[ns+"/"+name] = h
		}
	}
	return out, nil
}
