// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package nld

import (
	"context"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

const (
	hostLabel       = "Reserved:host"
	nldLabel        = "k8s:k8s-app=node-local-dns"
	systemNamespace = "kube-system"
	queryLabel      = "dnsQuery"
	responseLabel   = "dnsReponse"
	dnsPort         = 53
)

type nldHandler struct {
	includeDirection bool
	includeNodes     bool
	ignoreHost       bool

	context *api.ContextOptions

	upstream   *prometheus.CounterVec
	downstream *prometheus.CounterVec
	bypass     *prometheus.CounterVec
}

func (d *nldHandler) Init(registry *prometheus.Registry, options api.Options) error {
	c, err := api.ParseContextOptions(options)
	if err != nil {
		return err
	}
	d.context = c

	for key := range options {
		switch strings.ToLower(key) {
		case "direction":
			d.includeDirection = true
		case "nodes":
			d.includeNodes = true
		case "ignoreHost":
			d.ignoreHost = true
		}
	}

	contextLabels := d.context.GetLabelNames()
	var nodeLabel []string
	if d.includeNodes {
		nodeLabel = []string{"node"}
	}
	var directionLabel []string
	if d.includeDirection {
		directionLabel = []string{"direction"}
	}

	finalLabels := append(append(contextLabels, nodeLabel...), directionLabel...)

	d.downstream = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "nld_downstream_total",
		Help:      "Number of observed DNS queries from workloads to the Node Local DNS Cache",
	}, finalLabels)
	registry.MustRegister(d.downstream)

	d.upstream = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "nld_upstream_total",
		Help:      "Number of observed DNS queries from the Node Local DNS Cache to the upstream",
	}, finalLabels)
	registry.MustRegister(d.upstream)

	d.bypass = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Name:      "nld_bypass_total",
		Help:      "Number of observed DNS queries not going through the Node Local DNS Cache",
	}, finalLabels)
	registry.MustRegister(d.bypass)

	return nil
}

func (d *nldHandler) Status() string {
	var status []string
	if d.includeDirection {
		status = append(status, "includeDirection")
	}
	if d.includeNodes {
		status = append(status, "includeNodes")
	}
	if d.ignoreHost {
		status = append(status, "ignoreHost")
	}

	return strings.Join(append(status, d.context.Status()), ",")
}

func (d *nldHandler) Context() *api.ContextOptions {
	return d.context
}

func (d *nldHandler) ListMetricVec() []*prometheus.MetricVec {
	return []*prometheus.MetricVec{d.upstream.MetricVec, d.downstream.MetricVec, d.bypass.MetricVec}
}

// Is L4 on port 53 & verdict forwarded
// Check for host traffic (drop if applicable)
// Get node name (for labeling)
// Get direction (for labeling)
// IS NLD Source
// IS NLD Dest
// Increment the right metric
func (d *nldHandler) ProcessFlow(ctx context.Context, flow *flowpb.Flow) error {
	if flow.GetVerdict() != flowpb.Verdict_FORWARDED && flow.GetL4() == nil {
		return nil
	}

	isDNSQuery := checkDestinationPort(flow.GetL4())
	isDNSResponse := checkSourcePort(flow.GetL4())
	if !(isDNSQuery || isDNSResponse) {
		return nil
	}

	if d.ignoreHost && isHostTraffic(flow) {
		return nil
	}

	contextLabels, err := d.context.GetLabelValues(flow)
	if err != nil {
		return err
	}

	var nodeLabel []string
	if d.includeNodes {
		nodeLabel = []string{flow.NodeName}
	}

	var directionLabel []string
	if d.includeDirection && isDNSQuery {
		directionLabel = []string{queryLabel}
	}
	if d.includeDirection && isDNSResponse {
		directionLabel = []string{responseLabel}
	}

	finalLabels := append(append(contextLabels, nodeLabel...), directionLabel...)

	srcnld := isNodeLocalDNSPod(flow.Source)
	dstnld := isNodeLocalDNSPod(flow.Destination)

	if srcnld == false && dstnld == false {
		d.bypass.WithLabelValues(finalLabels...).Inc()
	}
	if srcnld == true && dstnld == false {
		if isDNSQuery {
			d.upstream.WithLabelValues(finalLabels...).Inc()
		}
		if isDNSResponse {
			d.downstream.WithLabelValues(finalLabels...).Inc()
		}
	}
	if srcnld == false && dstnld == true {
		if isDNSQuery {
			d.downstream.WithLabelValues(finalLabels...).Inc()
		}
		if isDNSResponse {
			d.upstream.WithLabelValues(finalLabels...).Inc()
		}
	}

	return nil
}

func checkDestinationPort(l4 *flowpb.Layer4) bool {
	if udp := l4.GetUDP(); udp != nil {
		if udp.DestinationPort == dnsPort {
			return true
		}
	}
	if tcp := l4.GetTCP(); tcp != nil {
		if tcp.DestinationPort == dnsPort {
			return true
		}
	}
	return false
}

func checkSourcePort(l4 *flowpb.Layer4) bool {
	if udp := l4.GetUDP(); udp != nil {
		if udp.SourcePort == dnsPort {
			return true
		}
	}
	if tcp := l4.GetTCP(); tcp != nil {
		if tcp.SourcePort == dnsPort {
			return true
		}
	}
	return false
}

func isNodeLocalDNSPod(endpoint *flowpb.Endpoint) bool {
	return endpoint.Namespace == systemNamespace && slices.Contains(endpoint.Labels, nldLabel)
}

func isHostTraffic(flow *flowpb.Flow) bool {
	return slices.Contains(flow.Source.Labels, hostLabel) || slices.Contains(flow.Destination.Labels, hostLabel)
}
