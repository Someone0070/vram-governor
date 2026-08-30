package nodeagent

import (
	"net"
	"testing"
)

func TestSystemSamplerAlwaysReportsStaticHostIdentity(t *testing.T) {
	sampler := &SystemSampler{}
	first := sampler.Sample()
	second := sampler.Sample()
	if first.Architecture == "" || first.CPULogical <= 0 || first.SampledAt.IsZero() || second.SampledAt.Before(first.SampledAt) {
		t.Fatalf("invalid system samples: first=%+v second=%+v", first, second)
	}
	for _, raw := range first.NetworkAddresses {
		ip := net.ParseIP(raw)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			t.Fatalf("invalid reported network address %q", raw)
		}
	}
}
