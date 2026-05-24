package sim

import (
	"sort"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type ceosBehavior struct{ baseDeviceBehavior }

func NewCEOSBehavior() DeviceBehavior {
	return ceosBehavior{baseDeviceBehavior{kind: "ceos", decision: DefaultBGPDecisionProcess()}}
}

func (b ceosBehavior) SelectRoutes(device model.Node, routes []RIBEntry) []RIBEntry {
	out := make([]RIBEntry, 0, len(routes))
	for _, route := range routes {
		if route.NextHop != "" && route.NextHop != route.From {
			continue
		}
		out = append(out, route)
	}
	sort.Slice(out, func(i, j int) bool {
		return b.DecisionProcess().Less(device, out[i], out[j])
	})
	return out
}
