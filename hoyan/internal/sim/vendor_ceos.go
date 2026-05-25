package sim

import (
	"sort"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type ceosBehavior struct{ baseDeviceBehavior }

func NewCEOSBehavior() DeviceBehavior {
	return ceosBehavior{baseDeviceBehavior{kind: model.KindCEOS, decision: ceosDecisionProcess{}}}
}

type ceosDecisionProcess struct{}

func (ceosDecisionProcess) Less(receiver model.Node, a, b RIBEntry) bool {
	return defaultBGPDecisionProcess{}.Less(receiver, a, b)
}

func (ceosDecisionProcess) Equivalent(receiver model.Node, a, b RIBEntry) bool {
	return false
}

func (b ceosBehavior) SelectRoutes(device model.Node, routes []RIBEntry) []RIBEntry {
	out := append([]RIBEntry(nil), routes...)
	sort.Slice(out, func(i, j int) bool {
		return b.DecisionProcess().Less(device, out[i], out[j])
	})
	return out
}
