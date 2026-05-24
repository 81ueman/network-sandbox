package sim

import (
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type BGPDecisionProcess interface {
	Less(receiver model.Node, a, b RIBEntry) bool
	Equivalent(receiver model.Node, a, b RIBEntry) bool
}

type defaultBGPDecisionProcess struct{}

func DefaultBGPDecisionProcess() BGPDecisionProcess {
	return defaultBGPDecisionProcess{}
}

func (defaultBGPDecisionProcess) Less(receiver model.Node, a, b RIBEntry) bool {
	if a.LocalPref != b.LocalPref {
		return a.LocalPref > b.LocalPref
	}
	if a.Origin == receiver.Name || b.Origin == receiver.Name {
		return a.Origin == receiver.Name
	}
	if len(a.ASPath) != len(b.ASPath) {
		return len(a.ASPath) < len(b.ASPath)
	}
	if a.MED != b.MED {
		return a.MED < b.MED
	}
	aExternal := firstHopExternal(receiver.ASN, a.ASPath)
	bExternal := firstHopExternal(receiver.ASN, b.ASPath)
	if aExternal != bExternal {
		return aExternal
	}
	if len(a.Links) != len(b.Links) {
		return len(a.Links) < len(b.Links)
	}
	return strings.Join(a.Nodes, ",") < strings.Join(b.Nodes, ",")
}

func (defaultBGPDecisionProcess) Equivalent(receiver model.Node, a, b RIBEntry) bool {
	if a.LocalPref != b.LocalPref {
		return false
	}
	if (a.Origin == receiver.Name) != (b.Origin == receiver.Name) {
		return false
	}
	if len(a.ASPath) != len(b.ASPath) {
		return false
	}
	if a.MED != b.MED {
		return false
	}
	return firstHopExternal(receiver.ASN, a.ASPath) == firstHopExternal(receiver.ASN, b.ASPath)
}

func firstHopExternal(localASN uint32, path []uint32) bool {
	if len(path) == 0 {
		return false
	}
	return path[0] != localASN
}
