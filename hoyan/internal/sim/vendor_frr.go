package sim

type frrBehavior struct{ baseBGPBehavior }

func NewFRRBehavior() DeviceBehavior {
	return frrBehavior{baseBGPBehavior{kind: "frr", decision: DefaultBGPDecisionProcess()}}
}
