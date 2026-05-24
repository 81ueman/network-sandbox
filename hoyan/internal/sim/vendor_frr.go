package sim

type frrBehavior struct{ baseDeviceBehavior }

func NewFRRBehavior() DeviceBehavior {
	return frrBehavior{baseDeviceBehavior{kind: "frr", decision: DefaultBGPDecisionProcess()}}
}
