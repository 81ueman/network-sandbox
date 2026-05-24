package sim

type srlinuxBehavior struct{ baseDeviceBehavior }

func NewSRLinuxBehavior() DeviceBehavior {
	return srlinuxBehavior{baseDeviceBehavior{kind: "srlinux", decision: DefaultBGPDecisionProcess()}}
}
