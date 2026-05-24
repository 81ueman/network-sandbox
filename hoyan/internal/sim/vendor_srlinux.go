package sim

type srlinuxBehavior struct{ baseBGPBehavior }

func NewSRLinuxBehavior() DeviceBehavior {
	return srlinuxBehavior{baseBGPBehavior{kind: "srlinux", decision: DefaultBGPDecisionProcess()}}
}
