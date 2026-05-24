package sim

var behaviorRegistry = map[string]DeviceBehavior{
	"frr":     NewFRRBehavior(),
	"ceos":    NewCEOSBehavior(),
	"srlinux": NewSRLinuxBehavior(),
}

func RegisterBehavior(kind string, behavior DeviceBehavior) {
	behaviorRegistry[kind] = behavior
}

func behaviorFor(kind string) DeviceBehavior {
	if b, ok := behaviorRegistry[kind]; ok {
		return b
	}
	return NewGenericBehavior(kind)
}
