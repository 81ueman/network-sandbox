package sim

import "sync"

var behaviorRegistry = map[string]DeviceBehavior{
	"frr":     NewFRRBehavior(),
	"ceos":    NewCEOSBehavior(),
	"srlinux": NewSRLinuxBehavior(),
}

var behaviorRegistryMu sync.RWMutex

func RegisterBehavior(kind string, behavior DeviceBehavior) func() {
	behaviorRegistryMu.Lock()
	defer behaviorRegistryMu.Unlock()
	old, hadOld := behaviorRegistry[kind]
	behaviorRegistry[kind] = behavior
	return func() {
		behaviorRegistryMu.Lock()
		defer behaviorRegistryMu.Unlock()
		if hadOld {
			behaviorRegistry[kind] = old
			return
		}
		delete(behaviorRegistry, kind)
	}
}

func BehaviorFor(kind string) DeviceBehavior {
	return behaviorFor(kind)
}

func behaviorFor(kind string) DeviceBehavior {
	behaviorRegistryMu.RLock()
	b, ok := behaviorRegistry[kind]
	behaviorRegistryMu.RUnlock()
	if ok {
		return b
	}
	return NewGenericBehavior(kind)
}
