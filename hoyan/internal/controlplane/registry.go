package controlplane

import (
	"sync"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

var behaviorRegistry = map[model.DeviceKind]DeviceBehavior{
	model.KindFRR:     NewFRRBehavior(),
	model.KindCEOS:    NewCEOSBehavior(),
	model.KindSRLinux: NewSRLinuxBehavior(),
}

var behaviorRegistryMu sync.RWMutex

func RegisterBehavior(kind model.DeviceKind, behavior DeviceBehavior) func() {
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

func BehaviorFor(kind model.DeviceKind) DeviceBehavior {
	return behaviorFor(kind)
}

func behaviorFor(kind model.DeviceKind) DeviceBehavior {
	behaviorRegistryMu.RLock()
	b, ok := behaviorRegistry[kind]
	behaviorRegistryMu.RUnlock()
	if ok {
		return b
	}
	return NewGenericBehavior(kind)
}
