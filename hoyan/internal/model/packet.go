package model

import "fmt"

type PortSet interface {
	Contains(port int) bool
	Overlaps(other PortSet) bool
	String() string
}

type AnyPortSet struct{}

func (AnyPortSet) Contains(port int) bool {
	return port > 0 && port <= 65535
}

func (AnyPortSet) Overlaps(other PortSet) bool {
	return other != nil
}

func (AnyPortSet) String() string {
	return "any"
}

type ExactPortSet struct {
	Port int
}

func (s ExactPortSet) Contains(port int) bool {
	return s.Port == port
}

func (s ExactPortSet) Overlaps(other PortSet) bool {
	if other == nil {
		return false
	}
	return other.Contains(s.Port)
}

func (s ExactPortSet) String() string {
	if s.Port <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", s.Port)
}

type PortRangeSet struct {
	Min int
	Max int
}

func (s PortRangeSet) Contains(port int) bool {
	return s.Min <= port && port <= s.Max
}

func (s PortRangeSet) Overlaps(other PortSet) bool {
	if other == nil {
		return false
	}
	for port := s.Min; port <= s.Max; port++ {
		if other.Contains(port) {
			return true
		}
	}
	return false
}

func (s PortRangeSet) String() string {
	return fmt.Sprintf("%d-%d", s.Min, s.Max)
}

func NormalizePortSet(set PortSet) PortSet {
	if set == nil {
		return AnyPortSet{}
	}
	return set
}

func ExactPort(port int) PortSet {
	if port <= 0 {
		return nil
	}
	return ExactPortSet{Port: port}
}

type PacketSpec struct {
	SrcSet           PrefixSet
	DstSet           PrefixSet
	Protocol         string
	SrcPort          PortSet
	DstPort          PortSet
	IngressInterface string
	EgressInterface  string
}

func (s PacketSpec) WithNormalizedPorts() PacketSpec {
	s.SrcPort = NormalizePortSet(s.SrcPort)
	s.DstPort = NormalizePortSet(s.DstPort)
	return s
}
