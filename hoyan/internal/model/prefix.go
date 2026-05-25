package model

import (
	"fmt"
	"net/netip"
)

type Prefix struct {
	pfx netip.Prefix
}

func ParsePrefix(raw string) (Prefix, error) {
	pfx, err := netip.ParsePrefix(raw)
	if err != nil {
		return Prefix{}, err
	}
	return Prefix{pfx: pfx.Masked()}, nil
}

func MustPrefix(raw string) Prefix {
	pfx, err := ParsePrefix(raw)
	if err != nil {
		panic(err)
	}
	return pfx
}

func MustPrefixes(raw ...string) []Prefix {
	out := make([]Prefix, 0, len(raw))
	for _, p := range raw {
		out = append(out, MustPrefix(p))
	}
	return out
}

func PrefixFromNetIP(pfx netip.Prefix) Prefix {
	return Prefix{pfx: pfx.Masked()}
}

func (p Prefix) NetIP() netip.Prefix {
	return p.pfx
}

func (p Prefix) Addr() netip.Addr {
	return p.pfx.Addr()
}

func (p Prefix) Bits() int {
	return p.pfx.Bits()
}

func (p Prefix) Contains(addr netip.Addr) bool {
	return p.pfx.Contains(addr)
}

func (p Prefix) Overlaps(other Prefix) bool {
	return p.Contains(other.Addr()) || other.Contains(p.Addr())
}

func (p Prefix) Equal(other Prefix) bool {
	return p.pfx == other.pfx
}

func (p Prefix) IsZero() bool {
	return !p.pfx.IsValid()
}

func (p Prefix) String() string {
	if p.IsZero() {
		return ""
	}
	return p.pfx.String()
}

func (p *Prefix) UnmarshalYAML(unmarshal func(any) error) error {
	var raw string
	if err := unmarshal(&raw); err != nil {
		return err
	}
	if raw == "" {
		*p = Prefix{}
		return nil
	}
	parsed, err := ParsePrefix(raw)
	if err != nil {
		return fmt.Errorf("prefix %s: %w", raw, err)
	}
	*p = parsed
	return nil
}

func (p Prefix) MarshalYAML() (any, error) {
	return p.String(), nil
}
