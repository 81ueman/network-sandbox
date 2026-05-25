package model

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
)

type ParsedConfig struct {
	Hostname       string
	ASN            uint32
	RouterID       string
	Loopback       string
	Interfaces     []Interface
	Prefixes       []string
	Neighbors      []BGPNeighbor
	PrefixLists    []PrefixList
	ASPathLists    []ASPathList
	CommunityLists []CommunityList
	RoutePolicies  []RoutePolicy
}

func ParseConfig(kind DeviceKind, path string) (ParsedConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ParsedConfig{}, err
	}
	switch kind {
	case KindFRR, KindCEOS:
		return parseFRRLike(kind, string(data))
	case KindSRLinux:
		return parseSRLinux(string(data))
	default:
		return ParsedConfig{}, fmt.Errorf("unsupported config kind %q", kind)
	}
}

func parseFRRLike(kind DeviceKind, text string) (ParsedConfig, error) {
	// TODO: parse cEOS route-map syntax separately. cEOS currently reuses the
	// FRR-like parser only for interfaces, BGP neighbors, and prefixes.
	var cfg ParsedConfig
	neighbors := map[string]*BGPNeighbor{}
	prefixLists := map[string]*PrefixList{}
	asPathLists := map[string]*ASPathList{}
	communityLists := map[string]*CommunityList{}
	routePolicies := map[string]*RoutePolicy{}
	var currentInterface string
	var currentRoutePolicy *RoutePolicy
	var currentRouteRule *RoutePolicyRule
	inBGP := false
	inAF := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(line, "route-map ") {
			currentRoutePolicy = nil
			currentRouteRule = nil
		}
		if line == "" || line == "!" {
			if line == "!" && !strings.HasPrefix(raw, " ") {
				currentInterface = ""
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case fields[0] == "hostname" && len(fields) >= 2:
			cfg.Hostname = fields[1]
		case kind == KindFRR && len(fields) >= 5 && fields[0] == "ip" && fields[1] == "prefix-list" && (fields[3] == "permit" || fields[3] == "deny"):
			rule, err := parsePrefixListRule(0, fields[3], fields[4], fields[5:])
			if err != nil {
				return ParsedConfig{}, fmt.Errorf("%s: %w", line, err)
			}
			addPrefixListRule(prefixLists, fields[2], rule)
		case kind == KindFRR && len(fields) >= 7 && fields[0] == "ip" && fields[1] == "prefix-list" && fields[3] == "seq" && (fields[5] == "permit" || fields[5] == "deny"):
			seq, err := strconv.Atoi(fields[4])
			if err != nil {
				return ParsedConfig{}, err
			}
			rule, err := parsePrefixListRule(seq, fields[5], fields[6], fields[7:])
			if err != nil {
				return ParsedConfig{}, fmt.Errorf("%s: %w", line, err)
			}
			addPrefixListRule(prefixLists, fields[2], rule)
		case kind == KindFRR && len(fields) >= 6 && fields[0] == "bgp" && fields[1] == "as-path" && fields[2] == "access-list" && (fields[4] == "permit" || fields[4] == "deny"):
			addStringListRule(asPathLists, fields[3], StringListRule{Action: fields[4], Pattern: strings.Join(fields[5:], " ")})
		case kind == KindFRR && len(fields) >= 6 && fields[0] == "bgp" && fields[1] == "community-list" && fields[2] == "standard" && (fields[4] == "permit" || fields[4] == "deny"):
			addCommunityListRule(communityLists, fields[3], StringListRule{Action: fields[4], Pattern: strings.Join(fields[5:], " ")})
		case kind == KindFRR && len(fields) >= 4 && fields[0] == "route-map" && (fields[2] == "permit" || fields[2] == "deny"):
			seq := 0
			if len(fields) >= 4 {
				var err error
				seq, err = strconv.Atoi(fields[3])
				if err != nil {
					return ParsedConfig{}, err
				}
			}
			currentRoutePolicy, currentRouteRule = addRoutePolicyRule(routePolicies, fields[1], fields[2], seq)
			currentInterface = ""
			inBGP = false
			inAF = false
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 5 && fields[0] == "match" && fields[1] == "ip" && fields[2] == "address" && fields[3] == "prefix-list":
			currentRouteRule.MatchPrefixList = fields[4]
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 5 && fields[0] == "match" && fields[1] == "ip" && fields[2] == "next-hop" && fields[3] == "prefix-list":
			currentRouteRule.MatchNextHopPrefixList = fields[4]
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 3 && fields[0] == "match" && fields[1] == "as-path":
			currentRouteRule.MatchASPathList = fields[2]
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 3 && fields[0] == "match" && fields[1] == "community":
			currentRouteRule.MatchCommunityList = fields[2]
			if len(fields) >= 4 {
				switch fields[3] {
				case "exact-match":
					currentRouteRule.MatchCommunityExact = true
				case "any":
				default:
					return ParsedConfig{}, fmt.Errorf("unsupported FRR route-map match statement %q", line)
				}
			}
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 1 && fields[0] == "match":
			return ParsedConfig{}, fmt.Errorf("unsupported FRR route-map match statement %q", line)
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 3 && fields[0] == "set" && fields[1] == "local-preference":
			v, delta, err := parseRouteMapInt(fields[2])
			if err != nil {
				return ParsedConfig{}, err
			}
			if delta {
				currentRouteRule.SetLocalPrefDelta = intPtr(v)
			} else {
				currentRouteRule.SetLocalPref = intPtr(v)
			}
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 3 && fields[0] == "set" && fields[1] == "metric":
			v, delta, err := parseRouteMapInt(fields[2])
			if err != nil {
				return ParsedConfig{}, err
			}
			if delta {
				currentRouteRule.SetMEDDelta = intPtr(v)
			} else {
				currentRouteRule.SetMED = intPtr(v)
			}
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 4 && fields[0] == "set" && fields[1] == "as-path" && fields[2] == "prepend":
			path, err := parseASPathFields(fields[3:])
			if err != nil {
				return ParsedConfig{}, err
			}
			currentRouteRule.SetASPathPrepend = path
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 3 && fields[0] == "set" && fields[1] == "community":
			communities := append([]string(nil), fields[2:]...)
			if len(communities) > 0 && communities[len(communities)-1] == "additive" {
				currentRouteRule.SetCommunityAdditive = true
				communities = communities[:len(communities)-1]
			}
			currentRouteRule.SetCommunities = communities
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 3 && fields[0] == "set" && fields[1] == "origin":
			switch fields[2] {
			case "igp", "egp", "incomplete":
				currentRouteRule.SetOriginCode = fields[2]
			default:
				return ParsedConfig{}, fmt.Errorf("unsupported FRR route-map origin %q", line)
			}
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 1 && (fields[0] == "set" || fields[0] == "call" || fields[0] == "continue" || fields[0] == "on-match"):
			return ParsedConfig{}, fmt.Errorf("unsupported FRR route-map statement %q", line)
		case kind == KindFRR && currentRoutePolicy != nil:
			// TODO: support more FRR route-map statements as the lab needs them.
		case fields[0] == "interface" && len(fields) >= 2:
			currentInterface = fields[1]
			inBGP = false
			inAF = false
		case currentInterface != "" && len(fields) >= 3 && fields[0] == "ip" && fields[1] == "address":
			addr := fields[2]
			cfg.Interfaces = upsertInterface(cfg.Interfaces, Interface{Name: currentInterface, Address: addr})
			if strings.EqualFold(currentInterface, "lo") || strings.HasPrefix(strings.ToLower(currentInterface), "loopback") {
				cfg.Loopback = addr
			}
		case len(fields) >= 4 && fields[0] == "ip" && fields[1] == "route" && strings.EqualFold(fields[3], "Null0"):
			cfg.Prefixes = appendUnique(cfg.Prefixes, fields[2])
		case len(fields) >= 3 && fields[0] == "router" && fields[1] == "bgp":
			asn, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil {
				return ParsedConfig{}, err
			}
			cfg.ASN = uint32(asn)
			inBGP = true
			inAF = false
			currentInterface = ""
		case inBGP && len(fields) >= 3 && (fields[0] == "bgp" || fields[0] == "router-id") && fields[len(fields)-2] == "router-id":
			cfg.RouterID = fields[len(fields)-1]
		case inBGP && len(fields) >= 2 && fields[0] == "router-id":
			cfg.RouterID = fields[1]
		case inBGP && len(fields) >= 2 && fields[0] == "address-family":
			inAF = true
		case inBGP && fields[0] == "exit-address-family":
			inAF = false
		case inBGP && len(fields) >= 4 && fields[0] == "neighbor" && fields[2] == "remote-as":
			asn, err := strconv.ParseUint(fields[3], 10, 32)
			if err != nil {
				return ParsedConfig{}, err
			}
			n := getNeighbor(neighbors, fields[1])
			n.RemoteAS = uint32(asn)
		case inBGP && inAF && len(fields) >= 3 && fields[0] == "network":
			cfg.Prefixes = appendUnique(cfg.Prefixes, fields[1])
		case inBGP && inAF && len(fields) >= 3 && fields[0] == "neighbor" && fields[2] == "activate":
			getNeighbor(neighbors, fields[1]).Activated = true
		case inBGP && inAF && len(fields) >= 3 && fields[0] == "neighbor" && fields[2] == "next-hop-self":
			getNeighbor(neighbors, fields[1]).NextHopSelf = true
		case kind == KindFRR && inBGP && inAF && len(fields) >= 5 && fields[0] == "neighbor" && fields[2] == "route-map":
			n := getNeighbor(neighbors, fields[1])
			switch fields[4] {
			case "in":
				n.ImportPolicy = fields[3]
			case "out":
				n.ExportPolicy = fields[3]
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return ParsedConfig{}, err
	}
	for _, n := range neighbors {
		if n.Activated || kind == KindSRLinux {
			cfg.Neighbors = append(cfg.Neighbors, *n)
		}
	}
	cfg.PrefixLists = sortedPrefixLists(prefixLists)
	cfg.ASPathLists = sortedASPathLists(asPathLists)
	cfg.CommunityLists = sortedCommunityLists(communityLists)
	cfg.RoutePolicies = sortedRoutePolicies(routePolicies)
	if cfg.Loopback == "" && cfg.RouterID != "" {
		cfg.Loopback = cfg.RouterID + "/32"
	}
	return cfg, nil
}

func parseSRLinux(text string) (ParsedConfig, error) {
	// TODO: parse SR Linux routing-policy and BGP import/export policy once
	// live lab configs use them.
	var cfg ParsedConfig
	groupAS := map[string]uint32{}
	neighborGroup := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "set" {
			continue
		}
		switch {
		case containsSeq(fields, "system", "name", "host-name") && len(fields) > 0:
			cfg.Hostname = fields[len(fields)-1]
		case containsSeq(fields, "interface") && containsSeq(fields, "ipv4", "address") && len(fields) > 0:
			iface := fieldAfter(fields, "interface")
			addr := fields[len(fields)-1]
			cfg.Interfaces = upsertInterface(cfg.Interfaces, Interface{Name: iface, Address: addr})
		case containsSeq(fields, "protocols", "bgp", "autonomous-system") && len(fields) > 0:
			asn, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
			if err != nil {
				return ParsedConfig{}, err
			}
			cfg.ASN = uint32(asn)
		case containsSeq(fields, "protocols", "bgp", "router-id") && len(fields) > 0:
			cfg.RouterID = fields[len(fields)-1]
			cfg.Loopback = cfg.RouterID + "/32"
		case containsSeq(fields, "protocols", "bgp", "group") && containsSeq(fields, "peer-as"):
			group := fieldAfter(fields, "group")
			asn, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
			if err != nil {
				return ParsedConfig{}, err
			}
			groupAS[group] = uint32(asn)
		case containsSeq(fields, "protocols", "bgp", "neighbor") && containsSeq(fields, "peer-group"):
			addr := fieldAfter(fields, "neighbor")
			neighborGroup[addr] = fields[len(fields)-1]
		}
	}
	if err := scanner.Err(); err != nil {
		return ParsedConfig{}, err
	}
	for addr, group := range neighborGroup {
		cfg.Neighbors = append(cfg.Neighbors, BGPNeighbor{Address: addr, RemoteAS: groupAS[group], Activated: true})
	}
	return cfg, nil
}

func getNeighbor(neighbors map[string]*BGPNeighbor, addr string) *BGPNeighbor {
	if neighbors[addr] == nil {
		neighbors[addr] = &BGPNeighbor{Address: addr}
	}
	return neighbors[addr]
}

func parsePrefixListRule(seq int, action, prefix string, fields []string) (PrefixListRule, error) {
	rule := PrefixListRule{Seq: seq, Action: action, Prefix: prefix}
	for i := 0; i < len(fields); i += 2 {
		if i+1 >= len(fields) {
			return PrefixListRule{}, fmt.Errorf("invalid prefix-list range")
		}
		v, err := strconv.Atoi(fields[i+1])
		if err != nil {
			return PrefixListRule{}, err
		}
		switch fields[i] {
		case "ge":
			rule.Ge = v
		case "le":
			rule.Le = v
		default:
			return PrefixListRule{}, fmt.Errorf("unsupported prefix-list option %q", fields[i])
		}
	}
	return rule, nil
}

func parseRouteMapInt(raw string) (int, bool, error) {
	delta := strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-")
	v, err := strconv.Atoi(raw)
	return v, delta, err
}

func parseASPathFields(fields []string) ([]uint32, error) {
	var out []uint32
	for _, field := range fields {
		asn, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return nil, err
		}
		out = append(out, uint32(asn))
	}
	return out, nil
}

func addPrefixListRule(prefixLists map[string]*PrefixList, name string, rule PrefixListRule) {
	if prefixLists[name] == nil {
		prefixLists[name] = &PrefixList{Name: name}
	}
	prefixLists[name].Rules = append(prefixLists[name].Rules, rule)
}

func addStringListRule(asPathLists map[string]*ASPathList, name string, rule StringListRule) {
	if asPathLists[name] == nil {
		asPathLists[name] = &ASPathList{Name: name}
	}
	asPathLists[name].Rules = append(asPathLists[name].Rules, rule)
}

func addCommunityListRule(communityLists map[string]*CommunityList, name string, rule StringListRule) {
	if communityLists[name] == nil {
		communityLists[name] = &CommunityList{Name: name}
	}
	communityLists[name].Rules = append(communityLists[name].Rules, rule)
}

func addRoutePolicyRule(routePolicies map[string]*RoutePolicy, name string, action string, seq int) (*RoutePolicy, *RoutePolicyRule) {
	if routePolicies[name] == nil {
		routePolicies[name] = &RoutePolicy{Name: name}
	}
	routePolicies[name].Rules = append(routePolicies[name].Rules, RoutePolicyRule{Seq: seq, Action: action})
	policy := routePolicies[name]
	return policy, &policy.Rules[len(policy.Rules)-1]
}

func sortedPrefixLists(prefixLists map[string]*PrefixList) []PrefixList {
	var out []PrefixList
	for _, prefixList := range prefixLists {
		cp := *prefixList
		cp.Rules = append([]PrefixListRule(nil), prefixList.Rules...)
		sort.Slice(cp.Rules, func(i, j int) bool {
			return cp.Rules[i].Seq < cp.Rules[j].Seq
		})
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedASPathLists(asPathLists map[string]*ASPathList) []ASPathList {
	var out []ASPathList
	for _, list := range asPathLists {
		cp := *list
		cp.Rules = append([]StringListRule(nil), list.Rules...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedCommunityLists(communityLists map[string]*CommunityList) []CommunityList {
	var out []CommunityList
	for _, list := range communityLists {
		cp := *list
		cp.Rules = append([]StringListRule(nil), list.Rules...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedRoutePolicies(routePolicies map[string]*RoutePolicy) []RoutePolicy {
	var out []RoutePolicy
	for _, routePolicy := range routePolicies {
		cp := *routePolicy
		cp.Rules = append([]RoutePolicyRule(nil), routePolicy.Rules...)
		sort.Slice(cp.Rules, func(i, j int) bool {
			return cp.Rules[i].Seq < cp.Rules[j].Seq
		})
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

func intPtr(v int) *int {
	return &v
}

func upsertInterface(xs []Interface, iface Interface) []Interface {
	for i := range xs {
		if xs[i].Name == iface.Name {
			xs[i] = iface
			return xs
		}
	}
	return append(xs, iface)
}

func appendUnique(xs []string, x string) []string {
	for _, existing := range xs {
		if existing == x {
			return xs
		}
	}
	return append(xs, x)
}

func containsSeq(fields []string, seq ...string) bool {
	pos := 0
	for _, f := range fields {
		if f == seq[pos] {
			pos++
			if pos == len(seq) {
				return true
			}
		}
	}
	return false
}

func fieldAfter(fields []string, marker string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == marker {
			return strings.Trim(fields[i+1], "[]")
		}
	}
	return ""
}

func interfaceAddr(interfaces []Interface, name string) (netip.Prefix, bool) {
	names := map[string]bool{name: true}
	if strings.HasPrefix(name, "e1-") {
		names["ethernet-1/"+strings.TrimPrefix(name, "e1-")] = true
	}
	if strings.HasPrefix(name, "eth") {
		names["Ethernet"+strings.TrimPrefix(name, "eth")] = true
	}
	for _, iface := range interfaces {
		if !names[iface.Name] {
			continue
		}
		pfx, err := netip.ParsePrefix(iface.Address)
		return pfx, err == nil
	}
	return netip.Prefix{}, false
}
