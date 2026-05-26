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
	Routes         []ConfiguredRoute
	Redistribute   []BGPRedistribution
	Neighbors      []BGPNeighbor
	PrefixLists    []PrefixList
	ASPathLists    []ASPathList
	CommunityLists []CommunityList
	RoutePolicies  []RoutePolicy
	Policies       []Policy
}

type ParseResult struct {
	Config   ParsedConfig
	Warnings []UnsupportedStatement
}

type UnsupportedStatement struct {
	Vendor string
	File   string
	Line   int
	Text   string
	Reason string
}

type UnsupportedConfigError struct {
	Warnings []UnsupportedStatement
}

type aclBinding struct {
	Name      string
	Interface string
	Stage     string
}

func (w UnsupportedStatement) String() string {
	loc := w.File
	if w.Line > 0 {
		loc = fmt.Sprintf("%s:%d", loc, w.Line)
	}
	if loc == "" {
		loc = w.Vendor
	}
	return fmt.Sprintf("%s: %s: %s", loc, w.Reason, w.Text)
}

func (e UnsupportedConfigError) Error() string {
	if len(e.Warnings) == 0 {
		return "unsupported config statements"
	}
	lines := make([]string, 0, len(e.Warnings)+1)
	lines = append(lines, fmt.Sprintf("unsupported config statements: %d", len(e.Warnings)))
	for _, warning := range e.Warnings {
		lines = append(lines, fmt.Sprintf("vendor=%s file=%s line=%d raw=%q reason=%s", warning.Vendor, warning.File, warning.Line, warning.Text, warning.Reason))
	}
	return strings.Join(lines, "\n")
}

func ParseConfig(kind DeviceKind, path string) (ParsedConfig, error) {
	result, err := parseConfig(kind, path, false)
	return result.Config, err
}

func ParseConfigWithWarnings(kind DeviceKind, path string) (ParseResult, error) {
	return parseConfig(kind, path, true)
}

func ParseNftablesConfig(path string) ([]Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseNftables(path, string(data))
}

func parseConfig(kind DeviceKind, path string, collectWarnings bool) (ParseResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ParseResult{}, err
	}
	switch kind {
	case KindFRR, KindCEOS:
		return parseFRRLike(kind, path, string(data), collectWarnings)
	case KindSRLinux:
		return parseSRLinux(path, string(data), collectWarnings)
	default:
		return ParseResult{}, fmt.Errorf("unsupported config kind %q", kind)
	}
}

func parseFRRLike(kind DeviceKind, path, text string, collectWarnings bool) (ParseResult, error) {
	var cfg ParsedConfig
	var warnings []UnsupportedStatement
	neighbors := map[string]*BGPNeighbor{}
	prefixLists := map[string]*PrefixList{}
	asPathLists := map[string]*ASPathList{}
	communityLists := map[string]*CommunityList{}
	routePolicies := map[string]*RoutePolicy{}
	aclPolicies := map[string][]Policy{}
	var aclBindings []aclBinding
	var currentInterface string
	var currentACL string
	var currentRoutePolicy *RoutePolicy
	var currentRouteRule *RoutePolicyRule
	inBGP := false
	inAF := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(line, "route-map ") {
			currentRoutePolicy = nil
			currentRouteRule = nil
			if !strings.HasPrefix(line, "ip access-list ") {
				currentACL = ""
			}
		}
		if line == "" || line == "!" {
			if line == "!" && !strings.HasPrefix(raw, " ") {
				currentInterface = ""
				currentACL = ""
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
		case len(fields) >= 3 && fields[0] == "ip" && fields[1] == "access-list":
			currentACL = fields[2]
			if len(fields) >= 4 && (fields[2] == "standard" || fields[2] == "extended") {
				currentACL = fields[3]
			}
			currentInterface = ""
			inBGP = false
			inAF = false
		case currentACL != "" && isACLRuleLine(fields):
			pol, ok, err := parseACLRule(kind, path, lineNo, line, currentACL, fields)
			if err != nil {
				if !collectWarnings {
					return ParseResult{}, err
				}
				warnings = append(warnings, unsupportedStatement(string(kind), path, lineNo, line, err.Error()))
				continue
			}
			if ok {
				aclPolicies[currentACL] = append(aclPolicies[currentACL], pol)
			}
		case kind == KindFRR && len(fields) >= 5 && fields[0] == "access-list" && (fields[2] == "permit" || fields[2] == "deny"):
			pol, ok, err := parseACLRule(kind, path, lineNo, line, fields[1], fields[2:])
			if err != nil {
				if !collectWarnings {
					return ParseResult{}, err
				}
				warnings = append(warnings, unsupportedStatement(string(kind), path, lineNo, line, err.Error()))
				continue
			}
			if ok {
				aclPolicies[fields[1]] = append(aclPolicies[fields[1]], pol)
			}
		case isRouteMapPolicyKind(kind) && len(fields) >= 5 && fields[0] == "ip" && fields[1] == "prefix-list" && (fields[3] == "permit" || fields[3] == "deny"):
			rule, err := parsePrefixListRule(0, fields[3], fields[4], fields[5:])
			if err != nil {
				return ParseResult{}, fmt.Errorf("%s: %w", line, err)
			}
			addPrefixListRule(prefixLists, fields[2], rule)
		case isRouteMapPolicyKind(kind) && len(fields) >= 7 && fields[0] == "ip" && fields[1] == "prefix-list" && fields[3] == "seq" && (fields[5] == "permit" || fields[5] == "deny"):
			seq, err := strconv.Atoi(fields[4])
			if err != nil {
				return ParseResult{}, err
			}
			rule, err := parsePrefixListRule(seq, fields[5], fields[6], fields[7:])
			if err != nil {
				return ParseResult{}, fmt.Errorf("%s: %w", line, err)
			}
			addPrefixListRule(prefixLists, fields[2], rule)
		case kind == KindFRR && len(fields) >= 6 && fields[0] == "bgp" && fields[1] == "as-path" && fields[2] == "access-list" && (fields[4] == "permit" || fields[4] == "deny"):
			addStringListRule(asPathLists, fields[3], StringListRule{Action: fields[4], Pattern: strings.Join(fields[5:], " ")})
		case kind == KindFRR && len(fields) >= 6 && fields[0] == "bgp" && fields[1] == "community-list" && fields[2] == "standard" && (fields[4] == "permit" || fields[4] == "deny"):
			addCommunityListRule(communityLists, fields[3], StringListRule{Action: fields[4], Pattern: strings.Join(fields[5:], " ")})
		case isRouteMapPolicyKind(kind) && len(fields) >= 4 && fields[0] == "route-map" && (fields[2] == "permit" || fields[2] == "deny"):
			seq := 0
			if len(fields) >= 4 {
				var err error
				seq, err = strconv.Atoi(fields[3])
				if err != nil {
					return ParseResult{}, err
				}
			}
			currentRoutePolicy, currentRouteRule = addRoutePolicyRule(routePolicies, fields[1], fields[2], seq)
			currentInterface = ""
			inBGP = false
			inAF = false
		case isRouteMapPolicyKind(kind) && currentRouteRule != nil && len(fields) >= 5 && fields[0] == "match" && fields[1] == "ip" && fields[2] == "address" && fields[3] == "prefix-list":
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
					if !collectWarnings {
						return ParseResult{}, fmt.Errorf("unsupported FRR route-map match statement %q", line)
					}
					warnings = append(warnings, unsupportedStatement(string(kind), path, lineNo, line, "unsupported FRR route-map match statement"))
				}
			}
		case isRouteMapPolicyKind(kind) && currentRouteRule != nil && len(fields) >= 1 && fields[0] == "match":
			if !collectWarnings {
				return ParseResult{}, fmt.Errorf("unsupported %s route-map match statement %q", routeMapVendorName(kind), line)
			}
			warnings = append(warnings, unsupportedStatement(string(kind), path, lineNo, line, fmt.Sprintf("unsupported %s route-map match statement", routeMapVendorName(kind))))
		case isRouteMapPolicyKind(kind) && currentRouteRule != nil && len(fields) >= 3 && fields[0] == "set" && fields[1] == "local-preference":
			v, delta, err := parseRouteMapInt(fields[2])
			if err != nil {
				return ParseResult{}, err
			}
			if delta {
				currentRouteRule.SetLocalPrefDelta = intPtr(v)
			} else {
				currentRouteRule.SetLocalPref = intPtr(v)
			}
		case isRouteMapPolicyKind(kind) && currentRouteRule != nil && len(fields) >= 3 && fields[0] == "set" && fields[1] == "metric":
			v, delta, err := parseRouteMapInt(fields[2])
			if err != nil {
				return ParseResult{}, err
			}
			if delta {
				currentRouteRule.SetMEDDelta = intPtr(v)
			} else {
				currentRouteRule.SetMED = intPtr(v)
			}
		case kind == KindFRR && currentRouteRule != nil && len(fields) >= 4 && fields[0] == "set" && fields[1] == "as-path" && fields[2] == "prepend":
			path, err := parseASPathFields(fields[3:])
			if err != nil {
				return ParseResult{}, err
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
				if !collectWarnings {
					return ParseResult{}, fmt.Errorf("unsupported FRR route-map origin %q", line)
				}
				warnings = append(warnings, unsupportedStatement(string(kind), path, lineNo, line, "unsupported FRR route-map origin"))
			}
		case isRouteMapPolicyKind(kind) && currentRouteRule != nil && len(fields) >= 1 && (fields[0] == "set" || fields[0] == "call" || fields[0] == "continue" || fields[0] == "on-match"):
			if !collectWarnings {
				return ParseResult{}, fmt.Errorf("unsupported %s route-map statement %q", routeMapVendorName(kind), line)
			}
			warnings = append(warnings, unsupportedStatement(string(kind), path, lineNo, line, fmt.Sprintf("unsupported %s route-map statement", routeMapVendorName(kind))))
		case isRouteMapPolicyKind(kind) && currentRoutePolicy != nil:
			if collectWarnings {
				warnings = append(warnings, unsupportedStatement(string(kind), path, lineNo, line, fmt.Sprintf("unsupported %s route-map statement", routeMapVendorName(kind))))
			}
		case fields[0] == "interface" && len(fields) >= 2:
			currentInterface = fields[1]
			currentACL = ""
			inBGP = false
			inAF = false
		case currentInterface != "" && len(fields) >= 3 && fields[0] == "ip" && fields[1] == "address":
			addr := fields[2]
			cfg.Interfaces = upsertInterface(cfg.Interfaces, Interface{Name: currentInterface, Address: addr})
			if strings.EqualFold(currentInterface, "lo") || strings.HasPrefix(strings.ToLower(currentInterface), "loopback") {
				cfg.Loopback = addr
			}
		case currentInterface != "" && len(fields) >= 4 && fields[0] == "ip" && fields[1] == "access-group":
			stage, ok := aclStage(fields[3])
			if ok {
				aclBindings = append(aclBindings, aclBinding{Name: fields[2], Interface: currentInterface, Stage: stage})
			}
		case len(fields) >= 4 && fields[0] == "ip" && fields[1] == "route":
			route, err := parseFRRLikeStaticRoute(kind, path, lineNo, line, fields)
			if err != nil {
				if !collectWarnings {
					return ParseResult{}, err
				}
				warnings = append(warnings, unsupportedStatement(string(kind), path, lineNo, line, err.Error()))
				continue
			}
			cfg.Routes = append(cfg.Routes, route)
		case len(fields) >= 3 && fields[0] == "router" && fields[1] == "bgp":
			asn, err := strconv.ParseUint(fields[2], 10, 32)
			if err != nil {
				return ParseResult{}, err
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
				return ParseResult{}, err
			}
			n := getNeighbor(neighbors, fields[1])
			n.RemoteAS = uint32(asn)
		case inBGP && inAF && len(fields) >= 2 && fields[0] == "network":
			cfg.Prefixes = appendUnique(cfg.Prefixes, fields[1])
		case inBGP && inAF && len(fields) >= 2 && fields[0] == "aggregate-address":
			route, err := parseAggregateRoute(kind, path, lineNo, line, fields)
			if err != nil {
				if !collectWarnings {
					return ParseResult{}, err
				}
				warnings = append(warnings, unsupportedStatement(string(kind), path, lineNo, line, err.Error()))
				continue
			}
			cfg.Routes = append(cfg.Routes, route)
		case inBGP && inAF && len(fields) >= 2 && fields[0] == "redistribute":
			redist, err := parseFRRLikeRedistribution(kind, path, lineNo, line, fields)
			if err != nil {
				if !collectWarnings {
					return ParseResult{}, err
				}
				warnings = append(warnings, unsupportedStatement(string(kind), path, lineNo, line, err.Error()))
				continue
			}
			cfg.Redistribute = append(cfg.Redistribute, redist)
		case inBGP && inAF && len(fields) >= 3 && fields[0] == "neighbor" && fields[2] == "activate":
			getNeighbor(neighbors, fields[1]).Activated = true
		case inBGP && inAF && len(fields) >= 3 && fields[0] == "neighbor" && fields[2] == "next-hop-self":
			getNeighbor(neighbors, fields[1]).NextHopSelf = true
		case isRouteMapPolicyKind(kind) && inBGP && inAF && len(fields) >= 5 && fields[0] == "neighbor" && fields[2] == "route-map":
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
		return ParseResult{}, err
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
	cfg.Policies = boundACLPolicies(aclPolicies, aclBindings)
	if cfg.Loopback == "" && cfg.RouterID != "" {
		cfg.Loopback = cfg.RouterID + "/32"
	}
	return ParseResult{Config: cfg, Warnings: warnings}, nil
}

func parseSRLinux(path, text string, collectWarnings bool) (ParseResult, error) {
	var cfg ParsedConfig
	var warnings []UnsupportedStatement
	groupAS := map[string]uint32{}
	groupImportPolicy := map[string]string{}
	groupExportPolicy := map[string]string{}
	groupNextHopSelf := map[string]bool{}
	neighborGroup := map[string]string{}
	neighborImportPolicy := map[string]string{}
	neighborExportPolicy := map[string]string{}
	neighborNextHopSelf := map[string]bool{}
	prefixLists := map[string]*PrefixList{}
	routePolicies := map[string]*RoutePolicy{}
	srlACLs := map[string]map[int]*Policy{}
	var aclBindings []aclBinding
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "set" {
			continue
		}
		switch {
		case containsSeq(fields, "acl", "interface") && containsAnyField(fields, "input", "output") && containsAnyField(fields, "acl-filter"):
			binding, ok := parseSRLinuxACLBinding(fields)
			if ok {
				aclBindings = append(aclBindings, binding)
			}
		case containsSeq(fields, "acl", "acl-filter"):
			if err := parseSRLinuxACL(srlACLs, path, lineNo, line, fields); err != nil {
				if !collectWarnings {
					return ParseResult{}, fmt.Errorf("%s: %w", line, err)
				}
				warnings = append(warnings, unsupportedStatement("srlinux", path, lineNo, line, err.Error()))
			}
		case srLinuxRoutingPolicyKind(fields) == "prefix-set":
			if err := parseSRLinuxPrefixSet(prefixLists, fields); err != nil {
				if !collectWarnings {
					return ParseResult{}, fmt.Errorf("%s: %w", line, err)
				}
				warnings = append(warnings, unsupportedStatement("srlinux", path, lineNo, line, err.Error()))
			}
		case srLinuxRoutingPolicyKind(fields) == "policy":
			if err := parseSRLinuxRoutePolicy(routePolicies, prefixLists, fields); err != nil {
				if !collectWarnings {
					return ParseResult{}, fmt.Errorf("%s: %w", line, err)
				}
				warnings = append(warnings, unsupportedStatement("srlinux", path, lineNo, line, err.Error()))
			}
		case containsSeq(fields, "system", "name", "host-name") && len(fields) > 0:
			cfg.Hostname = fields[len(fields)-1]
		case containsSeq(fields, "interface") && containsSeq(fields, "ipv4", "address") && len(fields) > 0:
			iface := fieldAfter(fields, "interface")
			addr := fields[len(fields)-1]
			cfg.Interfaces = upsertInterface(cfg.Interfaces, Interface{Name: iface, Address: addr})
		case containsSeq(fields, "static-routes", "route"):
			route, err := parseSRLinuxStaticRoute(path, lineNo, line, fields)
			if err != nil {
				if !collectWarnings {
					return ParseResult{}, fmt.Errorf("%s: %w", line, err)
				}
				warnings = append(warnings, unsupportedStatement("srlinux", path, lineNo, line, err.Error()))
				continue
			}
			cfg.Routes = append(cfg.Routes, route)
		case containsSeq(fields, "protocols", "bgp", "autonomous-system") && len(fields) > 0:
			asn, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
			if err != nil {
				return ParseResult{}, err
			}
			cfg.ASN = uint32(asn)
		case containsSeq(fields, "protocols", "bgp", "router-id") && len(fields) > 0:
			cfg.RouterID = fields[len(fields)-1]
			cfg.Loopback = cfg.RouterID + "/32"
		case containsSeq(fields, "protocols", "bgp", "group") && containsSeq(fields, "peer-as"):
			group := fieldAfter(fields, "group")
			asn, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
			if err != nil {
				return ParseResult{}, err
			}
			groupAS[group] = uint32(asn)
		case containsSeq(fields, "protocols", "bgp", "group") && containsAnyField(fields, "import-policy", "export-policy"):
			group := fieldAfter(fields, "group")
			policy, err := parseSRLinuxPolicyBinding(fields)
			if err != nil {
				if !collectWarnings {
					return ParseResult{}, fmt.Errorf("%s: %w", line, err)
				}
				warnings = append(warnings, unsupportedStatement("srlinux", path, lineNo, line, err.Error()))
				continue
			}
			if containsAnyField(fields, "import-policy") {
				groupImportPolicy[group] = policy
			} else {
				groupExportPolicy[group] = policy
			}
		case containsSeq(fields, "protocols", "bgp", "group") && containsSeq(fields, "next-hop-self"):
			group := fieldAfter(fields, "group")
			groupNextHopSelf[group] = true
		case containsSeq(fields, "protocols", "bgp", "neighbor") && containsSeq(fields, "peer-group"):
			addr := fieldAfter(fields, "neighbor")
			neighborGroup[addr] = fields[len(fields)-1]
		case containsSeq(fields, "protocols", "bgp", "neighbor") && containsAnyField(fields, "import-policy", "export-policy"):
			addr := fieldAfter(fields, "neighbor")
			policy, err := parseSRLinuxPolicyBinding(fields)
			if err != nil {
				if !collectWarnings {
					return ParseResult{}, fmt.Errorf("%s: %w", line, err)
				}
				warnings = append(warnings, unsupportedStatement("srlinux", path, lineNo, line, err.Error()))
				continue
			}
			if containsAnyField(fields, "import-policy") {
				neighborImportPolicy[addr] = policy
			} else {
				neighborExportPolicy[addr] = policy
			}
		case containsSeq(fields, "protocols", "bgp", "neighbor") && containsSeq(fields, "next-hop-self"):
			addr := fieldAfter(fields, "neighbor")
			neighborNextHopSelf[addr] = true
		case containsSeq(fields, "protocols", "bgp") && (containsAnyField(fields, "aggregate-address") || containsAnyField(fields, "aggregate-routes")):
			err := fmt.Errorf("unsupported SR Linux BGP aggregate route statement")
			if !collectWarnings {
				return ParseResult{}, fmt.Errorf("%s: %w", line, err)
			}
			warnings = append(warnings, unsupportedStatement("srlinux", path, lineNo, line, err.Error()))
		}
	}
	if err := scanner.Err(); err != nil {
		return ParseResult{}, err
	}
	for addr, group := range neighborGroup {
		neighbor := BGPNeighbor{
			Address:      addr,
			RemoteAS:     groupAS[group],
			Activated:    true,
			ImportPolicy: groupImportPolicy[group],
			ExportPolicy: groupExportPolicy[group],
			NextHopSelf:  groupNextHopSelf[group],
		}
		if policy := neighborImportPolicy[addr]; policy != "" {
			neighbor.ImportPolicy = policy
		}
		if policy := neighborExportPolicy[addr]; policy != "" {
			neighbor.ExportPolicy = policy
		}
		if neighborNextHopSelf[addr] {
			neighbor.NextHopSelf = true
		}
		cfg.Neighbors = append(cfg.Neighbors, neighbor)
	}
	addSRLinuxDefaultPolicyActions(routePolicies)
	cfg.PrefixLists = sortedPrefixLists(prefixLists)
	cfg.RoutePolicies = sortedRoutePolicies(routePolicies)
	cfg.Policies = boundACLPolicies(flattenSRLinuxACLs(srlACLs), aclBindings)
	return ParseResult{Config: cfg, Warnings: warnings}, nil
}

func parseFRRLikeStaticRoute(kind DeviceKind, path string, lineNo int, raw string, fields []string) (ConfiguredRoute, error) {
	if len(fields) != 4 {
		return ConfiguredRoute{}, fmt.Errorf("unsupported %s static route statement", routeMapVendorName(kind))
	}
	prefix, err := ParsePrefix(fields[2])
	if err != nil {
		return ConfiguredRoute{}, err
	}
	route := ConfiguredRoute{
		NetworkInstance: NetworkInstanceDefault,
		AFI:             AFIIPv4,
		Prefix:          prefix,
		Kind:            RouteSourceStatic,
		AdminDistance:   1,
		Source:          PolicySource{Vendor: string(kind), File: path, Line: lineNo, Raw: raw},
	}
	target := fields[3]
	if strings.EqualFold(target, "Null0") {
		route.Kind = RouteSourceBlackhole
		route.Interface = target
		return route, nil
	}
	if _, err := netip.ParseAddr(target); err == nil {
		route.NextHop = target
		return route, nil
	}
	route.Interface = target
	return route, nil
}

func parseAggregateRoute(kind DeviceKind, path string, lineNo int, raw string, fields []string) (ConfiguredRoute, error) {
	if len(fields) < 2 {
		return ConfiguredRoute{}, fmt.Errorf("unsupported %s aggregate-address statement", routeMapVendorName(kind))
	}
	prefixText := fields[1]
	prefix, err := ParsePrefix(prefixText)
	if err != nil {
		return ConfiguredRoute{}, err
	}
	route := ConfiguredRoute{
		NetworkInstance: NetworkInstanceDefault,
		AFI:             AFIIPv4,
		Prefix:          prefix,
		Kind:            RouteSourceAggregate,
		AdminDistance:   200,
		Source:          PolicySource{Vendor: string(kind), File: path, Line: lineNo, Raw: raw},
	}
	for _, opt := range fields[2:] {
		switch opt {
		case "summary-only":
			route.SummaryOnly = true
		default:
			return ConfiguredRoute{}, fmt.Errorf("unsupported %s aggregate-address option %q", routeMapVendorName(kind), opt)
		}
	}
	return route, nil
}

func parseFRRLikeRedistribution(kind DeviceKind, path string, lineNo int, raw string, fields []string) (BGPRedistribution, error) {
	redist := BGPRedistribution{Source: PolicySource{Vendor: string(kind), File: path, Line: lineNo, Raw: raw}}
	switch fields[1] {
	case "connected":
		redist.Kind = RouteSourceConnected
	case "static":
		redist.Kind = RouteSourceStatic
	default:
		return BGPRedistribution{}, fmt.Errorf("unsupported %s redistribute source %q", routeMapVendorName(kind), fields[1])
	}
	if len(fields) == 2 {
		return redist, nil
	}
	if len(fields) == 4 && fields[2] == "route-map" {
		redist.RouteMap = fields[3]
		return redist, nil
	}
	return BGPRedistribution{}, fmt.Errorf("unsupported %s redistribute statement", routeMapVendorName(kind))
}

func parseSRLinuxStaticRoute(path string, lineNo int, raw string, fields []string) (ConfiguredRoute, error) {
	prefixText := fieldAfter(fields, "route")
	if prefixText == "" {
		return ConfiguredRoute{}, fmt.Errorf("unsupported SR Linux static route statement")
	}
	prefix, err := ParsePrefix(prefixText)
	if err != nil {
		return ConfiguredRoute{}, err
	}
	route := ConfiguredRoute{
		NetworkInstance: NetworkInstanceDefault,
		AFI:             AFIIPv4,
		Prefix:          prefix,
		Kind:            RouteSourceStatic,
		AdminDistance:   5,
		Source:          PolicySource{Vendor: "srlinux", File: path, Line: lineNo, Raw: raw},
	}
	if nh := fieldAfter(fields, "next-hop"); nh != "" {
		if _, err := netip.ParseAddr(nh); err == nil {
			route.NextHop = nh
			return route, nil
		}
	}
	if iface := fieldAfter(fields, "interface"); iface != "" {
		route.Interface = iface
		return route, nil
	}
	if containsAnyField(fields, "blackhole") || containsAnyField(fields, "discard") {
		route.Kind = RouteSourceBlackhole
		return route, nil
	}
	return ConfiguredRoute{}, fmt.Errorf("unsupported SR Linux static route next-hop")
}

func parseSRLinuxPrefixSet(prefixLists map[string]*PrefixList, fields []string) error {
	name := fieldAfter(fields, "prefix-set")
	prefix := fieldAfter(fields, "prefix")
	if name == "" || prefix == "" {
		return fmt.Errorf("unsupported SR Linux prefix-set statement")
	}
	ge, le, err := parseSRLinuxMaskLengthRange(prefix, fieldAfter(fields, "mask-length-range"))
	if err != nil {
		return err
	}
	rule, err := parsePrefixListRule(0, "permit", prefix, prefixRangeFields(ge, le))
	if err != nil {
		return err
	}
	addPrefixListRule(prefixLists, name, rule)
	return nil
}

func parseSRLinuxMaskLengthRange(prefix, raw string) (int, int, error) {
	if raw == "" || raw == "exact" {
		return 0, 0, nil
	}
	parts := strings.Split(raw, "..")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("unsupported SR Linux mask-length-range %q", raw)
	}
	ge, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, err
	}
	le, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, err
	}
	parsed, err := netip.ParsePrefix(prefix)
	if err != nil {
		return 0, 0, err
	}
	if ge == parsed.Bits() {
		ge = 0
	}
	if le == parsed.Bits() {
		le = 0
	}
	return ge, le, nil
}

func prefixRangeFields(ge, le int) []string {
	var fields []string
	if ge > 0 {
		fields = append(fields, "ge", strconv.Itoa(ge))
	}
	if le > 0 {
		fields = append(fields, "le", strconv.Itoa(le))
	}
	return fields
}

const unsupportedSRLinuxPolicyPrefixList = "__unsupported_srlinux_policy_never_match__"

func parseSRLinuxRoutePolicy(routePolicies map[string]*RoutePolicy, prefixLists map[string]*PrefixList, fields []string) error {
	name := fieldAfter(fields, "policy")
	if name == "" {
		return fmt.Errorf("unsupported SR Linux routing-policy statement")
	}
	if containsSeq(fields, "default-action", "policy-result") {
		action := fields[len(fields)-1]
		if action != "accept" && action != "reject" {
			return fmt.Errorf("unsupported SR Linux routing-policy default-action %q", action)
		}
		addRoutePolicyRule(routePolicies, name, srLinuxPolicyAction(action), 65535)
		return nil
	}
	if !containsAnyField(fields, "statement") {
		return fmt.Errorf("unsupported SR Linux routing-policy statement")
	}
	seq, err := strconv.Atoi(fieldAfter(fields, "statement"))
	if err != nil {
		return err
	}
	policy, rule := ensureRoutePolicyRule(routePolicies, name, seq)
	_ = policy
	switch {
	case containsSeq(fields, "match", "prefix", "prefix-set"):
		rule.MatchPrefixList = fieldAfter(fields, "prefix-set")
	case containsSeq(fields, "action", "policy-result"):
		action := fields[len(fields)-1]
		if action != "accept" && action != "reject" {
			return fmt.Errorf("unsupported SR Linux routing-policy action %q", action)
		}
		rule.Action = srLinuxPolicyAction(action)
	case containsSeq(fields, "action") && fields[len(fields)-1] == "accept":
		rule.Action = "permit"
	case containsSeq(fields, "action") && fields[len(fields)-1] == "reject":
		rule.Action = "deny"
	case containsSeq(fields, "action", "bgp", "local-preference", "set"):
		v, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			return err
		}
		rule.SetLocalPref = intPtr(v)
	case containsSeq(fields, "action", "bgp", "med", "set") ||
		containsSeq(fields, "action", "bgp", "med", "operation", "set") ||
		containsSeq(fields, "action", "bgp", "metric", "set") ||
		containsSeq(fields, "action", "bgp", "metric", "operation", "set"):
		v, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			return err
		}
		rule.SetMED = intPtr(v)
	case containsSeq(fields, "action", "bgp", "next-hop", "set") && strings.EqualFold(fields[len(fields)-1], "self"):
		rule.SetNextHopSelf = true
	default:
		markUnsupportedSRLinuxRoutePolicyRule(prefixLists, rule)
		return fmt.Errorf("unsupported SR Linux routing-policy statement")
	}
	return nil
}

func markUnsupportedSRLinuxRoutePolicyRule(prefixLists map[string]*PrefixList, rule *RoutePolicyRule) {
	if prefixLists[unsupportedSRLinuxPolicyPrefixList] == nil {
		denyAny, err := parsePrefixListRule(0, "deny", "any", nil)
		if err == nil {
			prefixLists[unsupportedSRLinuxPolicyPrefixList] = &PrefixList{Name: unsupportedSRLinuxPolicyPrefixList, Rules: []PrefixListRule{denyAny}}
		}
	}
	rule.MatchPrefixList = unsupportedSRLinuxPolicyPrefixList
}

func addSRLinuxDefaultPolicyActions(routePolicies map[string]*RoutePolicy) {
	for _, policy := range routePolicies {
		hasDefault := false
		for _, rule := range policy.Rules {
			if rule.Seq == 65535 {
				hasDefault = true
				break
			}
		}
		if !hasDefault {
			policy.Rules = append(policy.Rules, RoutePolicyRule{Seq: 65535, Action: "permit"})
		}
	}
}

func ensureRoutePolicyRule(routePolicies map[string]*RoutePolicy, name string, seq int) (*RoutePolicy, *RoutePolicyRule) {
	if routePolicies[name] == nil {
		routePolicies[name] = &RoutePolicy{Name: name}
	}
	policy := routePolicies[name]
	for i := range policy.Rules {
		if policy.Rules[i].Seq == seq {
			return policy, &policy.Rules[i]
		}
	}
	policy.Rules = append(policy.Rules, RoutePolicyRule{Seq: seq, Action: "deny"})
	return policy, &policy.Rules[len(policy.Rules)-1]
}

func srLinuxPolicyAction(action string) string {
	if action == "reject" {
		return "deny"
	}
	return "permit"
}

func parseSRLinuxPolicyBinding(fields []string) (string, error) {
	for i, field := range fields {
		if field != "import-policy" && field != "export-policy" {
			continue
		}
		policies := fields[i+1:]
		if len(policies) == 0 {
			return "", fmt.Errorf("unsupported SR Linux empty BGP policy binding")
		}
		if policies[0] == "[" {
			policies = policies[1:]
			if len(policies) == 0 {
				return "", fmt.Errorf("unsupported SR Linux empty BGP policy binding")
			}
			if len(policies) < 2 || policies[1] != "]" {
				return "", fmt.Errorf("unsupported SR Linux multiple BGP policy binding")
			}
			return policies[0], nil
		}
		if len(policies) > 1 {
			return "", fmt.Errorf("unsupported SR Linux multiple BGP policy binding")
		}
		return policies[0], nil
	}
	return "", fmt.Errorf("unsupported SR Linux BGP policy binding")
}

func unsupportedStatement(vendor, file string, line int, text, reason string) UnsupportedStatement {
	return UnsupportedStatement{
		Vendor: vendor,
		File:   file,
		Line:   line,
		Text:   text,
		Reason: reason,
	}
}

func parseNftables(path, text string) ([]Policy, error) {
	var policies []Policy
	var tableName string
	inForward := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || line == "}" {
			if line == "}" && inForward {
				inForward = false
			}
			continue
		}
		fields := strings.Fields(strings.NewReplacer("{", " { ", ";", " ; ").Replace(line))
		if len(fields) == 0 {
			continue
		}
		switch {
		case len(fields) >= 4 && fields[0] == "table" && fields[1] == "inet":
			tableName = fields[2]
		case len(fields) >= 3 && fields[0] == "chain" && fields[1] == "forward":
			inForward = true
		case inForward && len(fields) >= 8 && fields[0] == "type" && fields[1] == "filter" && fields[2] == "hook" && fields[3] == "forward":
			continue
		case inForward:
			policy, ok, err := parseNftablesForwardRule(path, lineNo, line, tableName, fields)
			if err != nil {
				return nil, err
			}
			if ok {
				policies = append(policies, policy)
			}
		default:
			return nil, fmt.Errorf("%s:%d: unsupported nftables statement %q", path, lineNo, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return policies, nil
}

func parseNftablesForwardRule(path string, lineNo int, raw, tableName string, fields []string) (Policy, bool, error) {
	stage := ""
	iface := ""
	protocol := ""
	dstPrefix := Prefix{}
	dstPort := PortSet(nil)
	action := ""
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case ";":
			continue
		case "iifname", "oifname":
			if i+1 >= len(fields) {
				return Policy{}, false, fmt.Errorf("%s:%d: unsupported nftables interface match %q", path, lineNo, raw)
			}
			if fields[i] == "iifname" {
				stage = "ingress"
			} else {
				stage = "egress"
			}
			iface = strings.Trim(fields[i+1], `"`)
			i++
		case "ip":
			if i+2 >= len(fields) {
				return Policy{}, false, fmt.Errorf("%s:%d: unsupported nftables ip match %q", path, lineNo, raw)
			}
			switch fields[i+1] {
			case "protocol":
				protocol = fields[i+2]
			case "daddr":
				pfx, err := ParsePrefix(fields[i+2])
				if err != nil {
					return Policy{}, false, fmt.Errorf("%s:%d: %w", path, lineNo, err)
				}
				dstPrefix = pfx
			default:
				return Policy{}, false, fmt.Errorf("%s:%d: unsupported nftables ip match %q", path, lineNo, raw)
			}
			i += 2
		case "tcp", "udp":
			if i+2 >= len(fields) || fields[i+1] != "dport" || !supportedACLPortTail([]string{"eq", fields[i+2]}) {
				return Policy{}, false, fmt.Errorf("%s:%d: unsupported nftables transport match %q", path, lineNo, raw)
			}
			if protocol == "" {
				protocol = fields[i]
			}
			port, err := parseACLPort(fields[i+2])
			if err != nil {
				return Policy{}, false, fmt.Errorf("%s:%d: %w", path, lineNo, err)
			}
			dstPort = ExactPort(port)
			i += 2
		case "drop":
			action = "deny"
		case "accept":
			return Policy{}, false, nil
		default:
			return Policy{}, false, fmt.Errorf("%s:%d: unsupported nftables forward statement %q", path, lineNo, raw)
		}
	}
	if stage == "" || iface == "" || protocol == "" || dstPrefix.IsZero() || action == "" {
		return Policy{}, false, fmt.Errorf("%s:%d: incomplete nftables forward rule %q", path, lineNo, raw)
	}
	if protocol != "tcp" && protocol != "udp" && protocol != "icmp" && protocol != "ip" {
		return Policy{}, false, fmt.Errorf("%s:%d: unsupported nftables protocol %q", path, lineNo, protocol)
	}
	return Policy{
		Name:      nftablesPolicyName(tableName),
		Plane:     "data",
		Stage:     stage,
		Interface: iface,
		Action:    action,
		Protocol:  aclPolicyProtocol(protocol),
		DstPrefix: dstPrefix,
		DstPort:   dstPort,
		Seq:       lineNo,
		Source: PolicySource{
			Vendor: "nftables",
			File:   path,
			Line:   lineNo,
			Raw:    raw,
		},
	}, true, nil
}

func nftablesPolicyName(tableName string) string {
	if tableName == "" {
		return "NFTABLES-FORWARD"
	}
	return strings.ReplaceAll(tableName, "_", "-")
}

func isACLRuleLine(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	if len(fields) >= 3 && fields[0] == "seq" && (fields[2] == "permit" || fields[2] == "deny") {
		return true
	}
	if fields[0] == "permit" || fields[0] == "deny" {
		return true
	}
	if _, err := strconv.Atoi(fields[0]); err == nil && len(fields) >= 2 && (fields[1] == "permit" || fields[1] == "deny") {
		return true
	}
	return false
}

func parseACLRule(kind DeviceKind, path string, lineNo int, raw, name string, fields []string) (Policy, bool, error) {
	seq := 0
	if len(fields) >= 2 && fields[0] == "seq" {
		fields = fields[1:]
	}
	if n, err := strconv.Atoi(fields[0]); err == nil {
		seq = n
		fields = fields[1:]
	}
	if len(fields) < 4 {
		return Policy{}, false, fmt.Errorf("unsupported %s ACL statement", routeMapVendorName(kind))
	}
	action := fields[0]
	if action != "permit" && action != "deny" {
		return Policy{}, false, fmt.Errorf("unsupported %s ACL action %q", routeMapVendorName(kind), action)
	}
	protocol := fields[1]
	if protocol != "ip" && protocol != "tcp" && protocol != "udp" && protocol != "icmp" {
		return Policy{}, false, fmt.Errorf("unsupported %s ACL protocol %q", routeMapVendorName(kind), protocol)
	}
	rest := fields[2:]
	srcEnd, err := skipACLAddress(rest)
	if err != nil {
		return Policy{}, false, err
	}
	if srcEnd >= len(rest) {
		return Policy{}, false, fmt.Errorf("unsupported %s ACL destination", routeMapVendorName(kind))
	}
	dstPrefix, dstEnd, err := parseACLAddress(rest[srcEnd:])
	if err != nil {
		return Policy{}, false, err
	}
	dstPort, err := parseACLPortTail(rest[srcEnd+dstEnd:])
	if err != nil {
		return Policy{}, false, fmt.Errorf("unsupported %s ACL port match", routeMapVendorName(kind))
	}
	if action != "deny" {
		return Policy{}, false, nil
	}
	return Policy{
		Name:      name,
		Plane:     "data",
		Action:    "deny",
		Protocol:  aclPolicyProtocol(protocol),
		DstPrefix: dstPrefix,
		DstPort:   dstPort,
		Seq:       seq,
		Source: PolicySource{
			Vendor: string(kind),
			File:   path,
			Line:   lineNo,
			Raw:    raw,
		},
	}, true, nil
}

func skipACLAddress(fields []string) (int, error) {
	_, n, err := parseACLAddress(fields)
	return n, err
}

func parseACLAddress(fields []string) (Prefix, int, error) {
	if len(fields) == 0 {
		return Prefix{}, 0, fmt.Errorf("unsupported ACL empty address")
	}
	switch fields[0] {
	case "any":
		pfx, err := ParsePrefix("0.0.0.0/0")
		return pfx, 1, err
	case "host":
		if len(fields) < 2 {
			return Prefix{}, 0, fmt.Errorf("unsupported ACL host address")
		}
		pfx, err := ParsePrefix(fields[1] + "/32")
		return pfx, 2, err
	}
	if strings.Contains(fields[0], "/") {
		pfx, err := ParsePrefix(fields[0])
		return pfx, 1, err
	}
	if len(fields) >= 2 {
		if pfx, ok := wildcardPrefix(fields[0], fields[1]); ok {
			return pfx, 2, nil
		}
	}
	return Prefix{}, 0, fmt.Errorf("unsupported ACL address %q", strings.Join(fields, " "))
}

func wildcardPrefix(addr, wildcard string) (Prefix, bool) {
	ip, err := netip.ParseAddr(addr)
	if err != nil || !ip.Is4() {
		return Prefix{}, false
	}
	w, err := netip.ParseAddr(wildcard)
	if err != nil || !w.Is4() {
		return Prefix{}, false
	}
	wb := w.As4()
	bits := 0
	seenOne := false
	for _, octet := range wb {
		for bit := 7; bit >= 0; bit-- {
			one := octet&(1<<bit) != 0
			if one {
				seenOne = true
				continue
			}
			if seenOne {
				return Prefix{}, false
			}
			bits++
		}
	}
	pfx := netip.PrefixFrom(ip, bits).Masked()
	return PrefixFromNetIP(pfx), true
}

func supportedACLPortTail(fields []string) bool {
	_, err := parseACLPortTail(fields)
	return err == nil
}

func parseACLPortTail(fields []string) (PortSet, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	if len(fields) == 2 && fields[0] == "eq" {
		port, err := parseACLPort(fields[1])
		if err != nil {
			return nil, err
		}
		return ExactPort(port), nil
	}
	return nil, fmt.Errorf("unsupported port tail")
}

func parseACLPort(raw string) (int, error) {
	switch raw {
	case "www", "http":
		return 80, nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("unsupported port %q", raw)
	}
	return port, nil
}

func aclPolicyProtocol(protocol string) string {
	if protocol == "ip" {
		return ""
	}
	return protocol
}

func aclStage(raw string) (string, bool) {
	switch raw {
	case "in", "input":
		return "ingress", true
	case "out", "output":
		return "egress", true
	default:
		return "", false
	}
}

func boundACLPolicies(aclPolicies map[string][]Policy, bindings []aclBinding) []Policy {
	var out []Policy
	for _, binding := range bindings {
		for _, policy := range aclPolicies[binding.Name] {
			policy.Stage = binding.Stage
			policy.Interface = binding.Interface
			out = append(out, policy)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Seq < out[j].Seq
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func parseSRLinuxACL(aclPolicies map[string]map[int]*Policy, path string, lineNo int, raw string, fields []string) error {
	name := fieldAfter(fields, "acl-filter")
	if name == "" || fieldAfter(fields, "type") != "ipv4" {
		return nil
	}
	entryText := fieldAfter(fields, "entry")
	if entryText == "" {
		return nil
	}
	seq, err := strconv.Atoi(entryText)
	if err != nil {
		return err
	}
	if aclPolicies[name] == nil {
		aclPolicies[name] = map[int]*Policy{}
	}
	policy := aclPolicies[name][seq]
	if policy == nil {
		policy = &Policy{
			Name:   name,
			Plane:  "data",
			Seq:    seq,
			Source: PolicySource{Vendor: "srlinux", File: path, Line: lineNo, Raw: raw},
		}
		aclPolicies[name][seq] = policy
	}
	if containsSeq(fields, "match", "ipv4", "protocol") {
		proto := fields[len(fields)-1]
		if proto != "tcp" && proto != "udp" && proto != "icmp" && proto != "ip" {
			return fmt.Errorf("unsupported SR Linux ACL protocol %q", proto)
		}
		policy.Protocol = aclPolicyProtocol(proto)
		return nil
	}
	if containsSeq(fields, "match", "ipv4", "destination-ip", "prefix") {
		pfx, err := ParsePrefix(fields[len(fields)-1])
		if err != nil {
			return err
		}
		policy.DstPrefix = pfx
		return nil
	}
	if containsSeq(fields, "match", "transport", "destination-port", "value") {
		if !supportedACLPortTail([]string{"eq", fields[len(fields)-1]}) {
			return fmt.Errorf("unsupported SR Linux ACL destination port %q", fields[len(fields)-1])
		}
		port, err := parseACLPort(fields[len(fields)-1])
		if err != nil {
			return err
		}
		policy.DstPort = ExactPort(port)
		return nil
	}
	if containsSeq(fields, "action") {
		switch fields[len(fields)-1] {
		case "drop":
			policy.Action = "deny"
		case "accept":
			policy.Action = "permit"
		default:
			return fmt.Errorf("unsupported SR Linux ACL action %q", fields[len(fields)-1])
		}
		return nil
	}
	return fmt.Errorf("unsupported SR Linux ACL statement")
}

func parseSRLinuxACLBinding(fields []string) (aclBinding, bool) {
	name := fieldAfter(fields, "acl-filter")
	if name == "" || fieldAfter(fields, "type") != "ipv4" {
		return aclBinding{}, false
	}
	iface := fieldAfter(fields, "interface")
	stage := ""
	if containsAnyField(fields, "input") {
		stage = "ingress"
	}
	if containsAnyField(fields, "output") {
		stage = "egress"
	}
	if iface == "" || stage == "" {
		return aclBinding{}, false
	}
	return aclBinding{Name: name, Interface: iface, Stage: stage}, true
}

func flattenSRLinuxACLs(raw map[string]map[int]*Policy) map[string][]Policy {
	out := map[string][]Policy{}
	for name, entries := range raw {
		for _, policy := range entries {
			if policy.Action != "deny" {
				continue
			}
			if policy.Protocol == "" || policy.DstPrefix.IsZero() {
				continue
			}
			out[name] = append(out[name], *policy)
		}
	}
	return out
}

func srLinuxRoutingPolicyKind(fields []string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "routing-policy" {
			return fields[i+1]
		}
	}
	return ""
}

func isRouteMapPolicyKind(kind DeviceKind) bool {
	return kind == KindFRR || kind == KindCEOS
}

func routeMapVendorName(kind DeviceKind) string {
	switch kind {
	case KindCEOS:
		return "cEOS"
	default:
		return "FRR"
	}
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
	match, err := NewPrefixSet(rule.Prefix, rule.Ge, rule.Le)
	if err != nil {
		return PrefixListRule{}, err
	}
	rule.Match = match
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

func containsAnyField(fields []string, matches ...string) bool {
	for _, field := range fields {
		for _, match := range matches {
			if field == match {
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
