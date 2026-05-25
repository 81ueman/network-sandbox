package sim

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func applyRoutePolicy(topo *model.Topology, node model.Node, peerName string, policyName string, route RIBEntry) BGPRouteDecision {
	if policyName == "" {
		return BGPRouteDecision{Route: route, Accept: true}
	}
	policy, ok := routePolicyByName(node, policyName)
	if !ok {
		return BGPRouteDecision{Route: route, Accept: true}
	}
	for _, rule := range policy.Rules {
		if !routePolicyRuleMatches(topo, node, peerName, rule, route) {
			continue
		}
		if strings.EqualFold(rule.Action, "deny") {
			return BGPRouteDecision{Route: route, Accept: false, Reason: "route-map deny"}
		}
		out := route
		if rule.SetLocalPref != nil {
			out.LocalPref = *rule.SetLocalPref
		}
		if rule.SetLocalPrefDelta != nil {
			out.LocalPref = defaultLocalPref(out.LocalPref) + *rule.SetLocalPrefDelta
		}
		if rule.SetMED != nil {
			out.MED = *rule.SetMED
		}
		if rule.SetMEDDelta != nil {
			out.MED += *rule.SetMEDDelta
		}
		if len(rule.SetASPathPrepend) > 0 {
			out.ASPath = append(append([]uint32(nil), rule.SetASPathPrepend...), out.ASPath...)
		}
		if len(rule.SetCommunities) > 0 {
			if rule.SetCommunityAdditive {
				out.Communities = appendUniqueStrings(out.Communities, rule.SetCommunities...)
			} else {
				out.Communities = append([]string(nil), rule.SetCommunities...)
			}
			sort.Strings(out.Communities)
		}
		if rule.SetOriginCode != "" {
			out.OriginCode = rule.SetOriginCode
		}
		return BGPRouteDecision{Route: out, Accept: true}
	}
	return BGPRouteDecision{Route: route, Accept: false, Reason: "route-map implicit deny"}
}

func routePolicyRuleMatches(topo *model.Topology, node model.Node, peerName string, rule model.RoutePolicyRule, route RIBEntry) bool {
	if rule.MatchPrefixList != "" && !prefixListPermits(node, rule.MatchPrefixList, route.Prefix) {
		return false
	}
	if rule.MatchNextHopPrefixList != "" && !prefixListPermitsAddress(node, rule.MatchNextHopPrefixList, routeNextHopForPolicy(topo, node.Name, peerName, route)) {
		return false
	}
	if rule.MatchASPathList != "" && !asPathListPermits(node, rule.MatchASPathList, route.ASPath) {
		return false
	}
	if rule.MatchCommunityList != "" && !communityListPermits(node, rule.MatchCommunityList, route.Communities, rule.MatchCommunityExact) {
		return false
	}
	return true
}

func routePolicyByName(node model.Node, name string) (model.RoutePolicy, bool) {
	for _, policy := range node.RoutePolicies {
		if policy.Name == name {
			return policy, true
		}
	}
	return model.RoutePolicy{}, false
}

func prefixListPermits(node model.Node, name string, routePrefix string) bool {
	want, err := netip.ParsePrefix(routePrefix)
	if err != nil {
		return false
	}
	return prefixListPermitsPrefix(node, name, want)
}

func prefixListPermitsAddress(node model.Node, name string, addr string) bool {
	if addr == "" {
		return false
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	return prefixListPermitsPrefix(node, name, netip.PrefixFrom(ip, ip.BitLen()))
}

func prefixListPermitsPrefix(node model.Node, name string, want netip.Prefix) bool {
	for _, prefixList := range node.PrefixLists {
		if prefixList.Name != name {
			continue
		}
		for _, rule := range prefixList.Rules {
			if !prefixListRuleMatches(rule, want) {
				continue
			}
			return strings.EqualFold(rule.Action, "permit")
		}
		return false
	}
	return false
}

func prefixListRuleMatches(rule model.PrefixListRule, want netip.Prefix) bool {
	if rule.Prefix == "any" {
		return true
	}
	got, err := netip.ParsePrefix(rule.Prefix)
	if err != nil {
		return false
	}
	if !got.Contains(want.Addr()) {
		return false
	}
	minLen := got.Bits()
	maxLen := got.Bits()
	if rule.Ge != 0 {
		minLen = rule.Ge
		maxLen = want.Addr().BitLen()
	}
	if rule.Le != 0 {
		maxLen = rule.Le
	}
	return want.Bits() >= minLen && want.Bits() <= maxLen
}

func asPathListPermits(node model.Node, name string, asPath []uint32) bool {
	path := formatASPath(asPath)
	for _, list := range node.ASPathLists {
		if list.Name != name {
			continue
		}
		for _, rule := range list.Rules {
			matched, err := regexp.MatchString(rule.Pattern, path)
			if err != nil || !matched {
				continue
			}
			return strings.EqualFold(rule.Action, "permit")
		}
		return false
	}
	return false
}

func communityListPermits(node model.Node, name string, communities []string, exact bool) bool {
	allowed := map[string]bool{}
	denied := map[string]bool{}
	for _, list := range node.CommunityLists {
		if list.Name != name {
			continue
		}
		for _, rule := range list.Rules {
			if strings.EqualFold(rule.Action, "permit") {
				allowed[rule.Pattern] = true
			} else {
				denied[rule.Pattern] = true
			}
		}
		if exact {
			if len(communities) != len(allowed) {
				return false
			}
			for _, community := range communities {
				if !allowed[community] || denied[community] {
					return false
				}
			}
			return true
		}
		for _, community := range communities {
			if denied[community] {
				return false
			}
			if allowed[community] {
				return true
			}
		}
		return false
	}
	return false
}

func routeNextHopForPolicy(topo *model.Topology, node string, peerName string, route RIBEntry) string {
	if route.NextHop == "" {
		return ""
	}
	if route.NextHop == node && peerName != "" {
		return peerAddress(topo, peerName, node)
	}
	if direct := peerAddress(topo, node, route.NextHop); direct != route.NextHop {
		return direct
	}
	for i := 0; i+1 < len(route.Nodes); i++ {
		if route.Nodes[i] != route.NextHop {
			continue
		}
		if addr := peerAddress(topo, route.Nodes[i+1], route.NextHop); addr != route.NextHop {
			return addr
		}
	}
	return route.NextHop
}

func peerAddress(topo *model.Topology, node, peer string) string {
	if peer == "" {
		return ""
	}
	for _, l := range topo.Links {
		a, b := linkAddresses(l.Subnet)
		switch {
		case l.A == node && l.B == peer:
			return trimMask(b)
		case l.B == node && l.A == peer:
			return trimMask(a)
		}
	}
	return peer
}

func linkAddresses(raw string) (string, string) {
	parts := strings.Split(raw, "/")
	prefixLen := ""
	if len(parts) == 2 {
		prefixLen = "/" + parts[1]
	}
	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return raw, raw
	}
	last := 0
	fmt.Sscanf(octets[3], "%d", &last)
	a := parts[0] + prefixLen
	octets[3] = fmt.Sprint(last + 1)
	b := strings.Join(octets, ".") + prefixLen
	return a, b
}

func trimMask(addr string) string {
	return strings.Split(addr, "/")[0]
}

func formatASPath(path []uint32) string {
	parts := make([]string, 0, len(path))
	for _, asn := range path {
		parts = append(parts, fmt.Sprint(asn))
	}
	return strings.Join(parts, " ")
}

func appendUniqueStrings(xs []string, more ...string) []string {
	out := append([]string(nil), xs...)
	seen := map[string]bool{}
	for _, x := range out {
		seen[x] = true
	}
	for _, x := range more {
		if !seen[x] {
			out = append(out, x)
			seen[x] = true
		}
	}
	return out
}

func defaultLocalPref(v int) int {
	if v == 0 {
		return 100
	}
	return v
}
