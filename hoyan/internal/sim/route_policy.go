package sim

import (
	"net/netip"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

func applyRoutePolicy(node model.Node, policyName string, route RIBEntry) BGPRouteDecision {
	if policyName == "" {
		return BGPRouteDecision{Route: route, Accept: true}
	}
	policy, ok := routePolicyByName(node, policyName)
	if !ok {
		return BGPRouteDecision{Route: route, Accept: true}
	}
	for _, rule := range policy.Rules {
		if !routePolicyRuleMatches(node, rule, route) {
			continue
		}
		if strings.EqualFold(rule.Action, "deny") {
			return BGPRouteDecision{Route: route, Accept: false, Reason: "route-map deny"}
		}
		out := route
		if rule.SetLocalPref != nil {
			out.LocalPref = *rule.SetLocalPref
		}
		if rule.SetMED != nil {
			out.MED = *rule.SetMED
		}
		return BGPRouteDecision{Route: out, Accept: true}
	}
	return BGPRouteDecision{Route: route, Accept: false, Reason: "route-map implicit deny"}
}

func routePolicyRuleMatches(node model.Node, rule model.RoutePolicyRule, route RIBEntry) bool {
	if rule.MatchPrefixList == "" {
		return true
	}
	return prefixListPermits(node, rule.MatchPrefixList, route.Prefix)
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
	for _, prefixList := range node.PrefixLists {
		if prefixList.Name != name {
			continue
		}
		for _, rule := range prefixList.Rules {
			got, err := netip.ParsePrefix(rule.Prefix)
			if err != nil || got != want {
				continue
			}
			return strings.EqualFold(rule.Action, "permit")
		}
		return false
	}
	return false
}

func defaultLocalPref(v int) int {
	if v == 0 {
		return 100
	}
	return v
}
