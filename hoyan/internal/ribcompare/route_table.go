package ribcompare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
)

type routeTableNextHop struct {
	Address   string
	Interface string
}

func (frrCollector) CollectRouteTables(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		data, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "vtysh", "-c", "show ip route json")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s vtysh -c %q: %w", containerName, "show ip route json", err)
		}
		routes, err := ParseFRRRouteTable(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s FRR route table: %w", n.Name, err)
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func (ceosCollector) CollectRouteTables(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		data, err := runner.Run(ctx, "docker", "exec", "-i", containerName, "Cli", "-p", "15", "-c", "show ip route vrf default | json")
		if err != nil {
			return nil, fmt.Errorf("docker exec -i %s Cli -p 15 -c %q: %w", containerName, "show ip route vrf default | json", err)
		}
		routes, err := ParseCEOSRouteTable(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s cEOS route table: %w", n.Name, err)
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func (srlinuxCollector) CollectRouteTables(ctx context.Context, runner Runner, nodes []model.Node) ([]NormalizedBgpRoute, error) {
	var out []NormalizedBgpRoute
	for _, n := range nodes {
		containerName := n.RuntimeName()
		command := fmt.Sprintf("docker exec -it %s sr_cli --output-format json --pagination off -- show network-instance default route-table ipv4-unicast summary", shellQuote(containerName))
		data, err := runner.Run(ctx, "script", "-q", "/dev/null", "-c", command)
		if err != nil {
			return nil, fmt.Errorf("docker exec -it %s sr_cli route-table ipv4-unicast summary: %w", containerName, err)
		}
		routes, err := ParseSRLinuxRouteTable(n.Name, data)
		if err != nil {
			return nil, fmt.Errorf("%s SR Linux route table: %w", n.Name, err)
		}
		out = append(out, routes...)
	}
	sortRoutes(out)
	return out, nil
}

func ParseFRRRouteTable(node string, data []byte) ([]NormalizedBgpRoute, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	routesMap := raw
	if nested := asMap(raw["routes"]); nested != nil {
		routesMap = nested
	}
	var out []NormalizedBgpRoute
	for prefix, value := range routesMap {
		if _, err := netip.ParsePrefix(prefix); err != nil {
			continue
		}
		for _, item := range routeTableItems(value) {
			protocol := normalizedRouteTableProtocol(firstString(item, "protocol", "routeType", "type"))
			if protocol == "" {
				continue
			}
			hops := frrRouteTableNextHops(item)
			if routeTableBlackholeItem(item) || discardRouteTableNextHops(hops) || normalizedRouteTableProtocol(firstString(item, "type")) == "blackhole" {
				protocol = "blackhole"
				hops = nil
			}
			route := nonBGPRoute(node, "default", "ipv4", prefix, protocol, hops)
			if len(route.Paths) > 0 {
				out = append(out, route)
			}
		}
	}
	sortRoutes(out)
	return out, nil
}

func ParseCEOSRouteTable(node string, data []byte) ([]NormalizedBgpRoute, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	vrfs := asMap(raw["vrfs"])
	defaultVRF := asMap(vrfs["default"])
	routes := asMap(defaultVRF["routes"])
	var out []NormalizedBgpRoute
	for prefix, value := range routes {
		m := asMap(value)
		protocol := normalizedRouteTableProtocol(firstString(m, "routeType", "sourceProtocol"))
		if protocol == "" {
			continue
		}
		hops := ceosRouteTableNextHops(m["vias"])
		if discardRouteTableNextHops(hops) {
			protocol = "blackhole"
			hops = nil
		}
		out = append(out, nonBGPRoute(node, "default", "ipv4", prefix, protocol, hops))
	}
	sortRoutes(out)
	return out, nil
}

func ParseSRLinuxRouteTable(node string, data []byte) ([]NormalizedBgpRoute, error) {
	cleaned, err := jsonPayload(data)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(cleaned, &raw); err != nil {
		return nil, err
	}
	var out []NormalizedBgpRoute
	for _, inst := range asSlice(raw["instance"]) {
		for _, item := range asSlice(asMap(inst)["ip route"]) {
			m := asMap(item)
			if !routeTableActive(m) {
				continue
			}
			protocol := normalizedRouteTableProtocol(firstString(m, "Route Type", "route-type"))
			if protocol == "" {
				continue
			}
			prefix := firstString(m, "Prefix", "prefix")
			if prefix == "" {
				continue
			}
			hops := srlinuxRouteTableNextHops(m)
			if discardRouteTableNextHops(hops) {
				protocol = "blackhole"
				hops = nil
			}
			out = append(out, nonBGPRoute(node, "default", "ipv4", prefix, protocol, hops))
		}
	}
	sortRoutes(out)
	return out, nil
}

func routeTableItems(value any) []map[string]any {
	switch x := value.(type) {
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, item := range x {
			if m := asMap(item); m != nil {
				out = append(out, m)
			}
		}
		return out
	case map[string]any:
		return []map[string]any{x}
	default:
		return nil
	}
}

func normalizedRouteTableProtocol(protocol string) string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "bgp", "ebgp", "ibgp", "":
		return ""
	case "kernel", "connected", "connect", "direct", "local", "host":
		return "connected"
	case "static":
		return "static"
	case "blackhole", "discard", "drop", "null0", "null":
		return "blackhole"
	default:
		return ""
	}
}

func nonBGPRoute(node, ni, afi, prefix, protocol string, hops []routeTableNextHop) NormalizedBgpRoute {
	if ni == "" {
		ni = "default"
	}
	if afi == "" {
		afi = "ipv4"
	}
	return NormalizedBgpRoute{
		Node:            node,
		NetworkInstance: ni,
		AFI:             afi,
		Prefix:          prefix,
		Protocol:        protocol,
		Paths:           []NormalizedBgpPath{nonBGPPath(protocol, hops)},
	}
}

func nonBGPPath(protocol string, hops []routeTableNextHop) NormalizedBgpPath {
	path := NormalizedBgpPath{Best: true, Valid: true, Origin: "igp", LocalPref: 100}
	if protocol == "connected" || protocol == "blackhole" || len(hops) == 0 {
		return path
	}
	if hops[0].Address != "" {
		path.NextHop = hops[0].Address
	}
	return path
}

func discardRouteTableNextHops(hops []routeTableNextHop) bool {
	if len(hops) == 0 {
		return false
	}
	for _, hop := range hops {
		if !discardRouteTableNextHop(hop) {
			return false
		}
	}
	return true
}

func routeTableBlackholeItem(m map[string]any) bool {
	if boolValue(firstPresent(m, "blackhole", "discard")) {
		return true
	}
	for _, raw := range asSlice(firstPresent(m, "nexthops", "nextHops")) {
		hop := asMap(raw)
		if boolValue(firstPresent(hop, "blackhole", "discard")) {
			return true
		}
	}
	return false
}

func discardRouteTableNextHop(hop routeTableNextHop) bool {
	if hop.Address != "" && !discardRouteTableToken(hop.Address) {
		return false
	}
	return discardRouteTableToken(hop.Interface)
}

func discardRouteTableToken(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "null0", "null", "discard", "drop", "blackhole":
		return true
	default:
		return false
	}
}

func frrRouteTableNextHops(m map[string]any) []routeTableNextHop {
	if hops := routeTableNextHops(firstPresent(m, "nexthops", "nextHops")); len(hops) > 0 {
		return hops
	}
	hop := routeTableNextHop{
		Address:   firstString(m, "nexthop", "nextHop", "gateway", "via"),
		Interface: firstString(m, "interfaceName", "interface", "dev"),
	}
	if hop.Address != "" || hop.Interface != "" {
		return []routeTableNextHop{hop}
	}
	return nil
}

func ceosRouteTableNextHops(raw any) []routeTableNextHop {
	var out []routeTableNextHop
	for _, item := range asSlice(raw) {
		m := asMap(item)
		hop := routeTableNextHop{
			Address:   firstString(m, "nexthopAddr", "nextHop", "gateway"),
			Interface: firstString(m, "interface", "interfaceName"),
		}
		if hop.Address != "" || hop.Interface != "" {
			out = append(out, hop)
		}
	}
	return out
}

func srlinuxRouteTableNextHops(m map[string]any) []routeTableNextHop {
	hop := routeTableNextHop{
		Address:   srlinuxNextHopAddress(firstString(m, "Next-hop (Type)", "Next-hop", "next-hop")),
		Interface: firstString(m, "Next-hop Interface", "next-hop-interface"),
	}
	if hop.Address == "" && hop.Interface == "" {
		return nil
	}
	return []routeTableNextHop{hop}
}

func routeTableNextHops(raw any) []routeTableNextHop {
	var out []routeTableNextHop
	for _, item := range asSlice(raw) {
		m := asMap(item)
		hop := routeTableNextHop{
			Address:   firstString(m, "ip", "gateway", "nexthop", "nextHop"),
			Interface: firstString(m, "interfaceName", "interface", "dev"),
		}
		if hop.Address != "" || hop.Interface != "" {
			out = append(out, hop)
		}
	}
	return out
}

func routeTableActive(m map[string]any) bool {
	if v := firstPresent(m, "Active", "active"); v != nil {
		return boolValue(v)
	}
	if v := firstPresent(m, "selected", "installed", "fib"); v != nil {
		return boolValue(v)
	}
	return true
}

func jsonPayload(data []byte) ([]byte, error) {
	s := string(data)
	start := strings.IndexByte(s, '{')
	end := strings.LastIndexByte(s, '}')
	if start < 0 || end < start {
		return nil, fmt.Errorf("no JSON object found")
	}
	return []byte(s[start : end+1]), nil
}

func srlinuxNextHopAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "None" {
		return ""
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	addr := fields[0]
	if pfx, err := netip.ParsePrefix(addr); err == nil {
		return pfx.Addr().String()
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		return ip.String()
	}
	return addr
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
