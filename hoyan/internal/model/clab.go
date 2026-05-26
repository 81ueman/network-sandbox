package model

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type clabFile struct {
	Name   string  `yaml:"name"`
	Prefix *string `yaml:"prefix"`
	Mgmt   struct {
		IPv4Subnet string `yaml:"ipv4-subnet"`
		Network    string `yaml:"network"`
	} `yaml:"mgmt"`
	Topology struct {
		Nodes map[string]clabNode `yaml:"nodes"`
		Links []struct {
			Endpoints []string `yaml:"endpoints"`
		} `yaml:"links"`
	} `yaml:"topology"`
}

type clabNode struct {
	Kind          string   `yaml:"kind"`
	Group         string   `yaml:"group"`
	MgmtIPv4      string   `yaml:"mgmt-ipv4"`
	Binds         []string `yaml:"binds"`
	StartupConfig string   `yaml:"startup-config"`
}

type LoadLabTopologyOptions struct {
	CollectWarnings bool
	StrictConfig    bool
}

func LoadLabTopology(clabPath string) (*Topology, error) {
	topo, _, err := LoadLabTopologyWithOptions(clabPath, LoadLabTopologyOptions{})
	return topo, err
}

func LoadLabTopologyWithWarnings(clabPath string) (*Topology, []UnsupportedStatement, error) {
	return LoadLabTopologyWithOptions(clabPath, LoadLabTopologyOptions{CollectWarnings: true})
}

func LoadLabTopologyWithOptions(clabPath string, opts LoadLabTopologyOptions) (*Topology, []UnsupportedStatement, error) {
	data, err := os.ReadFile(clabPath)
	if err != nil {
		return nil, nil, err
	}
	var raw clabFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, nil, err
	}
	root := filepath.Dir(clabPath)
	topo := &Topology{Name: raw.Name, ManagementSubnet: raw.Mgmt.IPv4Subnet}
	var warnings []UnsupportedStatement
	collectWarnings := opts.CollectWarnings || opts.StrictConfig
	names := make([]string, 0, len(raw.Topology.Nodes))
	for name := range raw.Topology.Nodes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cnode := raw.Topology.Nodes[name]
		kind := normalizeKind(cnode.Kind)
		configPath := resolveConfigPath(cnode)
		if configPath == "" {
			return nil, nil, fmt.Errorf("node %s has no startup config or frr.conf bind", name)
		}
		fullConfigPath := configPath
		if !filepath.IsAbs(fullConfigPath) {
			fullConfigPath = filepath.Join(root, configPath)
		}
		result, err := parseConfig(kind, fullConfigPath, collectWarnings)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		parsed := result.Config
		warnings = append(warnings, result.Warnings...)
		prefixes, err := parsePrefixes(parsed.Prefixes)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", name, err)
		}
		node := Node{
			Name:           name,
			ContainerName:  containerlabContainerName(raw.Prefix, raw.Name, name),
			Kind:           kind,
			Role:           cnode.Group,
			ASN:            parsed.ASN,
			MgmtIPv4:       cnode.MgmtIPv4,
			Loopback:       parsed.Loopback,
			ConfigPath:     configPath,
			Prefixes:       prefixes,
			Routes:         parsed.Routes,
			Interfaces:     parsed.Interfaces,
			Neighbors:      parsed.Neighbors,
			Redistribute:   parsed.Redistribute,
			PrefixLists:    parsed.PrefixLists,
			ASPathLists:    parsed.ASPathLists,
			CommunityLists: parsed.CommunityLists,
			RoutePolicies:  parsed.RoutePolicies,
		}
		for ri := range node.Routes {
			node.Routes[ri].Node = name
			if node.Routes[ri].NetworkInstance == "" {
				node.Routes[ri].NetworkInstance = NetworkInstanceDefault
			}
			if node.Routes[ri].AFI == "" {
				node.Routes[ri].AFI = AFIIPv4
			}
		}
		topo.Nodes = append(topo.Nodes, node)
		for _, policy := range parsed.Policies {
			policy.Node = name
			topo.Policies = append(topo.Policies, policy)
		}
		nftPath := resolveNftablesConfigPath(cnode)
		if nftPath != "" {
			fullNftPath := nftPath
			if !filepath.IsAbs(fullNftPath) {
				fullNftPath = filepath.Join(root, nftPath)
			}
			policies, err := ParseNftablesConfig(fullNftPath)
			if err != nil {
				return nil, nil, fmt.Errorf("%s nftables: %w", name, err)
			}
			for _, policy := range policies {
				policy.Node = name
				topo.Policies = append(topo.Policies, policy)
			}
		}
	}
	if opts.StrictConfig && len(warnings) > 0 {
		return nil, warnings, UnsupportedConfigError{Warnings: warnings}
	}
	for i, link := range raw.Topology.Links {
		if len(link.Endpoints) != 2 {
			return nil, nil, fmt.Errorf("link %d must have two endpoints", i)
		}
		aNode, aIntf, err := splitEndpoint(link.Endpoints[0])
		if err != nil {
			return nil, nil, err
		}
		bNode, bIntf, err := splitEndpoint(link.Endpoints[1])
		if err != nil {
			return nil, nil, err
		}
		a, _ := topo.Node(aNode)
		b, _ := topo.Node(bNode)
		subnet, err := linkSubnet(a, aIntf, b, bIntf)
		if err != nil {
			return nil, nil, fmt.Errorf("%s-%s: %w", link.Endpoints[0], link.Endpoints[1], err)
		}
		topo.Links = append(topo.Links, Link{
			Name:   linkName(aNode, aIntf, bNode, bIntf),
			A:      aNode,
			B:      bNode,
			AIntf:  aIntf,
			BIntf:  bIntf,
			Cost:   1,
			Subnet: subnet.String(),
		})
	}
	resolveNeighborNodes(topo)
	if err := topo.Validate(); err != nil {
		return nil, nil, err
	}
	return topo, warnings, nil
}

func containerlabContainerName(prefix *string, labName, nodeName string) string {
	if prefix != nil && *prefix == "" {
		return nodeName
	}
	effectivePrefix := "clab"
	if prefix != nil {
		effectivePrefix = *prefix
	}
	return effectivePrefix + "-" + labName + "-" + nodeName
}

func parsePrefixes(raw []string) ([]Prefix, error) {
	out := make([]Prefix, 0, len(raw))
	for _, p := range raw {
		parsed, err := ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("prefix %s: %w", p, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

func normalizeKind(kind string) DeviceKind {
	switch kind {
	case "linux":
		return KindFRR
	case "arista_ceos":
		return KindCEOS
	case "nokia_srlinux":
		return KindSRLinux
	default:
		return DeviceKind(kind)
	}
}

func resolveConfigPath(n clabNode) string {
	if n.StartupConfig != "" {
		return n.StartupConfig
	}
	for _, bind := range n.Binds {
		parts := strings.Split(bind, ":")
		if len(parts) >= 2 && parts[1] == "/etc/frr/frr.conf" {
			return parts[0]
		}
	}
	return ""
}

func resolveNftablesConfigPath(n clabNode) string {
	for _, bind := range n.Binds {
		parts := strings.Split(bind, ":")
		if len(parts) >= 2 && parts[1] == "/etc/hoyan/nftables.conf" {
			return parts[0]
		}
	}
	return ""
}

func splitEndpoint(endpoint string) (string, string, error) {
	parts := strings.Split(endpoint, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid endpoint %q", endpoint)
	}
	return parts[0], parts[1], nil
}

func linkSubnet(a Node, aIntf string, b Node, bIntf string) (netip.Prefix, error) {
	ap, aok := InterfaceAddress(a.Kind, a.Interfaces, aIntf)
	bp, bok := InterfaceAddress(b.Kind, b.Interfaces, bIntf)
	switch {
	case aok && bok && ap.Masked() == bp.Masked():
		return ap.Masked(), nil
	case aok && !bok:
		return ap.Masked(), nil
	case !aok && bok:
		return bp.Masked(), nil
	case aok && bok:
		return netip.Prefix{}, fmt.Errorf("interface subnets differ: %s and %s", ap, bp)
	default:
		return netip.Prefix{}, fmt.Errorf("missing interface addresses")
	}
}

func linkName(aNode, aIntf, bNode, bIntf string) string {
	return strings.NewReplacer(":", "-", "_", "-").Replace(aNode + "-" + aIntf + "__" + bNode + "-" + bIntf)
}

func resolveNeighborNodes(topo *Topology) {
	addrToNode := map[string]string{}
	for _, n := range topo.Nodes {
		for _, iface := range n.Interfaces {
			pfx, err := netip.ParsePrefix(iface.Address)
			if err == nil {
				addrToNode[pfx.Addr().String()] = n.Name
			}
		}
	}
	for ni := range topo.Nodes {
		for pi := range topo.Nodes[ni].Neighbors {
			peer := addrToNode[topo.Nodes[ni].Neighbors[pi].Address]
			topo.Nodes[ni].Neighbors[pi].PeerNode = peer
		}
	}
}
