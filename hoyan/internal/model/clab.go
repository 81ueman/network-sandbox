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

type policyFile struct {
	Policies []Policy `yaml:"policies"`
}

type clabFile struct {
	Name string `yaml:"name"`
	Mgmt struct {
		IPv4Subnet string `yaml:"ipv4-subnet"`
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

func LoadLabTopology(clabPath, policyPath string) (*Topology, error) {
	data, err := os.ReadFile(clabPath)
	if err != nil {
		return nil, err
	}
	var raw clabFile
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	root := filepath.Dir(clabPath)
	topo := &Topology{Name: raw.Name, ManagementSubnet: raw.Mgmt.IPv4Subnet}
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
			return nil, fmt.Errorf("node %s has no startup config or frr.conf bind", name)
		}
		fullConfigPath := filepath.Join(root, configPath)
		parsed, err := ParseConfig(kind, fullConfigPath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		node := Node{
			Name:           name,
			Kind:           kind,
			Role:           cnode.Group,
			ASN:            parsed.ASN,
			MgmtIPv4:       cnode.MgmtIPv4,
			Loopback:       parsed.Loopback,
			ConfigPath:     configPath,
			Prefixes:       parsed.Prefixes,
			Interfaces:     parsed.Interfaces,
			Neighbors:      parsed.Neighbors,
			PrefixLists:    parsed.PrefixLists,
			ASPathLists:    parsed.ASPathLists,
			CommunityLists: parsed.CommunityLists,
			RoutePolicies:  parsed.RoutePolicies,
		}
		topo.Nodes = append(topo.Nodes, node)
	}
	for i, link := range raw.Topology.Links {
		if len(link.Endpoints) != 2 {
			return nil, fmt.Errorf("link %d must have two endpoints", i)
		}
		aNode, aIntf, err := splitEndpoint(link.Endpoints[0])
		if err != nil {
			return nil, err
		}
		bNode, bIntf, err := splitEndpoint(link.Endpoints[1])
		if err != nil {
			return nil, err
		}
		a, _ := topo.Node(aNode)
		b, _ := topo.Node(bNode)
		subnet, err := linkSubnet(a, aIntf, b, bIntf)
		if err != nil {
			return nil, fmt.Errorf("%s-%s: %w", link.Endpoints[0], link.Endpoints[1], err)
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
	if policyPath != "" {
		policies, err := LoadPolicies(policyPath)
		if err != nil {
			return nil, err
		}
		topo.Policies = policies
	}
	if err := topo.Validate(); err != nil {
		return nil, err
	}
	return topo, nil
}

func LoadPolicies(path string) ([]Policy, error) {
	var pf policyFile
	if err := loadYAML(path, &pf); err != nil {
		return nil, err
	}
	return pf.Policies, nil
}

func normalizeKind(kind string) string {
	switch kind {
	case "linux":
		return "frr"
	case "arista_ceos":
		return "ceos"
	case "nokia_srlinux":
		return "srlinux"
	default:
		return kind
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

func splitEndpoint(endpoint string) (string, string, error) {
	parts := strings.Split(endpoint, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid endpoint %q", endpoint)
	}
	return parts[0], parts[1], nil
}

func linkSubnet(a Node, aIntf string, b Node, bIntf string) (netip.Prefix, error) {
	ap, aok := interfaceAddr(a.Interfaces, aIntf)
	bp, bok := interfaceAddr(b.Interfaces, bIntf)
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
