package model

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type TopologyRenderOptions struct {
	Suffix      string
	LabName     string
	MgmtNetwork string
	MgmtSubnet  string
	SourceDir   string
}

func RenderIsolatedTopology(data []byte, opts TopologyRenderOptions) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	root := documentMapping(&doc)
	if root == nil {
		return nil, fmt.Errorf("topology YAML must be a mapping")
	}
	currentName := scalarValue(mappingValue(root, "name"))
	if currentName == "" {
		return nil, fmt.Errorf("topology YAML is missing name")
	}
	suffix, err := normalizeLabSuffix(opts.Suffix)
	if err != nil {
		return nil, err
	}
	if suffix == "" && opts.MgmtSubnet == "" {
		return nil, fmt.Errorf("suffix or explicit management subnet is required for isolated topology rendering")
	}
	labName := opts.LabName
	if labName == "" && suffix != "" {
		labName = currentName + "-" + suffix
	}
	if labName == "" {
		labName = currentName
	}
	mgmtNetwork := opts.MgmtNetwork
	if mgmtNetwork == "" {
		mgmtNetwork = labName
	}
	mgmtSubnet := opts.MgmtSubnet
	if mgmtSubnet == "" && suffix != "" {
		mgmtSubnet = fmt.Sprintf("172.86.%d.0/24", subnetOctetFromSuffix(suffix))
	}
	if mgmtSubnet == "" {
		mgmtSubnet = scalarValue(mappingValue(mappingValue(root, "mgmt"), "ipv4-subnet"))
	}
	if err := validateIPv4Subnet24(mgmtSubnet); err != nil {
		return nil, err
	}

	setScalar(root, "name", labName)
	removeMappingKey(root, "prefix")
	mgmt := ensureMapping(root, "mgmt")
	setScalar(mgmt, "network", mgmtNetwork)
	setScalar(mgmt, "ipv4-subnet", mgmtSubnet)
	if err := rewriteNodeMgmtIPs(root, mgmtSubnet); err != nil {
		return nil, err
	}
	if opts.SourceDir != "" {
		rewriteRelativeConfigPaths(root, opts.SourceDir)
	}

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(4)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func rewriteRelativeConfigPaths(root *yaml.Node, sourceDir string) {
	nodes := mappingValue(mappingValue(root, "topology"), "nodes")
	if nodes == nil || nodes.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(nodes.Content); i += 2 {
		node := nodes.Content[i+1]
		if startup := mappingValue(node, "startup-config"); startup != nil && startup.Kind == yaml.ScalarNode {
			startup.Value = absFromSourceDir(sourceDir, startup.Value)
		}
		binds := mappingValue(node, "binds")
		if binds == nil || binds.Kind != yaml.SequenceNode {
			continue
		}
		for _, bind := range binds.Content {
			if bind.Kind != yaml.ScalarNode {
				continue
			}
			parts := strings.Split(bind.Value, ":")
			if len(parts) == 0 {
				continue
			}
			parts[0] = absFromSourceDir(sourceDir, parts[0])
			bind.Value = strings.Join(parts, ":")
		}
	}
}

func absFromSourceDir(sourceDir, path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(filepath.Join(sourceDir, path))
}

func documentMapping(doc *yaml.Node) *yaml.Node {
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		doc = doc.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return nil
	}
	return doc
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func ensureMapping(m *yaml.Node, key string) *yaml.Node {
	if found := mappingValue(m, key); found != nil && found.Kind == yaml.MappingNode {
		return found
	}
	child := &yaml.Node{Kind: yaml.MappingNode}
	m.Content = append(m.Content, scalarNode(key), child)
	return child
}

func setScalar(m *yaml.Node, key, value string) {
	if found := mappingValue(m, key); found != nil {
		found.Kind = yaml.ScalarNode
		found.Tag = "!!str"
		found.Value = value
		found.Content = nil
		return
	}
	m.Content = append(m.Content, scalarNode(key), scalarNode(value))
}

func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

func scalarValue(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func removeMappingKey(m *yaml.Node, key string) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

func rewriteNodeMgmtIPs(root *yaml.Node, subnet string) error {
	nodes := mappingValue(mappingValue(root, "topology"), "nodes")
	if nodes == nil || nodes.Kind != yaml.MappingNode {
		return fmt.Errorf("topology YAML is missing topology.nodes")
	}
	for i := 0; i+1 < len(nodes.Content); i += 2 {
		nodeName := nodes.Content[i].Value
		node := nodes.Content[i+1]
		mgmtIPNode := mappingValue(node, "mgmt-ipv4")
		if mgmtIPNode == nil {
			continue
		}
		ip, err := netip.ParseAddr(mgmtIPNode.Value)
		if err != nil {
			return fmt.Errorf("%s mgmt-ipv4 %s: %w", nodeName, mgmtIPNode.Value, err)
		}
		next, err := hostInSubnet(subnet, ip)
		if err != nil {
			return fmt.Errorf("%s mgmt-ipv4 %s: %w", nodeName, mgmtIPNode.Value, err)
		}
		mgmtIPNode.Value = next
	}
	return nil
}

func hostInSubnet(subnet string, old netip.Addr) (string, error) {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return "", err
	}
	if !old.Is4() || !prefix.Addr().Is4() || prefix.Bits() != 24 {
		return "", fmt.Errorf("only IPv4 /24 management subnets are supported")
	}
	base := prefix.Addr().As4()
	host := old.As4()[3]
	if host == 0 || host == 255 {
		return "", fmt.Errorf("host octet %d is not usable in %s", host, subnet)
	}
	base[3] = host
	next := netip.AddrFrom4(base)
	if !prefix.Contains(next) {
		return "", fmt.Errorf("%s is outside %s", next, subnet)
	}
	return next.String(), nil
}

func validateIPv4Subnet24(subnet string) error {
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return err
	}
	if !prefix.Addr().Is4() || prefix.Bits() != 24 {
		return fmt.Errorf("management subnet must be an IPv4 /24, got %s", subnet)
	}
	return nil
}

var suffixChars = regexp.MustCompile(`[^a-z0-9-]+`)
var trailingDigits = regexp.MustCompile(`(\d+)$`)

func normalizeLabSuffix(suffix string) (string, error) {
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	suffix = strings.ReplaceAll(suffix, "_", "-")
	suffix = suffixChars.ReplaceAllString(suffix, "-")
	suffix = strings.Trim(suffix, "-")
	if strings.Contains(suffix, "--") {
		for strings.Contains(suffix, "--") {
			suffix = strings.ReplaceAll(suffix, "--", "-")
		}
	}
	if len(suffix) > 40 {
		return "", fmt.Errorf("suffix %q is too long; use 40 characters or fewer", suffix)
	}
	return suffix, nil
}

func subnetOctetFromSuffix(suffix string) int {
	if match := trailingDigits.FindStringSubmatch(suffix); len(match) == 2 {
		if n, err := strconv.Atoi(match[1]); err == nil && n > 0 && n < 255 {
			return n
		}
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(suffix))
	return int(h.Sum32()%254) + 1
}
