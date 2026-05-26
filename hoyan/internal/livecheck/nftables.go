package livecheck

import (
	"context"
	"fmt"
	"io"
	"sort"

	"github.com/81ueman/network-sandbox/hoyan/internal/model"
	"github.com/81ueman/network-sandbox/hoyan/internal/ribcompare"
)

const containerNftablesConfig = "/etc/hoyan/nftables.conf"

func ApplyNftablesPolicies(ctx context.Context, runner ribcompare.Runner, topo *model.Topology, out io.Writer) error {
	nodes := nftablesPolicyNodes(topo)
	for _, node := range nodes {
		if out != nil {
			fmt.Fprintf(out, "applying nftables policy on %s\n", node.Name)
		}
		script := "command -v nft >/dev/null && nft -f " + containerNftablesConfig
		if _, err := runner.Run(ctx, "docker", "exec", node.RuntimeName(), "sh", "-lc", script); err != nil {
			return fmt.Errorf("apply nftables policy on %s: %w", node.Name, err)
		}
	}
	return nil
}

func nftablesPolicyNodes(topo *model.Topology) []model.Node {
	if topo == nil {
		return nil
	}
	wanted := map[string]bool{}
	for _, acl := range topo.ACLs {
		if acl.Source.Vendor == "nftables" {
			wanted[acl.Node] = true
		}
	}
	var nodes []model.Node
	for _, node := range topo.Nodes {
		if wanted[node.Name] {
			nodes = append(nodes, node)
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return nodes
}
