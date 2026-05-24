package model

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

type ParsedConfig struct {
	Hostname   string
	ASN        uint32
	RouterID   string
	Loopback   string
	Interfaces []Interface
	Prefixes   []string
	Neighbors  []BGPNeighbor
}

func ParseConfig(kind, path string) (ParsedConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ParsedConfig{}, err
	}
	switch kind {
	case "frr", "ceos":
		return parseFRRLike(kind, string(data))
	case "srlinux":
		return parseSRLinux(string(data))
	default:
		return ParsedConfig{}, fmt.Errorf("unsupported config kind %q", kind)
	}
}

func parseFRRLike(kind, text string) (ParsedConfig, error) {
	var cfg ParsedConfig
	neighbors := map[string]*BGPNeighbor{}
	var currentInterface string
	inBGP := false
	inAF := false
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
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
		}
	}
	if err := scanner.Err(); err != nil {
		return ParsedConfig{}, err
	}
	for _, n := range neighbors {
		if n.Activated || kind == "srlinux" {
			cfg.Neighbors = append(cfg.Neighbors, *n)
		}
	}
	if cfg.Loopback == "" && cfg.RouterID != "" {
		cfg.Loopback = cfg.RouterID + "/32"
	}
	return cfg, nil
}

func parseSRLinux(text string) (ParsedConfig, error) {
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
