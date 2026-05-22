#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml


LAB_DIR = Path(__file__).resolve().parents[1]
TOPOLOGY_FILE = LAB_DIR / "batfish-clos.clab.yml"
SNAPSHOT_DIR = LAB_DIR / "snapshot"

CEOS_NODES = ("spine1", "spine2", "leaf1", "leaf2")
FRR_NODES = ("client1", "client2")
MGMT_INTERFACES = {"eth0", "Management0"}
FAILURES = {
    "spine1-leaf1": ("spine1", "Ethernet1", "leaf1", "Ethernet1"),
    "spine2-leaf1": ("spine2", "Ethernet1", "leaf1", "Ethernet2"),
    "spine1-leaf2": ("spine1", "Ethernet2", "leaf2", "Ethernet1"),
    "spine2-leaf2": ("spine2", "Ethernet2", "leaf2", "Ethernet2"),
}

def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"command failed: {' '.join(cmd)}")
    return result.stdout


def docker_exec(node: str, *cmd: str) -> str:
    return run(["docker", "exec", node, *cmd])


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"wrote {path.relative_to(LAB_DIR)}")


def sanitize_eos(lines: list[str]) -> list[str]:
    sanitized: list[str] = []
    skip_system_l1 = False
    for line in lines:
        if line == "system l1":
            skip_system_l1 = True
            continue
        if skip_system_l1:
            if line == "!":
                skip_system_l1 = False
            continue
        sanitized.append(line)
    return sanitized


def eos_running_config(node: str) -> str:
    config = docker_exec(node, "Cli", "-p", "15", "-c", "show running-config")
    lines = [line for line in config.splitlines() if not line.startswith("> ")]
    lines = sanitize_eos(lines)
    if not lines or not lines[0].startswith("!RANCID-CONTENT-TYPE: arista"):
        lines.insert(0, "!RANCID-CONTENT-TYPE: arista")
    return "\n".join(lines).rstrip() + "\n"


def failure_interfaces(node: str, failure: str | None) -> set[str]:
    if not failure:
        return set()
    node1, iface1, node2, iface2 = FAILURES[failure]
    interfaces = set()
    if node == node1:
        interfaces.add(iface1)
    if node == node2:
        interfaces.add(iface2)
    return interfaces


def shutdown_eos_interfaces(config: str, interfaces: set[str]) -> str:
    if not interfaces:
        return config
    output: list[str] = []
    current_interface: str | None = None
    shutdown_written = False
    for line in config.splitlines():
        if line.startswith("interface "):
            if current_interface in interfaces and not shutdown_written:
                output.append("   shutdown")
            current_interface = line.split(maxsplit=1)[1]
            shutdown_written = False
            output.append(line)
            continue
        if line == "!":
            if current_interface in interfaces and not shutdown_written:
                output.append("   shutdown")
            current_interface = None
            shutdown_written = False
            output.append(line)
            continue
        if current_interface in interfaces and line.strip() == "shutdown":
            shutdown_written = True
        output.append(line)
    if current_interface in interfaces and not shutdown_written:
        output.append("   shutdown")
    return "\n".join(output).rstrip() + "\n"


def sanitize_frr(config: str) -> str:
    unsupported = {"log stdout", "no bgp ebgp-requires-policy", "exit"}
    lines = [line for line in config.splitlines() if line.strip() not in unsupported]
    return "\n".join(lines).rstrip() + "\n"


def frr_config(node: str) -> str:
    return sanitize_frr(docker_exec(node, "cat", "/etc/frr/frr.conf"))


def interface_prefixes(node: str) -> dict[str, list[str]]:
    data = json.loads(docker_exec(node, "ip", "-j", "address", "show"))
    interfaces: dict[str, list[str]] = {}
    for iface in data:
        name = iface["ifname"]
        if name in MGMT_INTERFACES or name.startswith("sit") or name.startswith("tunl"):
            continue
        prefixes = []
        for addr in iface.get("addr_info", []):
            if addr.get("family") == "inet":
                prefixes.append(f"{addr['local']}/{addr['prefixlen']}")
        if prefixes:
            interfaces[name] = prefixes
    return interfaces


def hostname_from_frr(config: str, fallback: str) -> str:
    match = re.search(r"^hostname\s+(\S+)$", config, flags=re.MULTILINE)
    return match.group(1) if match else fallback


def cumulus_config(node: str, frr: str, prefixes: dict[str, list[str]]) -> str:
    hostname = hostname_from_frr(frr, node)
    iface_lines = [hostname, "# This file describes the network interfaces"]
    for iface, iface_prefixes in sorted(prefixes.items()):
        iface_lines.append(f"auto {iface}")
        iface_lines.append(f"iface {iface}")
        for prefix in iface_prefixes:
            iface_lines.append(f"    address {prefix}")
        iface_lines.append("")
    iface_lines.append("# ports.conf --")
    iface_lines.append("")
    return "\n".join(iface_lines).rstrip() + "\n\n" + frr


def normalize_interface(node: str, interface: str, kinds: dict[str, str]) -> str:
    if kinds.get(node) == "arista_ceos":
        match = re.fullmatch(r"eth(\d+)", interface)
        if match:
            return f"Ethernet{match.group(1)}"
    return interface


def edge_matches_failure(edge: dict[str, str], failure: tuple[str, str, str, str]) -> bool:
    node1, iface1, node2, iface2 = failure
    return (
        edge["node1"] == node1
        and edge["interface1"] == iface1
        and edge["node2"] == node2
        and edge["interface2"] == iface2
    ) or (
        edge["node1"] == node2
        and edge["interface1"] == iface2
        and edge["node2"] == node1
        and edge["interface2"] == iface1
    )


def layer1_topology(failure: str | None = None) -> str:
    topology = yaml.safe_load(TOPOLOGY_FILE.read_text(encoding="utf-8"))
    nodes = topology["topology"]["nodes"]
    kinds = {name: attrs["kind"] for name, attrs in nodes.items()}
    edges = []
    failed_edge = FAILURES[failure] if failure else None
    for link in topology["topology"]["links"]:
        left, right = link["endpoints"]
        node1, iface1 = left.split(":", 1)
        node2, iface2 = right.split(":", 1)
        edge = {
            "node1": node1,
            "interface1": normalize_interface(node1, iface1, kinds),
            "node2": node2,
            "interface2": normalize_interface(node2, iface2, kinds),
        }
        if failed_edge and edge_matches_failure(edge, failed_edge):
            continue
        edges.append(edge)
    return json.dumps({"edges": edges}, indent=2) + "\n"


def collect(snapshot_dir: Path, failure: str | None = None) -> None:
    for node in CEOS_NODES:
        config = eos_running_config(node)
        config = shutdown_eos_interfaces(config, failure_interfaces(node, failure))
        write(snapshot_dir / "configs" / f"{node}.cfg", config)

    for node in FRR_NODES:
        config = frr_config(node)
        write(
            snapshot_dir / "configs" / f"{node}.cfg",
            cumulus_config(node, config, interface_prefixes(node)),
        )

    write(snapshot_dir / "batfish" / "layer1_topology.json", layer1_topology(failure=failure))


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect a Batfish snapshot from the running CLOS lab.")
    parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=None,
        help="Snapshot directory to write. Defaults to ./snapshot.",
    )
    parser.add_argument(
        "--failure",
        choices=sorted(FAILURES),
        help="Generate a failure snapshot by removing one fabric link from layer1_topology.json.",
    )
    args = parser.parse_args()
    snapshot_dir = args.snapshot_dir
    if snapshot_dir is None:
        snapshot_dir = LAB_DIR / f"snapshot-fail-{args.failure}" if args.failure else SNAPSHOT_DIR
    collect(snapshot_dir.resolve(), failure=args.failure)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
