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
TOPOLOGY_FILE = LAB_DIR / "batfish-firewall.clab.yml"
SNAPSHOT_DIR = LAB_DIR / "snapshot"

CEOS_NODES = ("r1", "r2")
FRR_NODES = ("client", "server")
FW_NODE = "fw"
MGMT_INTERFACES = {"eth0", "Management0", "lo"}


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


def eos_running_config(node: str) -> str:
    config = docker_exec(node, "Cli", "-p", "15", "-c", "show running-config")
    lines = config.splitlines()
    lines = [line for line in lines if not line.startswith("> ")]
    lines = sanitize_eos(lines)
    if not lines or not lines[0].startswith("!RANCID-CONTENT-TYPE: arista"):
        lines.insert(0, "!RANCID-CONTENT-TYPE: arista")
    return "\n".join(lines).rstrip() + "\n"


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


def sanitize_frr(config: str) -> str:
    unsupported = {"log stdout"}
    lines = [line for line in config.splitlines() if line not in unsupported]
    return "\n".join(lines).rstrip() + "\n"


def frr_config(node: str) -> str:
    return sanitize_frr(docker_exec(node, "cat", "/etc/frr/frr.conf"))


def interface_prefixes(node: str) -> dict[str, list[str]]:
    data = json.loads(docker_exec(node, "ip", "-j", "address", "show"))
    interfaces: dict[str, list[str]] = {}
    for iface in data:
        name = iface["ifname"]
        if name in MGMT_INTERFACES or not name.startswith("eth"):
            continue
        prefixes = []
        for addr in iface.get("addr_info", []):
            if addr.get("family") == "inet":
                prefixes.append(f"{addr['local']}/{addr['prefixlen']}")
        if prefixes:
            interfaces[name] = prefixes
    return interfaces


def static_routes(node: str) -> list[tuple[str, str]]:
    data = json.loads(docker_exec(node, "ip", "-j", "route", "show"))
    routes: list[tuple[str, str]] = []
    for route in data:
        dst = route.get("dst")
        gateway = route.get("gateway")
        dev = route.get("dev")
        if not dst or not gateway:
            continue
        if dst == "default" or dev in MGMT_INTERFACES:
            continue
        routes.append((dst, gateway))
    return routes


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


def synthetic_frr_config(node: str, prefixes: dict[str, list[str]], routes: list[tuple[str, str]]) -> str:
    lines = [
        "frr version 10.6.1",
        "frr defaults traditional",
        f"hostname {node}",
        "service integrated-vtysh-config",
        "!",
    ]
    for iface, iface_prefixes in sorted(prefixes.items()):
        lines.append(f"interface {iface}")
        for prefix in iface_prefixes:
            lines.append(f" ip address {prefix}")
        lines.append("!")
    for dst, gateway in routes:
        lines.append(f"ip route {dst} {gateway}")
    lines.extend(["!", "line vty", ""])
    return "\n".join(lines)


def filter_table(iptables_save: str) -> str:
    lines = iptables_save.splitlines()
    in_filter = False
    output: list[str] = []
    for line in lines:
        if line == "*filter":
            in_filter = True
        if in_filter:
            output.append(line)
        if in_filter and line == "COMMIT":
            break
    if not output:
        raise SystemExit("iptables-save output did not include a *filter table")
    return "\n".join(output).rstrip() + "\n"


def host_policy_json() -> str:
    # Batfish can parse and test this host's iptables policy, but does not fully
    # model a Linux FORWARD chain as a transit dataplane node. Keep policy
    # validation separate from the dataplane node named "fw".
    return json.dumps(
        {
            "hostname": "fw-policy",
            "iptablesFile": "iptables/fw.iptables",
            "hostInterfaces": {
                "eth1": {
                    "name": "eth1",
                    "prefix": "192.0.2.254/32",
                }
            },
        },
        indent=2,
    ) + "\n"


def normalize_interface(node: str, interface: str, kinds: dict[str, str]) -> str:
    if kinds.get(node) == "arista_ceos":
        match = re.fullmatch(r"eth(\d+)", interface)
        if match:
            return f"Ethernet{match.group(1)}"
    return interface


def layer1_topology() -> str:
    topology = yaml.safe_load(TOPOLOGY_FILE.read_text(encoding="utf-8"))
    nodes = topology["topology"]["nodes"]
    kinds = {name: attrs["kind"] for name, attrs in nodes.items()}
    edges = []
    for link in topology["topology"]["links"]:
        left, right = link["endpoints"]
        node1, iface1 = left.split(":", 1)
        node2, iface2 = right.split(":", 1)
        edges.append(
            {
                "node1": node1,
                "interface1": normalize_interface(node1, iface1, kinds),
                "node2": node2,
                "interface2": normalize_interface(node2, iface2, kinds),
            }
        )
    return json.dumps({"edges": edges}, indent=2) + "\n"


def collect(snapshot_dir: Path) -> None:
    for node in CEOS_NODES:
        write(snapshot_dir / "configs" / f"{node}.cfg", eos_running_config(node))

    for node in FRR_NODES:
        config = frr_config(node)
        write(
            snapshot_dir / "configs" / f"{node}.cfg",
            cumulus_config(node, config, interface_prefixes(node)),
        )

    fw_prefixes = interface_prefixes(FW_NODE)
    fw_routes = static_routes(FW_NODE)
    fw_frr = synthetic_frr_config(FW_NODE, fw_prefixes, fw_routes)
    write(snapshot_dir / "configs" / "fw.cfg", cumulus_config(FW_NODE, fw_frr, fw_prefixes))

    iptables_save = docker_exec(FW_NODE, "iptables-save")
    write(snapshot_dir / "iptables" / "fw.iptables", filter_table(iptables_save))
    write(snapshot_dir / "hosts" / "fw.json", host_policy_json())
    write(snapshot_dir / "batfish" / "layer1_topology.json", layer1_topology())


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect a Batfish snapshot from the running lab.")
    parser.add_argument(
        "--snapshot-dir",
        type=Path,
        default=SNAPSHOT_DIR,
        help="Snapshot directory to write. Defaults to ./snapshot.",
    )
    args = parser.parse_args()
    collect(args.snapshot_dir.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
