#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints


LAB_DIR = Path(__file__).resolve().parents[1]
SNAPSHOT_DIR = LAB_DIR / "snapshot"
NETWORK = "batfish-firewall-lab"
SNAPSHOT = "base"


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def trace_text(row) -> str:
    return str(row.get("Traces", "")) + "\n" + str(row.get("Flow", ""))


def first_action(frame) -> str:
    text = frame.to_string(index=False)
    if "DENY" in text:
        return "DENY"
    if "PERMIT" in text:
        return "PERMIT"
    return text


def main() -> int:
    bf = Session(host="localhost")
    bf.set_network(NETWORK)
    bf.init_snapshot(str(SNAPSHOT_DIR), name=SNAPSHOT, overwrite=True)

    parse_status = bf.q.fileParseStatus().answer().frame()
    failed_parse = parse_status[parse_status["Status"] != "PASSED"]
    if not failed_parse.empty:
        print(failed_parse.to_string(index=False))
        fail("Batfish failed to parse one or more snapshot files")
    print("PASS: all snapshot files parsed")

    init_issues = bf.q.initIssues().answer().frame()
    if not init_issues.empty:
        print("INFO: Batfish initialization issues/warnings:")
        print(init_issues.to_string(index=False))

    l3_edges = bf.q.layer3Edges().answer().frame()
    edge_text = l3_edges.to_string(index=False)
    for expected in ("client", "r1", "fw", "r2", "server"):
        if expected not in edge_text:
            fail(f"missing {expected} in layer3Edges output")
    print("PASS: expected nodes appear in layer3 edges")

    http = bf.q.traceroute(
        startLocation="client",
        headers=HeaderConstraints(
            srcIps="10.10.10.10",
            dstIps="10.20.20.10",
            ipProtocols=["TCP"],
            dstPorts="80",
        ),
    ).answer().frame()
    if http.empty:
        fail("HTTP traceroute returned no rows")
    http_text = "\n".join(trace_text(row) for _, row in http.iterrows())
    if "ACCEPTED" not in http_text:
        print(http.to_string(index=False))
        fail("HTTP flow was not accepted")
    if "10.0.23.2" not in http_text:
        print(http.to_string(index=False))
        fail("HTTP flow did not use fw-to-r2 next hop")
    print("PASS: client -> server TCP/80 is accepted via fw")

    http_filter = bf.q.testFilters(
        nodes="fw-policy",
        filters="filter::FORWARD",
        startLocation="fw-policy[eth1]",
        headers=HeaderConstraints(
            srcIps="10.10.10.10",
            dstIps="10.20.20.10",
            ipProtocols=["TCP"],
            dstPorts="80",
        ),
    ).answer().frame()
    if first_action(http_filter) != "PERMIT":
        print(http_filter.to_string(index=False))
        fail("iptables FORWARD policy does not permit TCP/80")
    print("PASS: iptables FORWARD permits TCP/80")

    ssh_filter = bf.q.testFilters(
        nodes="fw-policy",
        filters="filter::FORWARD",
        startLocation="fw-policy[eth1]",
        headers=HeaderConstraints(
            srcIps="10.10.10.10",
            dstIps="10.20.20.10",
            ipProtocols=["TCP"],
            dstPorts="22",
        ),
    ).answer().frame()
    if first_action(ssh_filter) != "DENY":
        print(ssh_filter.to_string(index=False))
        fail("iptables FORWARD policy does not deny TCP/22")
    print("PASS: iptables FORWARD denies TCP/22")

    r1_routes = bf.q.routes(nodes="r1", network="10.20.20.0/24").answer().frame()
    routes_text = r1_routes.to_string(index=False)
    if "10.0.12.2" not in routes_text:
        print(r1_routes.to_string(index=False))
        fail("r1 route to server subnet does not point at fw")
    print("PASS: r1 routes server subnet toward fw")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
