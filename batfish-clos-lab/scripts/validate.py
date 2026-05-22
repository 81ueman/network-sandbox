#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from pybatfish.client.session import Session
from pybatfish.datamodel.flow import HeaderConstraints


LAB_DIR = Path(__file__).resolve().parents[1]
SNAPSHOT_DIR = LAB_DIR / "snapshot"
NETWORK = "batfish-clos-lab"
SNAPSHOT = "base"
FAILURE_SNAPSHOTS = {
    "fail-spine1-leaf1": {
        "path": LAB_DIR / "snapshot-fail-spine1-leaf1",
        "leaf1_next_hops": {"192.0.2.2"},
        "leaf1_absent_next_hops": {"192.0.2.0"},
        "leaf2_next_hops": {"192.0.2.6"},
        "leaf2_absent_next_hops": {"192.0.2.4"},
    },
    "fail-spine2-leaf1": {
        "path": LAB_DIR / "snapshot-fail-spine2-leaf1",
        "leaf1_next_hops": {"192.0.2.0"},
        "leaf1_absent_next_hops": {"192.0.2.2"},
        "leaf2_next_hops": {"192.0.2.4"},
        "leaf2_absent_next_hops": {"192.0.2.6"},
    },
    "fail-spine1-leaf2": {
        "path": LAB_DIR / "snapshot-fail-spine1-leaf2",
        "leaf1_next_hops": {"192.0.2.2"},
        "leaf1_absent_next_hops": {"192.0.2.0"},
        "leaf2_next_hops": {"192.0.2.6"},
        "leaf2_absent_next_hops": {"192.0.2.4"},
    },
    "fail-spine2-leaf2": {
        "path": LAB_DIR / "snapshot-fail-spine2-leaf2",
        "leaf1_next_hops": {"192.0.2.0"},
        "leaf1_absent_next_hops": {"192.0.2.2"},
        "leaf2_next_hops": {"192.0.2.4"},
        "leaf2_absent_next_hops": {"192.0.2.6"},
    },
}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def frame_text(frame) -> str:
    return frame.to_string(index=False)


def assert_accepted_trace(bf: Session, src: str, dst: str, start: str) -> None:
    traces = bf.q.traceroute(
        startLocation=start,
        headers=HeaderConstraints(srcIps=src, dstIps=dst, ipProtocols=["ICMP"]),
    ).answer().frame()
    if traces.empty:
        fail(f"{start} -> {dst} traceroute returned no rows")
    text = frame_text(traces)
    if "ACCEPTED" not in text:
        print(text)
        fail(f"{start} -> {dst} was not accepted")


def assert_ecmp_route(bf: Session, node: str, prefix: str, expected_next_hops: set[str]) -> None:
    routes = bf.q.routes(nodes=node, network=prefix).answer().frame()
    if routes.empty:
        fail(f"{node} has no route to {prefix}")
    text = frame_text(routes)
    missing = [next_hop for next_hop in expected_next_hops if next_hop not in text]
    if missing:
        print(text)
        fail(f"{node} route to {prefix} is missing ECMP next-hop(s): {', '.join(missing)}")
    print(f"PASS: {node} has ECMP route to {prefix} via {', '.join(sorted(expected_next_hops))}")


def assert_route_next_hops(
    bf: Session,
    node: str,
    prefix: str,
    expected_next_hops: set[str],
    absent_next_hops: set[str] | None = None,
) -> None:
    routes = bf.q.routes(nodes=node, network=prefix).answer().frame()
    if routes.empty:
        fail(f"{node} has no route to {prefix}")
    text = frame_text(routes)
    missing = [next_hop for next_hop in expected_next_hops if next_hop not in text]
    if missing:
        print(text)
        fail(f"{node} route to {prefix} is missing expected next-hop(s): {', '.join(missing)}")
    unexpected = [next_hop for next_hop in absent_next_hops or set() if next_hop in text]
    if unexpected:
        print(text)
        fail(f"{node} route to {prefix} still has failed next-hop(s): {', '.join(unexpected)}")
    print(f"PASS: {node} route to {prefix} uses expected next-hop(s): {', '.join(sorted(expected_next_hops))}")


def validate_snapshot_health(bf: Session) -> None:
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


def validate_topology_and_bgp(bf: Session) -> None:
    l3_edges = bf.q.layer3Edges().answer().frame()
    edge_text = frame_text(l3_edges)
    for expected in ("spine1", "spine2", "leaf1", "leaf2", "client1", "client2"):
        if expected not in edge_text:
            fail(f"missing {expected} in layer3Edges output")
    print("PASS: expected nodes appear in layer3 edges")

    bgp_edges = bf.q.bgpEdges().answer().frame()
    bgp_text = frame_text(bgp_edges)
    for expected in ("spine1", "spine2", "leaf1", "leaf2", "client1", "client2"):
        if expected not in bgp_text:
            print(bgp_text)
            fail(f"missing {expected} in BGP edges output")
    print("PASS: expected nodes appear in BGP edges")


def validate_reachability(bf: Session) -> None:
    assert_accepted_trace(bf, src="10.10.1.1", dst="10.10.2.1", start="client1")
    print("PASS: client1 loopback can reach client2 loopback")
    assert_accepted_trace(bf, src="10.10.2.1", dst="10.10.1.1", start="client2")
    print("PASS: client2 loopback can reach client1 loopback")


def main() -> int:
    bf = Session(host="localhost")
    bf.set_network(NETWORK)
    print(f"== Validating {SNAPSHOT} ==")
    bf.init_snapshot(str(SNAPSHOT_DIR), name=SNAPSHOT, overwrite=True)
    validate_snapshot_health(bf)
    validate_topology_and_bgp(bf)
    validate_reachability(bf)

    assert_ecmp_route(bf, "leaf1", "10.10.2.1/32", {"192.0.2.0", "192.0.2.2"})
    assert_ecmp_route(bf, "leaf2", "10.10.1.1/32", {"192.0.2.4", "192.0.2.6"})

    for snapshot_name, scenario in FAILURE_SNAPSHOTS.items():
        path = scenario["path"]
        if not path.exists():
            continue
        print(f"== Validating {snapshot_name} ==")
        bf.init_snapshot(str(path), name=snapshot_name, overwrite=True)
        validate_snapshot_health(bf)
        validate_reachability(bf)
        assert_route_next_hops(
            bf,
            "leaf1",
            "10.10.2.1/32",
            scenario["leaf1_next_hops"],
            scenario.get("leaf1_absent_next_hops"),
        )
        assert_route_next_hops(
            bf,
            "leaf2",
            "10.10.1.1/32",
            scenario["leaf2_next_hops"],
            scenario.get("leaf2_absent_next_hops"),
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
