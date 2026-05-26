# recursive-nexthop

Scenario lab for modeled recursive next-hop resolution and diagnostics for
routes that cannot be mapped to a topology data-plane interface. It currently
reuses the base WAN topology while keeping the scenario metadata and examples
separate from broader WAN checks.

Examples:

```bash
go run ./cmd/hoyan model rib --lab labs/recursive-nexthop --node core-bj
go run ./cmd/hoyan model fib --lab labs/recursive-nexthop --node core-bj
go run ./cmd/hoyan fib-compare --lab labs/recursive-nexthop
go run ./cmd/hoyan live-check --lab labs/recursive-nexthop --snapshot labs/recursive-nexthop/snapshots/latest.json --offline
```
