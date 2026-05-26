# base-wan

Standard multi-region Hoyan WAN lab. It covers FRR edge/customer/transit
routers, one cEOS core, one SR Linux core, BGP propagation, ACL dataplane
checks, prefix classes, recursive next-hop modeling, and RIB/FIB comparison.

Examples:

```bash
go run ./cmd/hoyan verify --lab labs/base-wan
go run ./cmd/hoyan live-check --lab labs/base-wan
go run ./cmd/hoyan rib-compare --lab labs/base-wan
go run ./cmd/hoyan fib-compare --lab labs/base-wan
go run ./cmd/hoyan rib-compare --lab labs/base-wan --snapshot labs/base-wan/snapshots/latest.json
go run ./cmd/hoyan fib-compare --lab labs/base-wan --snapshot labs/base-wan/snapshots/latest.json
go run ./cmd/hoyan live-check --lab labs/base-wan --snapshot labs/base-wan/snapshots/latest.json --offline
```
