# acl-semantics

Scenario lab for ACL behavior across Linux nftables, cEOS ACLs, and SR Linux
ACL policies. It currently reuses the base WAN topology and focuses on packet
queries that exercise deny, permit, multi-port permit, and live-probe coverage.

Examples:

```bash
go run ./cmd/hoyan verify --lab labs/acl-semantics --prefix-classes
go run ./cmd/hoyan model packet-classes --lab labs/acl-semantics --prefix 10.4.0.0/16
go run ./cmd/hoyan live-check --lab labs/acl-semantics --snapshot labs/acl-semantics/snapshots/latest.json --offline
```
