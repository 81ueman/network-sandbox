# SR Linux YANG Models

This directory is for local SR Linux YANG model checkouts used with `gnmic`.
The model repository itself is intentionally ignored by git.

## Setup

The OSPF lab currently uses `ghcr.io/nokia/srlinux:25.10`, so use a matching
25.10 model tag:

```bash
git clone -b v25.10.3 --depth 1 https://github.com/nokia/srlinux-yang-models.git \
  tools/yang/srlinux-yang-models
```

## Example

Generate config paths from the native OSPF model:

```bash
gnmic \
  --file tools/yang/srlinux-yang-models/srlinux-yang-models/srl_nokia/models/network-instance/srl_nokia-ospf.yang \
  --dir tools/yang/srlinux-yang-models/srlinux-yang-models/srl_nokia/models \
  --dir tools/yang/srlinux-yang-models/srlinux-yang-models/ietf \
  --dir tools/yang/srlinux-yang-models/srlinux-yang-models/iana \
  path --config-only --types
```
