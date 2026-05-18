---
name: gnmi-yang
description: Discover YANG-backed gNMI paths and run gnmic get or set operations against SR Linux and similar network devices. Use when Codex needs to inspect, read, or change device state/config over gNMI; derive a correct path from vendor YANG models; choose key names, config/state leaves, or value types; or build gnmic commands for SR Linux in this repository.
---

# gNMI YANG

Use the device's matching YANG model version before building gNMI paths. Do not rely on memory for path names, list keys, config/state status, or leaf value types.

## Workflow

1. Identify the target device, gNMI endpoint, credentials, and intended operation: `get` or `set`.
2. Find the matching YANG model files for the device version. In this repository, SR Linux models are expected under `tools/yang/srlinux-yang-models/srlinux-yang-models/`.
3. Use `gnmic path` with the main module via `--file` and dependency directories via `--dir`.
4. Add `--config-only` when looking for writable leaves for `set`.
5. Add `--types` when the value type matters.
6. Replace generated wildcard keys such as `[name=*]` with real key values before using `gnmic get` or `gnmic set`.
7. Run the `gnmic get` or `gnmic set` command and verify the result with a follow-up `get` when changing config.

## Discover Paths

Use `--file` for the main YANG module and `--dir` for imported dependencies.

```bash
gnmic \
  --file <path-to-main-model.yang> \
  --dir <path-to-vendor-model-dir> \
  --dir <path-to-ietf-model-dir> \
  --dir <path-to-iana-model-dir> \
  path --config-only --types
```

For SR Linux models in this repository, start from these directories and adjust the main module for the feature you are working on:

```bash
YANG_ROOT=tools/yang/srlinux-yang-models/srlinux-yang-models

gnmic \
  --file "$YANG_ROOT/srl_nokia/models/network-instance/srl_nokia-network-instance.yang" \
  --dir "$YANG_ROOT/srl_nokia/models" \
  --dir "$YANG_ROOT/ietf" \
  --dir "$YANG_ROOT/iana" \
  path --config-only --types
```

Filter candidate paths with shell tools after generating them. For example:

```bash
gnmic \
  --file "$YANG_ROOT/srl_nokia/models/network-instance/srl_nokia-network-instance.yang" \
  --dir "$YANG_ROOT/srl_nokia/models" \
  --dir "$YANG_ROOT/ietf" \
  --dir "$YANG_ROOT/iana" \
  path --config-only --types | rg 'bgp|ospf|interface|metric'
```

## Read Values

Prefer explicit paths discovered from YANG:

```bash
gnmic \
  -a <target>:57400 \
  -u <user> \
  -p <password> \
  --skip-verify \
  --encoding json_ietf \
  get \
  --path '<yang-backed-gnmi-path>'
```

Example shape:

```bash
gnmic \
  -a r1:57400 \
  -u admin \
  -p '<password>' \
  --skip-verify \
  --encoding json_ietf \
  get \
  --path '/network-instance[name=default]/protocols/bgp'
```

## Set Values

Only set paths that `gnmic path --config-only --types` shows as writable config leaves. Match the value to the discovered type.

```bash
gnmic \
  -a <target>:57400 \
  -u <user> \
  -p <password> \
  --skip-verify \
  --encoding json_ietf \
  set \
  --update-path '<config-leaf-path>' \
  --update-value '<typed-value>'
```

After a `set`, immediately verify:

```bash
gnmic \
  -a <target>:57400 \
  -u <user> \
  -p <password> \
  --skip-verify \
  --encoding json_ietf \
  get \
  --path '<same-or-parent-path>'
```

## Guardrails

- Do not invent gNMI paths from CLI syntax.
- Do not use wildcard keys from generated paths directly. Replace each `*` with the actual key, such as `[name=default]` or `[interface-name=ethernet-1/1.0]`.
- Check `--types` before choosing boolean, integer, enum, string, or JSON values for `set`.
- Prefer the main module that owns the feature being inspected, then include broad dependency directories with `--dir`.
- If `gnmic path` fails due to imports, add the missing dependency directory rather than editing generated paths manually.
