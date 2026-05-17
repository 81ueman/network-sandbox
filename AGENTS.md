# Agent Notes

## docker exec

- Use `docker exec -it` when running interactive network OS CLIs or commands
  that render output through a terminal.
- Some commands can exit successfully without printing useful output when run
  without a TTY. If a command should produce output but returns an empty result,
  retry with `-it` before assuming the command failed or produced no data.

Example:

```bash
docker exec -it <container> <cli-command>
```

## YANG Models and gNMI Paths

- Do not rely on memory when building gNMI paths. Use the device's matching
  YANG model version to discover paths, key names, config/state status, and
  value types.
- For `gnmic`, use `--file` to specify the main YANG module you want to inspect
  and `--dir` to provide directories containing imported dependency modules.
- After loading the YANG files, use `gnmic path` to generate candidate gNMI
  paths. Add `--config-only` for writable config leaves and `--types` to show
  leaf value types.

Example:

```bash
gnmic \
  --file <path-to-main-model.yang> \
  --dir <path-to-vendor-model-dir> \
  --dir <path-to-ietf-model-dir> \
  --dir <path-to-iana-model-dir> \
  path --config-only --types
```

- Generated paths often contain wildcard keys such as `[name=*]`. Replace those
  wildcards with real key values before using the path with `gnmic get` or
  `gnmic set`.
