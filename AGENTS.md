# Agent Notes

## Repository Overview

- This repository is a collection of network sandbox labs built with
  containerlab.
- Each top-level lab directory contains a containerlab topology and related
  configuration files for that lab. Treat each directory as a separate lab
  workspace unless the user explicitly asks for cross-lab changes.
- When working inside a lab directory, inspect its `*.clab.yml` topology file,
  local `README.md`, scripts, and `configs/` before making assumptions about
  node names, links, addressing, or routing behavior.

## docker exec

- Use `docker exec -it` when running interactive network OS CLIs or commands
  that render output through a terminal.
- Some commands can exit successfully without printing useful output when run
  without a TTY. If a command should produce output but returns an empty result,
  retry with `-it` before assuming the command failed or produced no data.
- Run SR Linux `sr_cli` show commands serially, not in parallel. Parallel
  `sr_cli` sessions can contend for CLI/candidate state and return errors such
  as "There is a commit already in progress for this candidate" even when the
  requested show command is read-only.

Example:

```bash
docker exec -it <container> <cli-command>
```
