---
name: hoyan-implementation-summary
description: Explain completed implementations in hoyan repository folders with concrete network-behavior examples instead of terse code summaries. Use when Codex has finished implementing a user request inside a hoyan folder or hoyan-related lab and is preparing the final response or implementation summary, especially for routing, RIB/FIB, gNMI, SR Linux, containerlab, topology, config, test, or network-control-plane changes.
---

# Hoyan Implementation Summary

## Overview

Prepare the final answer after a hoyan implementation so the user can understand what changed, why it works, and how the behavior appears in a small network example. Prefer concrete network outcomes over generic statements like "updated routing logic" or "added tests."

## Final Response Requirements

When finishing the task, include these items when relevant:

- State the concrete user-visible behavior implemented, not only the files or functions changed.
- Explain the main data flow or control-plane flow in domain terms: topology input, config input, route derivation, RIB selection, FIB/programming result, gNMI response, packet forwarding result, or generated artifact.
- Give a small example when the change affects network behavior. Use a minimal topology such as `leaf1 -- spine1 -- leaf2`, `host1 -- r1 -- host2`, or the actual lab nodes if known.
- Mention sample prefixes, next hops, interfaces, route preference, labels, communities, or policy matches when they make the behavior clearer.
- Connect the example back to the implementation: identify the module, function, config file, or test that now handles that case.
- Report verification commands or tests that were run, including meaningful results. If verification could not be run, say so directly and explain the remaining risk.
- Keep the answer concise, but make the explanation specific enough that the user can reason about the implementation without rereading the diff.

## Explanation Pattern

Use this structure unless the task is very small:

1. Start with a direct completion statement: what was implemented.
2. Add a concrete behavior example using actual or plausible lab objects.
3. Briefly map the example to the changed implementation points.
4. End with validation: tests, commands, or "not run" with reason.

## Example Style

Prefer:

"Implemented IPv4 route export filtering for the hoyan BGP lab. For example, in a `host1 -- leaf1 -- spine1 -- leaf2 -- host2` topology, a route for `10.0.2.0/24` learned on `leaf1` is now installed in the local RIB, evaluated against the export policy, and advertised to `spine1` only when the prefix set matches. The receiving node then sees the selected next hop in its RIB and programs the corresponding FIB entry toward the spine-facing interface. This is handled in `...` and covered by `...`; I verified it with `...`."

Avoid:

"Updated the BGP code and added a test."

## Scope Control

Do not invent details. If the actual topology, prefixes, RIB/FIB output, or node names are unknown, either use a clearly labeled illustrative example or say what was verified from code/tests only. Do not claim live lab verification unless the relevant commands actually ran.
