---
name: gh-pr-resolve-conflicts
description: Check a GitHub pull request for merge conflicts after it is created and resolve them when present. Use after Codex creates, opens, publishes, updates, or is asked to maintain a PR; inspect GitHub mergeability, compare the PR head with the base branch, merge or rebase the base branch locally when needed, fix conflict markers, validate the result, commit the resolution, and push the PR branch.
---

# GitHub PR Conflict Resolution

## Overview

After creating or updating a PR, verify that it can merge cleanly into its base branch. If GitHub or a local merge check reports conflicts, resolve them in the PR branch, run relevant validation, commit the resolution, and push.

## Workflow

1. Identify the PR and its branches.
   - Prefer the current branch PR: `gh pr view --json number,url,baseRefName,headRefName,mergeable,mergeStateStatus`.
   - If the user provided a PR number or URL, use that PR explicitly.
   - Confirm the head branch is editable. If the PR is from a fork or `maintainerCanModify` is false, report the blocker before changing anything.

2. Inspect mergeability.
   - Use `mergeStateStatus` and `mergeable` from `gh pr view`.
   - Treat `DIRTY`, `CONFLICTING`, or an explicit GitHub conflict message as requiring resolution.
   - If GitHub returns `UNKNOWN` or stale-looking data, perform a local check by fetching the base branch and attempting the integration locally.

3. Protect unrelated local work.
   - Run `git status --short` before checking out or merging.
   - If the current worktree is dirty with unrelated changes, create or use a clean worktree for the PR branch instead of stashing or overwriting files.
   - Never stage or commit unrelated local changes while resolving PR conflicts.

4. Reproduce and resolve conflicts locally.
   - Fetch both branches:

     ```bash
     git fetch origin <base-branch> <head-branch>
     ```

   - Check out the PR head branch.
   - Prefer merging the latest base branch into the PR branch for conflict resolution unless the repository or user explicitly prefers rebasing:

     ```bash
     git merge origin/<base-branch>
     ```

   - Resolve every conflict marker (`<<<<<<<`, `=======`, `>>>>>>>`) using the intent of both sides, not by blindly choosing one side.
   - Use `git diff --check` and `rg '^(<<<<<<<|=======|>>>>>>>)'` before committing.

5. Validate the resolved branch.
   - Run the most relevant tests or validators for the files touched by the PR.
   - If no project-specific tests are available, at minimum run syntax or formatting checks that apply and inspect the final diff.
   - If validation cannot run, record the reason in the final response.

6. Commit and push the resolution.
   - Stage only files changed by the conflict resolution.
   - Use a terse commit message such as `Resolve PR merge conflicts`.
   - Push the PR branch.
   - Re-check the PR with `gh pr view --json mergeable,mergeStateStatus,url` and report the final state.

## Local Conflict Check

Use this when GitHub's mergeability is unknown or delayed:

```bash
git fetch origin <base-branch> <head-branch>
git switch <head-branch>
git merge --no-commit --no-ff origin/<base-branch>
```

If the merge succeeds and this was only a check, abort it with:

```bash
git merge --abort
```

If the merge reports conflicts, continue resolving them and commit the merge once the files are correct.

## Reporting

Final responses should include the PR URL, whether conflicts were found, the resolution commit if one was created, validation performed, and any remaining GitHub merge state or check failures.
