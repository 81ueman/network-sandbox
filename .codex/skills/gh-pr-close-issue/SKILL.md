---
name: gh-pr-close-issue
description: Create GitHub pull requests that close their related issues automatically. Use when Codex is asked to create, draft, open, or publish a PR and the work appears connected to a GitHub issue by branch name, commit message, user request, local notes, or issue context; ensure the PR body includes an appropriate closing keyword such as `Closes #123` so merging the PR closes the issue.
---

# GitHub PR Issue Closing

## Overview

Ensure issue-backed PRs include GitHub closing keywords in the PR body. Apply this before creating the PR and when editing an already-drafted PR body.

## Workflow

1. Determine whether the PR is issue-backed.
   - Treat it as issue-backed when the user mentions an issue number, the branch name contains an issue number, commits mention an issue, a GitHub issue was inspected for the task, or local context clearly ties the work to an issue.
   - If multiple issues are intentionally addressed, include each issue reference.
   - If the relationship is ambiguous and cannot be inferred from available context, ask before adding a closing reference.

2. Use a GitHub-recognized closing keyword in the PR body.
   - Prefer `Closes #<issue-number>` for a single issue in the same repository.
   - Use one line per issue when closing multiple issues:

     ```markdown
     Closes #123
     Closes #124
     ```

   - For a different repository, use the full `owner/repo#123` form.
   - Do not use a closing keyword for issues that are merely related, partially addressed, or used only as background. Use `Related to #123` or omit the reference instead.

3. Preserve the PR template and existing useful content.
   - Add the closing reference near the end of the body unless the repository template has a dedicated issue field.
   - If there is a checklist item or field such as `Closes`, `Fixes`, `Issue`, or `Resolves`, fill that field instead of duplicating the reference elsewhere.
   - Keep summaries, tests, screenshots, and review notes intact.

4. Verify the PR body before submitting.
   - Confirm the exact issue number and repository.
   - Confirm at least one valid closing keyword appears when the PR is issue-backed.
   - If using `gh pr create`, pass the completed body with `--body` or `--body-file`.
   - If using another GitHub tool, inspect the final body field before creation.

## Examples

Use these forms in the PR body:

```markdown
## Summary
- Add route validation for SR Linux lab configs

## Tests
- go test ./...

Closes #42
```

```markdown
Related to #42
```

Use `Related to` only when merge should not close the issue.
