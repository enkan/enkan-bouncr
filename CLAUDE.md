# Enkan Bouncr Project Instructions

## Language

- All code, comments, commit messages, documentation entries MUST be written in **English**.

## Improvement Proposals (ADR)

Improvement proposals and architectural decisions are tracked as GitHub Issues.

- Use `gh issue create` to file new proposals
- Include the following sections in the issue body:
  - **Rationale** — why the change is needed
  - **Scope** — what is affected
  - **Proposed direction** — concrete approach
  - **Acceptance criteria** — how to verify completion
- Label proposals with `enhancement` and a priority label (`priority:high`, `priority:medium`, `priority:low`)
- Close the issue with a reference commit (`closes #N`) when implemented
- Close with `wontfix` label when rejected, with a brief reason in a comment

## Responding to GitHub Issues and PR Reviews

### PR review comments

1. Fetch review comments (inline code comments):

   ```sh
   gh api repos/enkan/enkan-bouncr/pulls/<N>/comments
   ```

2. Fetch PR-level conversation comments:

   ```sh
   gh pr view <N> --comments
   ```

3. Evaluate each comment — determine whether it is actionable or a false positive (e.g., reviewer unaware of a migration)
4. For actionable comments: fix the code, add tests, commit, and push to the PR branch
5. Reply to an inline review comment (use `-F in_reply_to=<comment_id>` with the numeric `id` field):

   ```sh
   gh api -X POST repos/enkan/enkan-bouncr/pulls/<N>/comments \
     -f body="<reply text>" \
     -F in_reply_to=<comment_id>
   ```

   - Do NOT use `repos/.../pulls/comments/<id>/replies` — that endpoint does not exist and returns 404
   - Actionable: describe what was fixed
   - False positive: explain why no change is needed

### Issue workflow

1. Create a feature branch: `git checkout -b feature/<short-name> develop`
2. Implement the fix with tests
3. Commit with `closes #N` in the message body to auto-close the issue on merge
4. Push and create a PR: `gh pr create --base develop`
5. After merge, delete the feature branch
