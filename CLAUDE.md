# CLAUDE.md

A Claude Code mod (plugin of function hooks). Repo root is the mod folder. All logic is in `hooks/register.ts`, tests in `hooks/register.test.ts`. No build step; Claude Code loads the `.ts` directly.

Load the `plugin-authoring` skill before changing the hooks module; the mod API is early access and `claude plugin validate .` is the source of truth.

Run before committing:

```bash
claude plugin validate .   # must list only $.env.get, $.fs.read, $.process.run, $.session.cwd, $.ui.toast
claude plugin test .
```

Design rules:

- Fail open on tooling errors (git missing, not a repo, read failure): the guard must never block unrelated work. Fail closed on a match.
- A new content pattern must be specific enough that a hit is worth stopping a commit. Test it against the tracked files in `~/REPOS/*` for noise before adding it.
- `.secret-guard-allow` belongs to Tim. Never weaken the rule that blocks Claude from writing it. The shell check (`WRITES_ALLOW`) runs per line and refuses write forms; it does not refuse reads or mentions. Version 0.1.0 refused any command that named the file unless it began with a read, which blocked `cd repo && cat ...` and heredocs that only mention the file. When you add a write form, add it to the test that lists them.
