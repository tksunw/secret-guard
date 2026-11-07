# secret-guard

A Claude Code mod that stops Claude from committing or pushing secrets.

It hooks the Bash tool. When a command runs `git commit` or `git push` (directly, through `rtk`, after a `cd`, or with `git -C`), the mod inspects what that command would publish and refuses the call if it finds a secret. Claude gets the file, line and pattern in the refusal, with the fix.

What it checks:

- **Commit:** staged files and staged added lines. When the same command also runs `git add`, or the commit uses `-a`, it widens the check to tracked working-tree changes and untracked files that are not gitignored.
- **Push:** every commit on `HEAD` that no remote-tracking branch holds yet (`git log HEAD --not --remotes`), so a secret committed earlier and deleted later is still caught before it leaves the machine.
- **Unignored secret files:** a commit that is otherwise clean raises a toast naming any untracked secret file the repo does not ignore.

Secret files by name: `.env` and `.env.*` (not `.example`, `.sample`, `.template`, `.dist`), `.claude/settings.local.json` (Claude Code's "don't ask again" rules, which hold the exact commands you approved, inline credentials included), `.apikeys*`, `*.key`, `*.pfx`, `*.p12`, `*.jks`, `*.keystore`, `*.kdbx`, `*.ppk`, `*.tfstate`, `terraform.tfvars`, SSH private keys, Oracle wallets (`cwallet.sso`, `ewallet.p12`), `credentials`, `.netrc`, `.pgpass`, `.git-credentials`.

Secret lines by content: private key blocks, AWS access keys, GitHub, GitLab, npm, Anthropic, OpenAI and Slack tokens, Azure storage and shared access keys, SAS signatures, JWTs, `Password=` in connection strings, credentials in URLs, `password|secret|api_key|client_secret|token = "<literal>"` assignments, inline env vars such as `PGPASSWORD=<literal>` or `DB_PASSWORD=<literal>`, and passwords given on a command line (`sshpass -p`, `mysql -p<literal>`, `docker login -p`, `az login -p`, `--password`, `--token`, `-passin`, `curl -u user:pass`). Placeholders and lookups (`${var.x}`, `$(cmd)`, `lookup(...)`, `os.environ`, `changeme`, `CHANGE_ME`, `test-key`, `<...>`, and prose values like `choose_a_strong_password`) are skipped.

## False positives

Add a path glob to `.secret-guard-allow` at the repo root, one per line, `#` for comments. `*` matches within a path segment, `**` across segments.

```
# Public test fixtures
tests/fixtures/*.key
```

Only you edit this file. The mod refuses Claude's Edit and Write calls on it. It also refuses any shell line that would write to it, move it or delete it: redirects, `tee`, `sed -i`, `cp`/`mv`/`rm`/`touch`, `git checkout`/`restore`, the PowerShell `*-Content`/`*-Item` cmdlets, and Python or Node file writes. Reads and plain mentions pass, including `cd repo && cat .secret-guard-allow` and a heredoc that only names the file. The check guards against Claude editing the list by mistake. It is not proof against deliberate obfuscation.

## Limits

It guards Claude's tool calls only. Commits you make in your own shell are not checked; pair it with a git pre-commit hook such as gitleaks if you want that too. The command parsing follows `cd`, `&&`, `;`, `|` and `git -C`; it is not a full shell parser.

## Install

```
/plugin install secret-guard --marketplace tksunw/claude-plugins
```

Or clone this repo and point Claude Code at it, either through the mods folder:

```bash
git clone <repo-url> ~/REPOS/secret-guard
ln -s ~/REPOS/secret-guard ~/.claude/mods/secret-guard
```

with `~/.claude/settings.json` holding `"env": { "CLAUDE_CODE_PLUGIN_DIRS": "~/.claude/mods" }`, or for one session with `claude --plugin-dir ~/REPOS/secret-guard`.

On Windows, use `New-Item -ItemType SymbolicLink -Path "$env:USERPROFILE\.claude\mods\secret-guard" -Target "$env:USERPROFILE\REPOS\secret-guard"`.

## Update

```bash
git -C ~/REPOS/secret-guard pull
```

A running session reloads the mod when the folder changes.

## Develop

```bash
claude plugin validate .
claude plugin test .
```
