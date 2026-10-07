import type { EngineInterface, Register } from 'claude-code'

// Paths that hold secrets by their name alone. Binary formats (pfx, p12, wallets) cannot be read for
// content, so their name is the only signal. Public certificates (.pem, .crt) are left to the content
// scan, which catches the private key block when one is in them.
const SECRET_NAME =
  /(^|\/)(\.env(\.[^/]+)?|\.apikeys[^/]*|\.env\.[^/]+|[^/]+\.(key|pfx|p12|jks|keystore|kdbx|ppk|tfstate|tfstate\.backup)|id_(rsa|dsa|ecdsa|ed25519)|cwallet\.sso|ewallet\.p12|credentials(\.json)?|\.netrc|\.pgpass|\.git-credentials|terraform\.tfvars)$/i
const TEMPLATE_NAME = /\.(example|sample|template|dist)$/i

// Patterns read on the lines a commit or push adds. Each is specific enough that a hit is worth a stop.
const SECRET_LINE: [string, RegExp][] = [
  ['private key', /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/],
  ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/],
  ['GitHub token', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b/],
  ['Anthropic key', /\bsk-ant-[A-Za-z0-9_-]{20,}/],
  ['OpenAI key', /\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['Azure storage key', /AccountKey=[A-Za-z0-9+/]{40,}={0,2}/],
  ['Azure shared access key', /SharedAccessKey=[A-Za-z0-9+/]{30,}={0,2}/],
  ['SAS signature', /[?&]sig=[A-Za-z0-9%+/]{30,}/],
  ['JWT', /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ['connection string password', /\b(?:Password|Pwd)=[^;'"\s]{6,}/i],
  ['URL credentials', /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s:/@]{6,}@/i],
  [
    'assigned secret',
    /\b(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|auth[_-]?token|private[_-]?key)\b["']?\s*[:=]\s*["']?(?![$<{(%]|\bnull\b|\btrue\b|\bfalse\b)[^\s"'`,;)]{8,}/i,
  ],
]
// Values on an "assigned secret" hit that are placeholders, not secrets.
const PLACEHOLDER = /changeme|change-me|example|placeholder|your[_-]|redacted|x{6,}|\*{4,}|<[^>]*>|\.\.\.|lookup|getenv|environ|process\.env|\$env:|os\.environ/i

const ALLOW_FILE = '.secret-guard-allow'
// Shell forms that write, move or delete the allow list. Checked per line, so a heredoc that only
// mentions the file (a note, a README) passes, and so does any read (`cd repo && cat ...`).
// Guards against Claude editing the list, not against deliberate obfuscation.
const AL = String.raw`\.secret-guard-allow\b`
const WRITES_ALLOW: RegExp[] = [
  new RegExp(String.raw`>{1,2}\|?\s*["']?[^\s"'<>|;&]*${AL}`), // redirect into it
  new RegExp(String.raw`\btee\b[^|;&\n]*${AL}`),
  new RegExp(String.raw`\b(?:sed|perl|ruby)\b[^|;&\n]*\s-[a-zA-Z]*i[^|;&\n]*${AL}`),
  new RegExp(String.raw`\b(?:cp|mv|rm|ln|touch|truncate|install|dd|shred|unlink|chmod|chown)\b[^|;&\n]*${AL}`),
  new RegExp(String.raw`\bgit\b[^|;&\n]*\b(?:checkout|restore|rm|mv|apply|stash)\b[^|;&\n]*${AL}`),
  new RegExp(String.raw`\b(?:Set-Content|Add-Content|Clear-Content|Out-File|New-Item|Remove-Item|Copy-Item|Move-Item|Rename-Item)\b[^|;&\n]*${AL}`, 'i'),
  new RegExp(String.raw`${AL}["'\x60]?\s*,\s*["'\x60]?[wax]`), // open('.secret-guard-allow', 'w')
  new RegExp(String.raw`(?:write_text|write_bytes|writeFile|writeFileSync|appendFile|WriteAllText|AppendAllText)\b[^\n]*${AL}`),
  new RegExp(String.raw`${AL}[^\n]*\.(?:write_text|write_bytes|unlink|rename|replace)\(`),
]

export function writesAllowFile(command: string): boolean {
  return command.split('\n').some(line => line.includes(ALLOW_FILE) && WRITES_ALLOW.some(r => r.test(line)))
}

type Git = { dir: string; sub: string; args: string[] }
type Finding = { file: string; line?: number; what: string; shown?: string }

export const register: Register = on => {
  // The allow list is Tim's to edit. Claude reading it is fine; Claude writing it would defeat the guard.
  on('tool.call', { tool: 'Edit' }, ($, e, next) => (isAllowFile(e.file_path) ? { deny: allowDeny($.plugin.name) } : next(e)))
  on('tool.call', { tool: 'Write' }, ($, e, next) => (isAllowFile(e.file_path) ? { deny: allowDeny($.plugin.name) } : next(e)))

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    if (writesAllowFile(e.command)) return { deny: allowDeny($.plugin.name) }

    const home = (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE')) ?? ''
    const calls = gitCalls(e.command, await $.session.cwd(), home)
    const adds = calls.some(c => c.sub === 'add')

    for (const call of calls) {
      if (call.sub !== 'commit' && call.sub !== 'push') continue
      const root = await gitText($, call.dir, ['rev-parse', '--show-toplevel'])
      if (root === undefined) continue
      const allow = await readAllow($, root.trim())

      const found =
        call.sub === 'commit'
          ? await scanCommit($, root.trim(), adds || call.args.some(a => a === '-a' || a === '--all' || /^-[a-zA-Z]*a/.test(a)))
          : await scanPush($, root.trim())
      const blocking = found.filter(f => !allowed(allow, f.file))

      const loose = (await untrackedSecrets($, root.trim())).filter(f => !allowed(allow, f))
      if (loose.length > 0 && blocking.length === 0) {
        $.ui.toast(`secret-guard: not gitignored in ${baseName(root.trim())}: ${loose.slice(0, 3).join(', ')}${loose.length > 3 ? ' …' : ''}`)
      }

      if (blocking.length > 0) return { deny: denyText($.plugin.name, call.sub, blocking, loose) }
    }

    return next(e)
  })
}

// --- what a command runs ---------------------------------------------------------------------

// Each git invocation in a shell command, with the directory it runs in. Follows `cd` between
// segments and `git -C`. Good enough for the commands Claude writes; not a shell parser.
export function gitCalls(command: string, cwd: string, home: string): Git[] {
  const calls: Git[] = []
  let dir = cwd
  for (const raw of command.split(/&&|\|\||;|\n|\|/)) {
    const words = tokens(raw)
    while (words.length > 0 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[0])) words.shift()
    if (words[0] === 'rtk') words.shift()
    if (words[0] === 'cd' || words[0] === 'pushd' || words[0] === 'Set-Location') {
      if (words[1] !== undefined) dir = resolve(dir, words[1], home)
      continue
    }
    if (words[0] !== 'git') continue
    let at = dir
    let i = 1
    while (i < words.length && words[i].startsWith('-')) {
      if (words[i] === '-C' && words[i + 1] !== undefined) {
        at = resolve(at, words[i + 1], home)
        i += 2
      } else if (words[i] === '-c' || words[i] === '--git-dir' || words[i] === '--work-tree') i += 2
      else i += 1
    }
    if (words[i] !== undefined) calls.push({ dir: at, sub: words[i], args: words.slice(i + 1) })
  }
  return calls
}

function tokens(text: string): string[] {
  return [...text.matchAll(/"([^"]*)"|'([^']*)'|(\S+)/g)].map(m => m[1] ?? m[2] ?? m[3])
}

function resolve(from: string, to: string, home: string): string {
  const path = to.replace(/^~(?=$|[\\/])/, home)
  if (/^([A-Za-z]:)?[\\/]/.test(path)) return path
  const parts = from.replace(/\\/g, '/').split('/')
  for (const part of path.replace(/\\/g, '/').split('/')) {
    if (part === '..') parts.pop()
    else if (part !== '.' && part !== '') parts.push(part)
  }
  return parts.join('/') || '/'
}

// --- scans -----------------------------------------------------------------------------------

async function scanCommit($: EngineInterface, root: string, wide: boolean): Promise<Finding[]> {
  const names = lines(await gitText($, root, ['diff', '--cached', '--name-only', '--diff-filter=ACMR']))
  const patches = [(await gitText($, root, ['diff', '--cached', '-U0', '--no-color', '--no-ext-diff'])) ?? '']
  if (wide) {
    names.push(...lines(await gitText($, root, ['diff', '--name-only', '--diff-filter=ACMR'])))
    patches.push((await gitText($, root, ['diff', '-U0', '--no-color', '--no-ext-diff'])) ?? '')
    for (const file of lines(await gitText($, root, ['ls-files', '--others', '--exclude-standard']))) {
      names.push(file)
      const text = await readText($, `${root}/${file}`)
      if (text !== undefined) patches.push(asPatch(file, text))
    }
  }
  return [...byName(names), ...byContent(patches.join('\n'))]
}

async function scanPush($: EngineInterface, root: string): Promise<Finding[]> {
  // Commits on HEAD that no remote-tracking branch holds yet: what this push would publish.
  const names = lines(await gitText($, root, ['log', '--format=', '--name-only', '--diff-filter=ACMR', 'HEAD', '--not', '--remotes']))
  const patch = (await gitText($, root, ['log', '--format=', '-p', '-U0', '--no-color', '--no-ext-diff', 'HEAD', '--not', '--remotes'])) ?? ''
  return [...byName(names), ...byContent(patch)]
}

async function untrackedSecrets($: EngineInterface, root: string): Promise<string[]> {
  return lines(await gitText($, root, ['ls-files', '--others', '--exclude-standard'])).filter(isSecretName)
}

export function isSecretName(path: string): boolean {
  return SECRET_NAME.test(path) && !TEMPLATE_NAME.test(path)
}

function byName(names: string[]): Finding[] {
  return [...new Set(names)].filter(isSecretName).map(file => ({ file, what: 'secret file by name' }))
}

// Reads a unified diff and reports each added line that matches a secret pattern.
export function byContent(patch: string): Finding[] {
  const found: Finding[] = []
  let file = ''
  let line = 0
  for (const text of patch.split('\n')) {
    if (text.startsWith('+++ ')) {
      file = text.slice(4).replace(/^b\//, '')
      continue
    }
    const hunk = /^@@ -\S+ \+(\d+)/.exec(text)
    if (hunk) {
      line = Number(hunk[1])
      continue
    }
    if (!text.startsWith('+')) continue
    const added = text.slice(1)
    for (const [what, pattern] of SECRET_LINE) {
      const hit = pattern.exec(added)
      if (hit === null) continue
      if (what === 'assigned secret' && PLACEHOLDER.test(hit[0])) continue
      found.push({ file, line, what, shown: mask(hit[0]) })
      break
    }
    line += 1
  }
  return found
}

function asPatch(file: string, text: string): string {
  return [`+++ b/${file}`, '@@ -0,0 +1 @@', ...text.split('\n').map(l => `+${l}`)].join('\n')
}

function mask(text: string): string {
  return text.length <= 10 ? `${text.slice(0, 3)}…` : `${text.slice(0, 10)}…(${text.length} chars)`
}

// --- the allow list --------------------------------------------------------------------------

// One path glob per line (`*` within a segment, `**` across), relative to the repo root. `#` comments.
async function readAllow($: EngineInterface, root: string): Promise<RegExp[]> {
  const text = await readText($, `${root}/${ALLOW_FILE}`)
  if (text === undefined) return []
  return text
    .split('\n')
    .map(l => l.replace(/#.*/, '').trim())
    .filter(l => l !== '')
    .map(glob)
}

export function glob(pattern: string): RegExp {
  const body = pattern
    .replace(/^\.?\//, '')
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/\u0000/g, '.*')
  return new RegExp(`^${body}$`)
}

function allowed(allow: RegExp[], file: string): boolean {
  return allow.some(r => r.test(file))
}

function isAllowFile(path: string): boolean {
  return path.replace(/\\/g, '/').endsWith(`/${ALLOW_FILE}`) || path === ALLOW_FILE
}

// --- text ------------------------------------------------------------------------------------

function denyText(plugin: string, sub: string, found: Finding[], loose: string[]): string {
  const rows = found
    .slice(0, 15)
    .map(f => `  ${f.file}${f.line ? `:${f.line}` : ''}  ${f.what}${f.shown ? `  ${f.shown}` : ''}`)
  const more = found.length > 15 ? [`  …and ${found.length - 15} more`] : []
  const unignored = loose.length > 0 ? [``, `Not gitignored: ${loose.join(', ')}`] : []
  return [
    `${plugin}: git ${sub} blocked, it would publish what looks like a secret:`,
    ...rows,
    ...more,
    ...unignored,
    ``,
    sub === 'push'
      ? `These are in local commits not yet pushed. Remove the secret from history (rewrite the unpushed commits), add the file to .gitignore, and rotate the credential if it was ever pushed elsewhere.`
      : `Unstage it (git restore --staged <file>, or git rm --cached <file> if already tracked), add it to .gitignore, then commit again.`,
    `If a hit is a false positive, ask Tim to add its path to ${ALLOW_FILE} at the repo root. Do not edit that file yourself.`,
  ].join('\n')
}

function allowDeny(plugin: string): string {
  return `${plugin}: ${ALLOW_FILE} is edited by Tim only. Tell Tim which path to add and why.`
}

function lines(text: string | undefined): string[] {
  return (text ?? '').split('\n').map(l => l.trim()).filter(l => l !== '')
}

function baseName(path: string): string {
  return path.replace(/\\/g, '/').split('/').pop() ?? path
}

async function gitText($: EngineInterface, dir: string, args: string[]): Promise<string | undefined> {
  try {
    const ran = await $.process.run(['git', ...args], { cwd: dir, timeoutMs: 20_000 })
    return ran.exitCode === 0 ? ran.stdout : undefined
  } catch {
    return undefined
  }
}

async function readText($: EngineInterface, path: string): Promise<string | undefined> {
  try {
    const text = await $.fs.read(path)
    return typeof text === 'string' && !text.includes('\u0000') ? text : undefined
  } catch {
    return undefined
  }
}
