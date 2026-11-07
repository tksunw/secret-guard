import type { On } from 'claude-code'
import { expect, mock, test } from 'claude-code/testing'
import { byContent, gitCalls, glob, isPlaceholder, isSecretName } from './register'

// A repo at /r. `git` answers by subcommand from `out`; files by path from `files`.
function world(on: On, out: Record<string, string> = {}, files: Record<string, string> = {}) {
  const it = { ran: [] as string[][], toasts: [] as string[], passed: [] as string[] }
  mock.env(on, { HOME: '/home/t' })
  on('session.cwd', () => ({ value: '/r' }))
  on('process.run', (_$, e) => {
    const argv = [...e.argv]
    it.ran.push(argv)
    const key = argv.slice(1).join(' ')
    if (key === 'rev-parse --show-toplevel') return { value: run('/r\n') }
    const hit = Object.keys(out).find(k => key.startsWith(k))
    return { value: run(hit === undefined ? '' : out[hit]) }
  })
  on('fs.read', (_$, e) => (e.path in files ? { value: files[e.path] } : { deny: 'ENOENT' }))
  on('ui.toast', (_$, e) => {
    it.toasts.push(e.text)
    return { value: undefined }
  })
  on('tool.call', (_$, e) => {
    it.passed.push(e.tool === 'Bash' ? e.command : e.tool)
    return { result: {}, text: 'ok' } as never
  })
  return it
}

const run = (stdout: string) => ({ exitCode: 0, stdout, stderr: '', isStdoutTruncated: false, isStderrTruncated: false })

const KEY_PATCH = ['+++ b/app.py', '@@ -0,0 +4,2 @@', '+import os', '+AWS = "AKIAABCDEFGHIJKLMNOP"'].join('\n')

test('a staged .env blocks the commit', async ($, on) => {
  const it = world(on, { 'diff --cached --name-only': '.env\nREADME.md\n' })
  const done = await $.tool.call({ tool: 'Bash', command: 'git commit -m "add config"' })
  expect('deny' in done || (done as { isError?: boolean }).isError === true).toBe(true)
  expect(it.passed).toEqual([])
})

test('a staged AWS key blocks the commit with file and line', async ($, on) => {
  const it = world(on, { 'diff --cached -U0': KEY_PATCH })
  const done = (await $.tool.call({ tool: 'Bash', command: 'rtk git commit -m x' })) as { text?: string; deny?: string }
  expect(done.deny ?? done.text).toContain('app.py:5')
  expect(done.deny ?? done.text).toContain('AWS access key')
  expect(it.passed).toEqual([])
})

test('a clean commit passes untouched', async ($, on) => {
  const it = world(on, { 'diff --cached --name-only': 'README.md\n', 'diff --cached -U0': '+++ b/README.md\n@@ -1 +1 @@\n+hello' })
  await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
  expect(it.passed).toEqual(['git commit -m x'])
})

test('add then commit in one command scans the working tree and untracked files', async ($, on) => {
  const it = world(on, { 'ls-files --others': 'notes/creds.txt\n' }, { '/r/notes/creds.txt': 'client_secret = "q8Zr7Tx2Vb9Lm4Kp"\n' })
  await $.tool.call({ tool: 'Bash', command: 'git add -A && git commit -m x' })
  expect(it.passed).toEqual([])
})

test('an allow-listed path passes', async ($, on) => {
  const it = world(on, { 'diff --cached --name-only': 'certs/test.key\n' }, { '/r/.secret-guard-allow': '# test fixtures\ncerts/*.key\n' })
  await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
  expect(it.passed).toEqual(['git commit -m x'])
})

test('push scans unpushed commits', async ($, on) => {
  const it = world(on, { 'log --format= -p': KEY_PATCH })
  await $.tool.call({ tool: 'Bash', command: 'cd sub && git push' })
  expect(it.passed).toEqual([])
  expect(it.ran.some(a => a.includes('--remotes'))).toBe(true)
})

test('an unignored secret file that is not committed only toasts', async ($, on) => {
  const it = world(on, { 'ls-files --others': '.env\n' })
  await $.tool.call({ tool: 'Bash', command: 'git commit -m x' })
  expect(it.passed).toEqual(['git commit -m x'])
  expect(it.toasts[0]).toContain('.env')
})

test('Claude cannot write the allow list', async ($, on) => {
  const it = world(on)
  await $.tool.call({ tool: 'Write', file_path: '/r/.secret-guard-allow', content: '**' })
  await $.tool.call({ tool: 'Bash', command: 'echo "**" >> .secret-guard-allow' })
  await $.tool.call({ tool: 'Bash', command: 'cat .secret-guard-allow' })
  expect(it.passed).toEqual(['cat .secret-guard-allow'])
})

test('reads and mentions of the allow list pass; every write form is refused', async ($, on) => {
  const it = world(on)
  const reads = [
    'cd /r && cat .secret-guard-allow',
    'git -C /r diff -- .secret-guard-allow | head',
    "cat > 'note.md' <<'EOF'\nOnly Tim edits .secret-guard-allow at the repo root.\nEOF",
    'git add .secret-guard-allow',
  ]
  const writes = [
    'cd /r && echo x > .secret-guard-allow',
    'printf "x\\n" >>/r/.secret-guard-allow',
    'echo x | tee -a .secret-guard-allow',
    "sed -i 's/a/b/' .secret-guard-allow",
    'rm -f .secret-guard-allow',
    'cp /tmp/x /r/.secret-guard-allow',
    'git checkout -- .secret-guard-allow',
    'Set-Content -Path .secret-guard-allow -Value x',
    `python3 -c "open('.secret-guard-allow','w').write('**')"`,
    `python3 -c "import pathlib; pathlib.Path('.secret-guard-allow').write_text('**')"`,
  ]
  for (const command of [...reads, ...writes]) await $.tool.call({ tool: 'Bash', command })
  expect(it.passed).toEqual(reads)
})

test('helpers', () => {
  expect(gitCalls('cd ~/REPOS/x && git -C sub commit -am y; git push', '/w', '/home/t')).toEqual([
    { dir: '/home/t/REPOS/x/sub', sub: 'commit', args: ['-am', 'y'] },
    { dir: '/home/t/REPOS/x', sub: 'push', args: [] },
  ])
  expect(isSecretName('migration/.env')).toBe(true)
  expect(isSecretName('.env.example')).toBe(false)
  expect(isSecretName('.apikeys.json')).toBe(true)
  expect(isSecretName('smc-root-ca.pem')).toBe(false)
  expect(glob('certs/**').test('certs/a/b.key')).toBe(true)
  expect(byContent('+++ b/x.tf\n@@ -0,0 +1 @@\n+password = lookup(j, "Pwd")')).toEqual([])
  expect(byContent('+++ b/x.tf\n@@ -0,0 +1 @@\n+password = "${var.pwd}"')).toEqual([])
  expect(byContent('+++ b/c.ini\n@@ -0,0 +1 @@\n+Server=x;User Id=a;Password=Hunter2Pass;').length).toBe(1)
})

// What Claude Code writes into .claude/settings.local.json on "don't ask again": the exact command,
// with any inline credential. Each line is one allow rule.
const RULE = (cmd: string) => `+++ b/.claude/settings.local.json\n@@ -0,0 +3 @@\n+      "Bash(${cmd})",`

test('inline credentials in an allow rule are caught', () => {
  const caught = [
    'PGPASSWORD=Hunter2Secret9 psql -h db.example.com -U admin -d prod',
    'DB_PASSWORD=supersecret123 npm start',
    'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQ4Lm9Vk aws s3 ls',
    'ANTHROPIC_API_KEY=sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123 python app.py',
    'sshpass -p MyS3cretPass! ssh root@203.0.113.5',
    'mysql -u root -pS3cretPw99 -h 10.0.0.5 app',
    'mysql -u root --password=S3cretPw99 app',
    'docker login -u tim -p MyRegistryPw1 ghcr.io',
    'az login --service-principal -u 1111-2222 -p Abc~XyZ.secret123 --tenant t',
    'curl -u admin:Sup3rSecret https://api.example.com',
    'openssl pkcs12 -in x.pfx -passin pass:Hunter2Pass',
    'npm config set //registry.npmjs.org/:_authToken npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    'curl -H "PRIVATE-TOKEN: glpat-ABCDEFGHIJKLMNOPQRST" https://gitlab.com/api/v4/projects',
  ]
  for (const cmd of caught) expect(byContent(RULE(cmd)).length).toBe(1)
})

test('variables, prompts, ports and placeholders in an allow rule pass', () => {
  const clean = [
    'PGPASSWORD=$DB_PASS psql -h $DB_HOST',
    'PGPASSWORD=${DB_PASS} psql',
    'DB_PASSWORD=$(op read op://vault/db/password) npm start',
    'mysql -u root -p mydatabase',
    'psql -h localhost -p 5432 -U app',
    'sshpass -p "$PASS" ssh host',
    'docker login -u tim -p $GHCR_TOKEN ghcr.io',
    'curl -w %{http_code} -u user:$TOKEN https://x',
    'wget -P /tmp/downloads https://x/file',
    'APP_PASSWORD=CHANGE_ME_APP_PASSWORD docker compose up',
    'APP_PASSWORD=choose_a_strong_local_password',
    'RENTCAST_API_KEY=test-key-123 ./smoke.sh',
    'FILE__PASSWORD=/run/secrets/gui_password',
    'xcrun notarytool submit --apple-id you@example.com --password app-specific-password',
    'GITHUB_TOKEN=$(gh auth token) gh repo list',
  ]
  for (const cmd of clean) expect(byContent(RULE(cmd))).toEqual([])
  expect(isPlaceholder('APP_PASSWORD=choose_a_strong_local_password')).toBe(true)
  expect(isPlaceholder('APP_PASSWORD=x9Kq2mZp8Lw')).toBe(false)
})

test('.claude/settings.local.json is a secret file by name', () => {
  expect(isSecretName('.claude/settings.local.json')).toBe(true)
  expect(isSecretName('sub/.claude/settings.local.json')).toBe(true)
  expect(isSecretName('.claude/settings.json')).toBe(false)
})
