import type { On } from 'claude-code'
import { expect, mock, test } from 'claude-code/testing'
import { byContent, gitCalls, glob, isSecretName } from './register'

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
