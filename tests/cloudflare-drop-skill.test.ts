import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { expect, test } from 'vitest'

const skillDirectory = resolve('skills/cloudflare-drop')

function readSkillFile(path: string) {
  return readFileSync(resolve(skillDirectory, path), 'utf8')
}

test('cloudflare-drop skill has a legal focused activation description', () => {
  const source = readSkillFile('SKILL.md')
  const frontmatter = source.match(/^---\n([\s\S]*?)\n---/u)?.[1] ?? ''
  expect(frontmatter).toMatch(/^name: cloudflare-drop$/mu)
  const description = frontmatter.match(/^description: (.+)$/mu)?.[1] ?? ''
  expect(description.startsWith('Use this skill when')).toBe(true)
  expect(description.length).toBeLessThan(1024)
  expect(description).toMatch(/分享|分享码|加密分享/u)
  expect(description).toMatch(/upload|share code|encrypted share/iu)
  expect(description).toContain('Cloudflare Drop for 分享')
  expect(source).toContain('Do not use')
  expect(source).toMatch(/generic file copy|其他云存储/iu)
})

test('skill workflow captures server password and ephemeral safety rules', () => {
  const source = readSkillFile('SKILL.md')
  expect(source).toContain('CLOUDFLARE_DROP_URL')
  expect(source).toMatch(/ask the user|询问用户/iu)
  expect(source).toContain('V2')
  expect(source).toMatch(/does not support V1|不支持 V1/iu)
  expect(source).toContain('--ephemeral')
  expect(source).toMatch(/lookup|查询/iu)
  expect(source).toMatch(/consumes|失效|消耗/iu)
  expect(source).toContain('--password-file')
  expect(source).toMatch(/never.*supplied password|不要.*用户提供的密码/iu)
  expect(source).toContain('references/cli.md')
})

test('skill manifest declares portable local execution', () => {
  const manifest = readSkillFile('skill.yaml')
  expect(manifest).toContain('name: cloudflare-drop')
  expect(manifest).toContain('version: 0.1.0')
  expect(manifest).toContain('entry: SKILL.md')
  expect(manifest).toContain('- claude')
  expect(manifest).toContain('- codex')
  expect(manifest).toContain('- shell')
  expect(manifest).toMatch(/- ['"]\*['"]/u)
})

test('launcher maps every supported OS and architecture', () => {
  const launcher = readSkillFile('scripts/cloudflare-drop')
  for (const target of [
    'darwin-amd64',
    'darwin-arm64',
    'linux-amd64',
    'linux-arm64',
  ]) {
    expect(launcher).toContain(target)
  }
  expect(launcher).toContain('unsupported platform')
  expect(launcher).toContain('exec "$script_dir/bin/$target/cloudflare-drop"')
})

test('native build excludes environment-specific VCS metadata', () => {
  const buildScript = readFileSync(
    resolve('scripts/build-cloudflare-drop-skill'),
    'utf8',
  )
  expect(buildScript).toContain('required_go_version=go1.25.5')
  expect(buildScript).toContain('CGO_ENABLED=0')
  expect(buildScript).toContain('-buildvcs=false')
  expect(buildScript).toContain('-trimpath')
})

test('CLI reference documents commands and stable JSON channels', () => {
  const reference = readSkillFile('references/cli.md')
  expect(reference).toContain('cloudflare-drop upload')
  expect(reference).toContain('cloudflare-drop get')
  expect(reference).toContain('--text')
  expect(reference).toContain('--stdin')
  expect(reference).toContain('--encrypt')
  expect(reference).toContain('--output')
  expect(reference).toMatch(/stdout.*JSON/iu)
  expect(reference).toMatch(/stderr.*progress|progress.*stderr/iu)
})
