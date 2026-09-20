// SPDX-License-Identifier: MIT
import { createHash, createPublicKey, verify } from 'node:crypto'
import { readFile, writeFile, rename, unlink } from 'node:fs/promises'
import { isIP } from 'node:net'
import { resolve, join } from 'node:path'
import { domainToASCII, fileURLToPath } from 'node:url'

export const SOURCE = 'https://snyfer.com/blocklist/domains.json'
export const PUBLIC_KEY = 'YVW2zsIyjP805yuyAXLct/s/SX7o57iGxcqYd4QTTLg='
export const MAX_BYTES = 8 * 1024 * 1024
export const FILES = ['domains.txt', 'domains.json', 'hosts.txt', 'adblock.txt', 'signed.json', 'stats.json']
const MAX_AGE = 48 * 60 * 60 * 1000
const ROOT = fileURLToPath(new URL('../', import.meta.url))
const COPYRIGHT = 'Copyright 2026 Snyfer — https://snyfer.com'
const LICENSE = 'CC BY 4.0 — https://creativecommons.org/licenses/by/4.0/'
export const sha256 = (text) => createHash('sha256').update(text).digest('hex')
const json = (value) => JSON.stringify(value, null, 2) + '\n'

export function signedMessage(list) {
  return `snyfer-exact-list|v=${list.version}|builtAt=${list.builtAt}|count=${list.domains.length}|sha256=${sha256(JSON.stringify(list.domains))}`
}

export function validDomain(domain) {
  return typeof domain === 'string' && domain.length <= 253 && domain.includes('.') &&
    domain === domain.toLowerCase() && domainToASCII(domain) === domain && !isIP(domain) &&
    domain !== 'snyfer.com' && !domain.endsWith('.snyfer.com') &&
    domain.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
}

export function validateList(list, { publicKey = PUBLIC_KEY, now = Date.now(), freshness = true } = {}) {
  if (!list || typeof list !== 'object' || Array.isArray(list) ||
      Object.keys(list).sort().join(',') !== 'builtAt,domains,sig,version') throw Error('Invalid signed list object')
  if (!Number.isSafeInteger(list.version) || list.version < 1) throw Error('Invalid source version')
  if (typeof list.builtAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(list.builtAt) ||
      !Number.isFinite(Date.parse(list.builtAt)) || new Date(list.builtAt).toISOString() !== list.builtAt) throw Error('Invalid source date')
  const age = now - Date.parse(list.builtAt)
  if (freshness && (age > MAX_AGE || age < -5 * 60 * 1000)) throw Error('Source is stale or dated in the future')
  if (!Array.isArray(list.domains) || list.domains.length < 1 || list.domains.length > 200_000) throw Error('Invalid domain count')
  for (let i = 0; i < list.domains.length; i++) {
    if (!validDomain(list.domains[i]) || (i > 0 && list.domains[i - 1] >= list.domains[i])) throw Error('Domains must be valid, sorted and unique')
  }
  if (typeof list.sig !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(list.sig)) throw Error('Invalid signature encoding')
  const signature = Buffer.from(list.sig, 'base64url')
  if (signature.toString('base64url') !== list.sig) throw Error('Noncanonical signature encoding')
  const key = createPublicKey({
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKey, 'base64')]),
    format: 'der', type: 'spki',
  })
  if (!verify(null, Buffer.from(signedMessage(list)), key, signature)) throw Error('Invalid publisher signature')
  return list
}

export function assertUpdate(next, previous) {
  if (!previous) return
  if (next.version < previous.version) throw Error('Source version rollback refused')
  if (next.version === previous.version && next.sig !== previous.sig) throw Error('Different payload at the same version')
  if (previous.domains.length > 100 && next.domains.length < previous.domains.length * 0.5) throw Error('List shrank by more than 50%; review the source before publishing')
}

export function render(list) {
  const title = 'Snyfer Blocklist'
  const info = [title, COPYRIGHT, `License: ${LICENSE}`, `Source updated: ${list.builtAt}`, `Domains: ${list.domains.length}`, 'https://github.com/snyfer-official/blocklist']
  const output = {
    'domains.txt': list.domains.join('\n') + '\n',
    'domains.json': json(list.domains),
    'hosts.txt': info.map((line) => '# ' + line).join('\n') + '\n' + list.domains.map((domain) => `0.0.0.0 ${domain}`).join('\n') + '\n',
    'adblock.txt': '[Adblock Plus 2.0]\n' + info.map((line) => '! ' + line).join('\n') + '\n! Expires: 1 day\n' + list.domains.map((domain) => `||${domain}^`).join('\n') + '\n',
    'signed.json': json({ version: list.version, builtAt: list.builtAt, domains: list.domains, sig: list.sig }),
  }
  output['stats.json'] = json({
    schemaVersion: 1,
    name: title,
    source: SOURCE,
    sourceVersion: list.version,
    sourceUpdatedAt: list.builtAt,
    count: list.domains.length,
    license: 'CC-BY-4.0',
    attribution: 'Snyfer — https://snyfer.com — CC BY 4.0',
    sha256: Object.fromEntries(Object.entries(output).map(([name, content]) => [name, sha256(content)])),
  })
  return output
}

export async function fetchSource(fetcher = fetch) {
  const response = await fetcher(SOURCE, {
    headers: { accept: 'application/json' }, credentials: 'omit', redirect: 'error',
    signal: AbortSignal.timeout(20_000),
  })
  if (!response.ok) throw Error(`Source HTTP ${response.status}`)
  if (!/^application\/json\b/i.test(response.headers.get('content-type') ?? '')) throw Error('Source is not JSON')
  if (Number(response.headers.get('content-length')) > MAX_BYTES) {
    await response.body?.cancel()
    throw Error('Source exceeds size limit')
  }
  if (!response.body) throw Error('Empty source response')
  const reader = response.body.getReader()
  const chunks = []
  let size = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > MAX_BYTES) throw Error('Source exceeds size limit')
      chunks.push(value)
    }
  } catch (error) {
    await reader.cancel().catch(() => {})
    throw error
  } finally {
    reader.releaseLock()
  }
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)))
}

async function previousList() {
  try {
    return validateList(JSON.parse(await readFile(join(ROOT, 'signed.json'), 'utf8')), { freshness: false })
  } catch (error) {
    if (error.code === 'ENOENT') return null
    throw error
  }
}

async function main() {
  const mode = process.argv[2] ?? '--sync'
  if (!['--sync', '--check'].includes(mode) || process.argv.length > 3) throw Error('Usage: node scripts/sync.mjs [--sync|--check]')
  const previous = await previousList()
  if (mode === '--check') {
    if (!previous) throw Error('No published snapshot')
    for (const [name, content] of Object.entries(render(previous))) {
      if (await readFile(join(ROOT, name), 'utf8') !== content) throw Error(`Generated file differs: ${name}`)
    }
    console.log(`Verified ${previous.domains.length} domains and all output formats (source date: ${previous.builtAt})`)
    return
  }
  const next = validateList(await fetchSource())
  assertUpdate(next, previous)
  const output = render(next)
  // Git publishes all outputs in one commit; a failed job never pushes partial files.
  const staged = []
  try {
    for (const [name, content] of Object.entries(output)) {
      const temp = join(ROOT, `.${name}.${process.pid}.tmp`)
      staged.push(temp)
      await writeFile(temp, content, { flag: 'wx' })
    }
    for (let i = 0; i < FILES.length; i++) await rename(staged[i], join(ROOT, FILES[i]))
  } finally {
    await Promise.all(staged.map((path) => unlink(path).catch(() => {})))
  }
  console.log(`Published snapshot: ${next.domains.length} domains, version ${next.version}, source date ${next.builtAt}`)
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error(error.message); process.exitCode = 1 })
}
