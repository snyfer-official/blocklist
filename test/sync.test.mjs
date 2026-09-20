// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict'
import { generateKeyPairSync, sign } from 'node:crypto'
import { test } from 'node:test'
import { SOURCE, MAX_BYTES, validDomain, signedMessage, validateList, assertUpdate, render, fetchSource, sha256 } from '../scripts/sync.mjs'

const pair = generateKeyPairSync('ed25519')
const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('base64')
const now = Date.parse('2026-09-20T00:00:00.000Z')
function fixture(extra = {}) {
  const list = { version: 42, builtAt: new Date(now).toISOString(), domains: ['a.test', 'b.test'], ...extra }
  return { ...list, sig: sign(null, Buffer.from(signedMessage(list)), pair.privateKey).toString('base64url') }
}
const validate = (list) => validateList(list, { publicKey, now })

test('verifies a signed source and rejects altered domains, version, date or signature', () => {
  const list = fixture()
  assert.equal(validate(list), list)
  for (const change of [{ domains: ['a.test'] }, { version: 43 }, { builtAt: new Date(now - 1000).toISOString() }, { sig: 'A'.repeat(86) }]) {
    assert.throws(() => validate({ ...list, ...change }), /signature/)
  }
  assert.throws(() => validateList(list, { now }), /signature/)
})

test('refuses stale/future data; historical snapshots remain verifiable offline', () => {
  for (const date of [now - 49 * 3600000, now + 6 * 60000]) {
    const list = fixture({ builtAt: new Date(date).toISOString() })
    assert.throws(() => validate(list), /stale|future/)
    validateList(list, { publicKey, now, freshness: false })
  }
})

test('rejects malformed, duplicate, unsorted, empty or unsafe domain data', () => {
  for (const domains of [[], ['b.test', 'a.test'], ['a.test', 'a.test'], ['https://a.test'], ['127.0.0.1'], ['snyfer.com'], ['login.snyfer.com'], ['a.test\n0.0.0.0 safe.com'], ['A.test'], ['a..test'], ['-a.test'], ['a.test.']]) {
    assert.throws(() => validate(fixture({ domains })))
  }
  for (const value of [null, 'localhost', 'user:pass@a.test', '*.a.test', 'é.test']) assert.equal(validDomain(value), false)
  assert.equal(validDomain('xn--bcher-kva.de'), true)
  assert.throws(() => validate({ ...fixture(), extra: 'not allowed' }))
  assert.throws(() => validate(fixture({ builtAt: '2026-02-30T00:00:00.000Z' })))
})

test('refuses rollback, same-version replacement and suspicious mass removal', () => {
  const previous = fixture()
  assertUpdate(previous, previous)
  assert.throws(() => assertUpdate(fixture({ version: 41 }), previous), /rollback/)
  assert.throws(() => assertUpdate(fixture({ domains: ['a.test'] }), previous), /same version/)
  const big = fixture({ domains: Array.from({ length: 101 }, (_, i) => `${i}.test`) })
  assert.throws(() => assertUpdate(fixture({ version: 43 }), big), /50%/)
  assertUpdate(fixture({ version: 43 }), previous)
})

test('all formats preserve domain membership and carry consistent checksums', () => {
  const list = fixture()
  const output = render(list)
  assert.equal(output['domains.txt'], 'a.test\nb.test\n')
  assert.deepEqual(JSON.parse(output['domains.json']), list.domains)
  assert.match(output['hosts.txt'], /0\.0\.0\.0 a\.test\n0\.0\.0\.0 b\.test\n$/)
  assert.match(output['adblock.txt'], /\|\|a\.test\^\n\|\|b\.test\^\n$/)
  assert.deepEqual(JSON.parse(output['signed.json']), list)
  const stats = JSON.parse(output['stats.json'])
  assert.equal(stats.count, 2)
  for (const [file, hash] of Object.entries(stats.sha256)) assert.equal(hash, sha256(output[file]))
  assert.deepEqual(render(list), output)
})

test('fetches only the public feed without credentials and refuses HTTP/HTML/oversized bodies', async () => {
  const data = fixture()
  assert.deepEqual(await fetchSource(async (url, options) => {
    assert.equal(url, SOURCE)
    assert.equal(options.credentials, 'omit')
    assert.equal(options.redirect, 'error')
    assert.deepEqual(options.headers, { accept: 'application/json' })
    return Response.json(data)
  }), data)
  await assert.rejects(fetchSource(async () => new Response('', { status: 503 })), /HTTP 503/)
  await assert.rejects(fetchSource(async () => new Response('<html>', { headers: { 'content-type': 'text/html' } })), /not JSON/)
  await assert.rejects(fetchSource(async () => new Response('{}', { headers: { 'content-type': 'application/json', 'content-length': String(MAX_BYTES + 1) } })), /size limit/)
  await assert.rejects(fetchSource(async () => new Response(new Uint8Array(MAX_BYTES + 1), { headers: { 'content-type': 'application/json' } })), /size limit/)
})
