// Run: bun test/roundtrip.mjs  (or node)
import {readFileSync} from 'node:fs'
import assert from 'node:assert/strict'

globalThis.window = {crypto: globalThis.crypto}
const src = readFileSync(new URL('../js/crypto.js', import.meta.url), 'utf8')
const {encryptString, decryptString, load_public_key, serialize_key} = new Function(
    src + '; return {encryptString, decryptString, load_public_key, serialize_key}')()

const {publicKey, privateKey} = await crypto.subtle.generateKey(
    {name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256'},
    false, ['encrypt', 'decrypt'])
const pub = await load_public_key(serialize_key(await crypto.subtle.exportKey('jwk', publicKey)))

for (const secret of ['hunter2', 'x'.repeat(5000), 'ünïcödé 🐕']) {
    assert.equal(await decryptString(privateKey, await encryptString(pub, secret)), secret)
}

const enc = await encryptString(pub, 'secret')
const tampered = enc.slice(0, -4) + (enc.endsWith('AAAA') ? 'BBBB' : 'AAAA')
await assert.rejects(decryptString(privateKey, tampered), {name: 'OperationError'})

assert.equal((await crypto.subtle.exportKey('jwk', publicKey)).d, undefined)
await assert.rejects(crypto.subtle.exportKey('jwk', privateKey)) // non-extractable

console.log('ok')
