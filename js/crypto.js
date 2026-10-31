const ALGO_NAME = 'RSA-OAEP'
const ALGO_HASH = 'SHA-256'
const ALGO_KEY_LENGTH = 2048

function serialize_key(key) {
    return btoa(JSON.stringify(key))
}

function deserialize_key(str) {
    return JSON.parse(atob(str))
}

// Private key is non-extractable and lives in IndexedDB (CryptoKey is structured-cloneable),
// so a script on the page can use it but never read it out.
function idbRequest(mode, fn) {
    return new Promise((ok, fail) => {
        const open = indexedDB.open('retriever', 1)
        open.onupgradeneeded = () => open.result.createObjectStore('keys')
        open.onerror = () => fail(open.error)
        open.onsuccess = () => {
            const req = fn(open.result.transaction('keys', mode).objectStore('keys'))
            req.onsuccess = () => ok(req.result)
            req.onerror = () => fail(req.error)
        }
    })
}

async function generateKeyPair() {
    const saved = await idbRequest('readonly', s => s.get('pair'))
    if (saved) {
        return saved.pub
    }

    const {publicKey, privateKey} = await window.crypto.subtle.generateKey(
        {
            name: ALGO_NAME,
            modulusLength: ALGO_KEY_LENGTH,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: ALGO_HASH,
        },
        false, // public key is always exportable; this only locks the private key
        ['encrypt', 'decrypt']
    );

    const pub = serialize_key(await window.crypto.subtle.exportKey('jwk', publicKey))
    await idbRequest('readwrite', s => s.put({pub, priv: privateKey}, 'pair'))
    localStorage.clear() // drop legacy extractable private keys from older versions
    return pub
}

async function load_public_key(serialized_key) {
    return await window.crypto.subtle.importKey(
        'jwk',
        deserialize_key(serialized_key),
        {name: ALGO_NAME, hash: ALGO_HASH},
        false,
        ['encrypt']
    );
}

async function load_private_key(public_key_ser) {
    const saved = await idbRequest('readonly', s => s.get('pair'))
    if (!saved || saved.pub !== public_key_ser) {
        throw new Error('no private key for this public key')
    }
    return saved.priv
}

// Hybrid: RSA-OAEP alone caps plaintext at 190 bytes. Output = base64(wrappedAesKey[256] | iv[12] | ciphertext).
const WRAPPED_LEN = ALGO_KEY_LENGTH / 8
const IV_LEN = 12

async function encryptString(publicKey, plaintext) {
    const {subtle} = window.crypto
    const aesKey = await subtle.generateKey({name: 'AES-GCM', length: 256}, true, ['encrypt'])
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_LEN))
    const body = new Uint8Array(await subtle.encrypt({name: 'AES-GCM', iv}, aesKey, new TextEncoder().encode(plaintext)))
    const wrapped = new Uint8Array(await subtle.encrypt({name: ALGO_NAME}, publicKey, await subtle.exportKey('raw', aesKey)))

    const out = new Uint8Array(WRAPPED_LEN + IV_LEN + body.length)
    out.set(wrapped)
    out.set(iv, WRAPPED_LEN)
    out.set(body, WRAPPED_LEN + IV_LEN)
    // ponytail: spread caps at ~100KB of input; chunk it if secrets get bigger than that
    return btoa(String.fromCharCode(...out))
}

async function decryptString(privateKey, encryptedBase64) {
    const {subtle} = window.crypto
    const bytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0))
    const wrapped = bytes.slice(0, WRAPPED_LEN)
    const iv = bytes.slice(WRAPPED_LEN, WRAPPED_LEN + IV_LEN)
    const body = bytes.slice(WRAPPED_LEN + IV_LEN)

    const rawKey = await subtle.decrypt({name: ALGO_NAME}, privateKey, wrapped)
    const aesKey = await subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt'])
    return new TextDecoder().decode(await subtle.decrypt({name: 'AES-GCM', iv}, aesKey, body))
}