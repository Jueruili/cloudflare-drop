import { afterAll, beforeAll, expect, test, vi } from 'vitest'
import { readFileSync, writeFileSync } from 'node:fs'

const interop = vi.hoisted(() => ({
  derivedKey: Uint8Array.from(
    Buffer.from(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      'hex',
    ),
  ),
}))

vi.mock('argon2-browser/dist/argon2-bundled.min.js', () => ({
  ArgonType: { Argon2id: 2 },
  hash: async () => ({ hash: interop.derivedKey }),
}))

const manifest = JSON.parse(
  readFileSync(new URL('./fixtures/v2/manifest.json', import.meta.url), 'utf8'),
) as {
  password: string
  filename: string
  type: string
  plaintextPattern: string
  repeat: number
}
const plaintext = manifest.plaintextPattern.repeat(manifest.repeat)
const dataKey = Uint8Array.from({ length: 32 }, (_value, index) => index + 60)
const realCrypto = globalThis.crypto
let randomOffset = 0

beforeAll(() => {
  const subtle = {
    encrypt: realCrypto.subtle.encrypt.bind(realCrypto.subtle),
    decrypt: realCrypto.subtle.decrypt.bind(realCrypto.subtle),
    importKey: realCrypto.subtle.importKey.bind(realCrypto.subtle),
    exportKey: realCrypto.subtle.exportKey.bind(realCrypto.subtle),
    generateKey: async () =>
      realCrypto.subtle.importKey('raw', dataKey, { name: 'AES-GCM' }, true, [
        'encrypt',
        'decrypt',
      ]),
  } as unknown as SubtleCrypto
  const getRandomValues = (<T extends ArrayBufferView | null>(array: T): T => {
    if (!array) return array
    const bytes = new Uint8Array(
      array.buffer,
      array.byteOffset,
      array.byteLength,
    )
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = randomOffset % 256
      randomOffset += 1
    }
    return array
  }) as Crypto['getRandomValues']
  vi.stubGlobal('crypto', { subtle, getRandomValues } as Crypto)
})

afterAll(() => {
  vi.unstubAllGlobals()
})

const { Encryptor } = await import('../web/helpers/encryptor')

async function collect(stream: ReadableStream<Uint8Array>) {
  return new Uint8Array(await new Response(stream).arrayBuffer())
}

test('TypeScript and Go retain V2 encrypted-file compatibility', async () => {
  randomOffset = 0
  const file = new File([plaintext], manifest.filename, { type: manifest.type })
  const encrypted = await Encryptor.encryptStream(manifest.password, file)
  const tsBytes = await collect(encrypted.stream)
  const tsFixture = new URL('./fixtures/v2/ts-v2.bin', import.meta.url)

  if (process.env.UPDATE_V2_FIXTURES === '1') {
    writeFileSync(tsFixture, tsBytes)
  }
  expect(Buffer.from(tsBytes)).toEqual(readFileSync(tsFixture))

  const goBytes = readFileSync(
    new URL('./fixtures/v2/go-v2.bin', import.meta.url),
  )
  const decrypted = await Encryptor.decryptWithMetadata(
    manifest.password,
    new Blob([goBytes]),
  )
  expect(decrypted.metadata).toEqual({
    filename: manifest.filename,
    type: manifest.type,
  })
  await expect(decrypted.blob.text()).resolves.toBe(plaintext)
})
