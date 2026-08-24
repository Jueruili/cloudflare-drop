# Dual Storage and Secure Sharing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add automatic KV/R2 storage selection while enforcing server-side upload limits and making numeric-code sharing, downloads, and ephemeral links safe.

**Architecture:** A storage service selects R2 when available and otherwise uses KV, while each D1 record persists its selected provider. Upload manifests and download grants are short-lived KV records. Route handlers call the services instead of directly addressing storage, so browser and terminal downloads share the same authorization and stream behavior.

**Tech Stack:** Cloudflare Workers, Hono, D1/Drizzle, KV, R2, Preact, Vitest.

---

## File Structure

- `src/storage/index.ts` selects a provider and exposes stream/delete operations.
- `src/storage/kv.ts` preserves legacy KV object and chunk streaming.
- `src/storage/r2.ts` writes, reads, and deletes R2 objects.
- `src/shares.ts` validates duration, atomically claims ephemeral rows, and creates/consumes file-bound download grants.
- `src/uploads.ts` owns upload manifests, chunk validation, finalization, size and digest checks.
- `src/files/*.ts` become thin HTTP adapters over shares and uploads.
- `src/middlewares/limit.middleware.ts` applies route-class-aware rate limits.
- `data/schemas/files.schema.ts` and a migration add provider, claim state, and indexes.
- `tests/*.test.ts` exercise services with in-memory KV/R2/D1 fixtures.

### Task 1: Establish the Test Harness and Schema Contract

**Files:**

- Modify: `package.json`
- Modify: `data/schemas/files.schema.ts`
- Create: `data/migrations/0009_dual_storage_security.sql`
- Create: `tests/helpers.ts`
- Create: `tests/files-schema.test.ts`

- [ ] **Step 1: Add a failing schema contract test**

```ts
import { expect, test } from 'vitest'
import { files } from '../data/schemas/files.schema'

test('files persist provider and ephemeral claim state', () => {
  expect(files.storage_provider.name).toBe('storage_provider')
  expect(files.claimed_at.name).toBe('claimed_at')
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pnpm vitest run tests/files-schema.test.ts`

Expected: FAIL because Vitest and the schema fields do not exist.

- [ ] **Step 3: Add Vitest and the schema migration**

```sql
ALTER TABLE `files` ADD `storage_provider` text NOT NULL DEFAULT 'kv';
ALTER TABLE `files` ADD `claimed_at` integer;
CREATE INDEX `files_due_date_idx` ON `files` (`due_date`);
CREATE INDEX `files_created_at_idx` ON `files` (`created_at`);
```

Add `storage_provider: text('storage_provider').notNull().default('kv')` and
`claimed_at: integer('claimed_at', { mode: 'timestamp' })` to the Drizzle
schema. Add `test: "vitest run"` and `vitest` to development dependencies.

- [ ] **Step 4: Run the focused test and type check**

Run: `pnpm vitest run tests/files-schema.test.ts && pnpm tsc -b`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add package.json pnpm-lock.yaml data/schemas/files.schema.ts data/migrations/0009_dual_storage_security.sql tests
git commit -m "test: establish storage schema contract"
```

### Task 2: Add Provider Selection and Legacy KV Streaming

**Files:**

- Create: `src/storage/types.ts`
- Create: `src/storage/kv.ts`
- Create: `src/storage/r2.ts`
- Create: `src/storage/index.ts`
- Create: `tests/storage.test.ts`
- Modify: `worker-configuration.d.ts`

- [ ] **Step 1: Write failing provider tests**

```ts
test('auto storage prefers R2 only when bound', () => {
  expect(
    selectStorage({ STORAGE_DRIVER: 'auto', FILES: r2, file_drops: kv }),
  ).toBeInstanceOf(R2Storage)
  expect(
    selectStorage({ STORAGE_DRIVER: 'auto', file_drops: kv }),
  ).toBeInstanceOf(KvStorage)
})

test('legacy KV chunk metadata is streamed in order', async () => {
  await kv.put('file', 'chunks', {
    metadata: [{ objectId: 'part-0' }, { objectId: 'part-1' }],
  })
  await kv.put('part-0', 'one')
  await kv.put('part-1', 'two')
  await expect(readText(await new KvStorage(kv).get('file'))).resolves.toBe(
    'onetwo',
  )
})
```

- [ ] **Step 2: Verify red**

Run: `pnpm vitest run tests/storage.test.ts`

Expected: FAIL because `selectStorage`, `R2Storage`, and `KvStorage` do not exist.

- [ ] **Step 3: Implement the minimal adapter contract**

```ts
export interface Storage {
  get(key: string): Promise<ReadableStream<Uint8Array> | null>
  put(key: string, data: ArrayBuffer | ReadableStream): Promise<void>
  delete(key: string): Promise<void>
}

export function selectStorage(
  env: Pick<Env, 'STORAGE_DRIVER' | 'FILES' | 'file_drops'>,
): Storage {
  if (env.STORAGE_DRIVER === 'r2' && !env.FILES)
    throw new Error('R2 storage is not configured')
  return env.STORAGE_DRIVER !== 'kv' && env.FILES
    ? new R2Storage(env.FILES)
    : new KvStorage(env.file_drops)
}
```

`KvStorage.get` must detect legacy `metadata` and concatenate its objects in a
back-pressure-aware `TransformStream`. `R2Storage.get` returns `object.body`.
Add optional `FILES?: R2Bucket` and `STORAGE_DRIVER: string` to `Env`.

- [ ] **Step 4: Verify green**

Run: `pnpm vitest run tests/storage.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/storage worker-configuration.d.ts tests/storage.test.ts
git commit -m "feat: add KV and R2 storage adapters"
```

### Task 3: Enforce Upload Manifests and Server-Side Limits

**Files:**

- Create: `src/uploads.ts`
- Modify: `src/files/getFileChunkInfo.ts`
- Modify: `src/files/fileChunkCreate.ts`
- Modify: `src/files/mergeFileChunk.ts`
- Modify: `src/files/fileCreate.ts`
- Create: `tests/uploads.test.ts`

- [ ] **Step 1: Write failing upload validation tests**

```ts
test('rejects a chunk whose observed size differs from its manifest', async () => {
  await uploads.createManifest({
    id: 'u',
    sha: shaOf('abc'),
    size: 3,
    chunks: [{ chunkId: 0, size: 3 }],
  })
  await expect(uploads.putChunk('u', 0, new Blob(['abcd']))).rejects.toThrow(
    'Chunk size does not match manifest',
  )
})

test('finalization derives the persisted size from validated chunks', async () => {
  await uploads.createManifest({
    id: 'u',
    sha: shaOf('abc'),
    size: 3,
    chunks: [{ chunkId: 0, size: 3 }],
  })
  await uploads.putChunk('u', 0, new Blob(['abc']))
  await expect(uploads.finalize('u')).resolves.toMatchObject({ size: 3 })
})
```

- [ ] **Step 2: Verify red**

Run: `pnpm vitest run tests/uploads.test.ts`

Expected: FAIL because `UploadService` does not exist.

- [ ] **Step 3: Implement upload manifests**

Store a namespaced manifest in KV with `id`, `sha`, `size`, ordered chunks,
provider, and five-minute TTL. `putChunk` reads the manifest, rejects unknown
or duplicate chunk IDs and mismatched `Blob.size`, and writes only validated
chunks. `finalize` requires all chunks, sums actual sizes, validates the SHA-256
of the assembled stream, writes the final object through `Storage`, and returns
`{ objectId, provider, size, hash }`. `FileCreate` accepts that finalized
descriptor and rejects raw client `fileInfo` descriptors. Direct uploads derive
size and digest from the received `File`.

- [ ] **Step 4: Verify green**

Run: `pnpm vitest run tests/uploads.test.ts && pnpm build:web`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/uploads.ts src/files tests/uploads.test.ts
git commit -m "feat: validate uploads on the server"
```

### Task 4: Bind Download Grants and Atomically Claim Ephemeral Shares

**Files:**

- Create: `src/shares.ts`
- Modify: `src/files/fileShareCodeFetch.ts`
- Modify: `src/files/fileFetch.ts`
- Create: `tests/shares.test.ts`

- [ ] **Step 1: Write failing authorization tests**

```ts
test('a grant cannot download a different file', async () => {
  const grant = await shares.createGrant(fileA)
  await expect(shares.consumeGrant(grant.token, fileB.id)).rejects.toThrow(
    'Invalid download token',
  )
})

test('two concurrent ephemeral lookups grant access once', async () => {
  const results = await Promise.allSettled([
    shares.lookup(ephemeral.code),
    shares.lookup(ephemeral.code),
  ])
  expect(
    results.filter((result) => result.status === 'fulfilled'),
  ).toHaveLength(1)
})
```

- [ ] **Step 2: Verify red**

Run: `pnpm vitest run tests/shares.test.ts`

Expected: FAIL because `ShareService` does not exist.

- [ ] **Step 3: Implement the share service**

Generate `crypto.randomUUID()` grants under `download:${token}` with JSON
`{ fileId }` and a five-minute TTL. `lookup` reads a non-expired file; for an
ephemeral file it executes a conditional `UPDATE files SET claimed_at = now,
due_date = epoch WHERE id = ? AND claimed_at IS NULL AND due_date > now` and
requires one returned row. `consumeGrant` validates the stored file ID and
returns the record; the HTTP handler deletes the grant only after `Storage.get`
returns a non-null stream. `FileFetch` must no longer delete an unbound token.

- [ ] **Step 4: Verify green**

Run: `pnpm vitest run tests/shares.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/shares.ts src/files tests/shares.test.ts
git commit -m "feat: secure share grants and ephemeral claims"
```

### Task 5: Unify Terminal and Browser Reads, and Rate Limit Public Routes

**Files:**

- Modify: `src/middlewares/terminal.middleware.ts`
- Modify: `src/middlewares/limit.middleware.ts`
- Modify: `src/index.ts`
- Create: `tests/downloads.test.ts`

- [ ] **Step 1: Write failing terminal and rate-limit tests**

```ts
test('curl retrieves a KV chunked file through the shared download service', async () => {
  const response = await app.request(
    '/?code=123456',
    { headers: { 'user-agent': 'curl/8' } },
    env,
  )
  await expect(response.text()).resolves.toBe('onetwo')
})

test('the chunk and lookup routes invoke the configured limiter', async () => {
  await app.request('/files/chunks', { method: 'POST' }, limitedEnv)
  await expect(
    app.request('/files/share/123456', {}, limitedEnv),
  ).resolves.toHaveProperty('status', 429)
})
```

- [ ] **Step 2: Verify red**

Run: `pnpm vitest run tests/downloads.test.ts`

Expected: FAIL because terminal routing bypasses the storage and share services.

- [ ] **Step 3: Route through shared services**

Use `ShareService.lookup` in terminal middleware, then `selectStorage` to
stream the result. Add middleware paths `/files/*` and a dedicated lookup
limiter for `/files/share/*`; use route-class prefixes such as `upload:${ip}`
and `lookup:${ip}:${code}`. Preserve normal download capacity by only limiting
the grant exchange, not the already-authorized stream.

- [ ] **Step 4: Verify green**

Run: `pnpm vitest run tests/downloads.test.ts && pnpm vitest run`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/index.ts src/middlewares tests/downloads.test.ts
git commit -m "fix: unify public download authorization"
```

### Task 6: Bound Retention, Cleanup, Admin Queries, and Deployment Config

**Files:**

- Modify: `src/common.ts`
- Modify: `src/files/fileCreate.ts`
- Modify: `src/scheduled.ts`
- Modify: `src/admin/listShares.ts`
- Modify: `prepare.sh`
- Modify: `wrangler.example.toml`
- Create: `tests/cleanup.test.ts`

- [ ] **Step 1: Write failing retention and cleanup tests**

```ts
test('only 999year is permanent and arbitrary retention is rejected', () => {
  expect(parseDuration('999year')).toEqual({ permanent: true })
  expect(() => parseDuration('10000year')).toThrow('Duration exceeds maximum')
})

test('cleanup deletes one bounded batch through the stored provider', async () => {
  await cleanupExpired(env, { batchSize: 1 })
  expect(r2.delete).toHaveBeenCalledTimes(1)
  expect(kv.delete).not.toHaveBeenCalled()
})
```

- [ ] **Step 2: Verify red**

Run: `pnpm vitest run tests/cleanup.test.ts`

Expected: FAIL because duration parsing and bounded cleanup do not exist.

- [ ] **Step 3: Implement retention and administration limits**

Export `parseDuration` with `999year` as the only permanent value and a
constant maximum for all other inputs. Select expired rows with a fixed limit,
delete their storage through the selected row provider, and delete each D1 row
only after object deletion succeeds. Restrict admin `size` to 1..100, `page` to
non-negative integers, and `orderBy` to `size`, `due_date`, or `created_at`.
Add optional `R2_BUCKET` handling to `prepare.sh` and the commented R2 binding
to the example Wrangler file.

- [ ] **Step 4: Verify green**

Run: `pnpm vitest run tests/cleanup.test.ts && pnpm tsc -b && pnpm build:web`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/common.ts src/files/fileCreate.ts src/scheduled.ts src/admin/listShares.ts prepare.sh wrangler.example.toml tests/cleanup.test.ts
git commit -m "feat: bound retention and storage cleanup"
```

### Task 7: Update Clients, CI, and Documentation

**Files:**

- Modify: `web/api/uploader.ts`
- Modify: `web/api/index.ts`
- Modify: `web/main.tsx`
- Modify: `README.md`
- Modify: `.github/workflows/deploy.yml`
- Create: `tests/uploader.test.ts`

- [ ] **Step 1: Write a failing client request test**

```ts
test('uploader sends a manifest ID instead of client-controlled file metadata', async () => {
  await uploader.upload(file)
  expect(fetch).toHaveBeenCalledWith(
    '/files/chunks/merged',
    expect.objectContaining({ method: 'POST' }),
  )
  expect(lastCreateRequest.fileInfo).toBeUndefined()
})
```

- [ ] **Step 2: Verify red**

Run: `pnpm vitest run tests/uploader.test.ts`

Expected: FAIL because the client still sends `fileInfo`.

- [ ] **Step 3: Update the client and delivery pipeline**

Make the uploader send only its manifest ID after server finalization. Keep
download URLs using the opaque file-bound grant. Dynamically import `Admin` in
`web/main.tsx`; dynamically import the encryption helper when a password is
used. Document `STORAGE_DRIVER` and `R2_BUCKET`, including the automatic KV
fallback. Add `pnpm tsc -b`, `pnpm test`, and `pnpm build:web` before Wrangler
deployment in CI.

- [ ] **Step 4: Verify green**

Run: `pnpm test && pnpm tsc -b && pnpm build:web`

Expected: PASS with a smaller initial JavaScript bundle.

- [ ] **Step 5: Commit**

```bash
git add web README.md .github/workflows/deploy.yml tests/uploader.test.ts package.json pnpm-lock.yaml
git commit -m "feat: document dual storage sharing workflow"
```
