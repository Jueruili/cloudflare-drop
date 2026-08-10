# Cloudflare Drop Agent Skill and CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a portable Cloudflare Drop Agent Skill backed by a bundled Go CLI that uploads and retrieves text or files, including streaming V2 encrypted shares, on macOS and Linux.

**Architecture:** A small Go command delegates V2 framing to `internal/cryptoformat`, Cloudflare Drop HTTP operations to `internal/dropclient`, and argument/output/file orchestration to `internal/cli`. The Skill contains one launcher and four committed static binaries; TypeScript and Go use deterministic V2 fixtures to prevent format drift.

**Tech Stack:** Go 1.25.5, Go standard library, `golang.org/x/crypto/argon2`, Vitest/TypeScript compatibility tests, POSIX shell launcher, existing Hono Worker API.

---

## File Map

- `go.mod`, `go.sum`: Go module and pinned Argon2 dependency.
- `cmd/cloudflare-drop/main.go`: process entry point and build-time version.
- `internal/cryptoformat/v2.go`: V2 constants, header parsing, size calculation, AAD/nonce helpers, errors.
- `internal/cryptoformat/encrypt.go`: streaming V2 writer and injectable test dependencies.
- `internal/cryptoformat/decrypt.go`: strict V2 reader and streaming authenticated decryption.
- `internal/cryptoformat/password.go`: unbiased alphanumeric password generation.
- `internal/dropclient/client.go`: server URL validation, HTTP transport, API envelope decoding, shared types.
- `internal/dropclient/target.go`: share code/share URL resolution.
- `internal/dropclient/upload.go`: direct and upload-session APIs with bounded part retry.
- `internal/dropclient/download.go`: non-retried lookup and single-use download requests.
- `internal/cli/run.go`: command dispatch, exit-code mapping, common JSON errors.
- `internal/cli/args.go`: order-independent flag normalization and password source resolution.
- `internal/cli/upload.go`: file/text/stdin upload orchestration.
- `internal/cli/get.go`: lookup, download, integrity checking, decrypt, and result orchestration.
- `internal/cli/files.go`: safe destination names, private temporary files, atomic publication.
- `internal/cli/output.go`: stable JSON success/error contracts.
- `tests/fixtures/v2/manifest.json`: deterministic interop metadata and fixed derived key.
- `tests/fixtures/v2/ts-v2.bin`, `tests/fixtures/v2/go-v2.bin`: cross-language V2 fixtures.
- `tests/encryptor-interop.test.ts`: TypeScript side of V2 fixture compatibility.
- `skills/cloudflare-drop/SKILL.md`: activation description and agent workflow.
- `skills/cloudflare-drop/skill.yaml`: portable Skill manifest.
- `skills/cloudflare-drop/references/cli.md`: complete command and JSON reference.
- `skills/cloudflare-drop/scripts/cloudflare-drop`: OS/architecture launcher.
- `skills/cloudflare-drop/scripts/bin/*/cloudflare-drop`: four release binaries.
- `skills/cloudflare-drop/scripts/bin/SHA256SUMS`: committed binary hashes.
- `scripts/build-cloudflare-drop-skill`: reproducible cross-build script.
- `.prettierignore`: exclude native binary directories from staged formatting.
- `.github/workflows/deploy.yml`: run Go tests and verify committed binaries.
- `README.md`: document Skill/CLI usage and supported platforms.

### Task 1: Establish the Go CLI contract

**Files:**

- Create: `go.mod`
- Create: `go.sum`
- Create: `cmd/cloudflare-drop/main.go`
- Create: `internal/cli/run.go`
- Create: `internal/cli/output.go`
- Test: `internal/cli/run_test.go`

- [ ] **Step 1: Write failing process-contract tests**

Create tests that invoke `Run` without starting a subprocess:

```go
func TestRunVersionWritesJSON(t *testing.T) {
    var stdout, stderr bytes.Buffer
    code := Run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr, "1.2.3")
    require.Equal(t, 0, code)
    require.JSONEq(t, `{"ok":true,"operation":"version","version":"1.2.3"}`, stdout.String())
    require.Empty(t, stderr.String())
}

func TestRunRejectsUnknownCommandWithUsageExitCode(t *testing.T) {
    var stdout, stderr bytes.Buffer
    code := Run([]string{"unknown"}, strings.NewReader(""), &stdout, &stderr, "dev")
    require.Equal(t, 2, code)
    require.JSONEq(t, `{"ok":false,"error":{"code":"USAGE","message":"unknown command: unknown"}}`, stdout.String())
}
```

Use only the standard library in tests; replace `require` above with a local `assertJSON` helper using `encoding/json` and `reflect.DeepEqual` so the initial module adds no test framework.

- [ ] **Step 2: Run the tests and confirm the package does not exist**

Run: `go test ./internal/cli`

Expected: FAIL because `internal/cli` and `Run` do not exist.

- [ ] **Step 3: Add the module, output structs, and dispatcher**

Create `go.mod` with:

```go
module github.com/oustn/cloudflare-drop

go 1.24.0

toolchain go1.25.5

require golang.org/x/crypto v0.41.0
```

Define the stable envelope and exit classes:

```go
type ErrorBody struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}

type Response struct {
    OK        bool       `json:"ok"`
    Operation string     `json:"operation,omitempty"`
    Version   string     `json:"version,omitempty"`
    Error     *ErrorBody `json:"error,omitempty"`
}

const (
    ExitOK        = 0
    ExitUsage     = 2
    ExitNetwork   = 3
    ExitIntegrity = 4
)
```

`Run(args, stdin, stdout, stderr, version)` must handle `--version`, `version`, `upload`, and `get`; the last two initially return a `NOT_IMPLEMENTED` usage error. Encode exactly one JSON object plus a newline to stdout.

Create `main.go` as a thin wrapper:

```go
package main

import (
    "os"
    "github.com/oustn/cloudflare-drop/internal/cli"
)

var version = "dev"

func main() {
    os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, version))
}
```

- [ ] **Step 4: Format, resolve the module, and run tests**

Run: `gofmt -w cmd internal && go mod tidy && go test ./internal/cli`

Expected: PASS; `go.sum` is created.

- [ ] **Step 5: Commit the CLI skeleton**

```bash
git add go.mod go.sum cmd/cloudflare-drop internal/cli
git commit -m "feat: add cloudflare drop cli skeleton"
```

### Task 2: Implement V2 encryption and password generation

**Files:**

- Create: `internal/cryptoformat/v2.go`
- Create: `internal/cryptoformat/encrypt.go`
- Create: `internal/cryptoformat/password.go`
- Test: `internal/cryptoformat/encrypt_test.go`
- Test: `internal/cryptoformat/password_test.go`

- [ ] **Step 1: Write failing size, deterministic encryption, and password tests**

Cover the exact TypeScript constants and streaming behavior:

```go
func TestEncryptedSizeMatchesWrittenBytes(t *testing.T) {
    plaintext := bytes.Repeat([]byte("abcd"), 300_000)
    metadata := Metadata{Filename: "报告.txt", Type: "text/plain;charset=utf-8"}
    cfg := Config{Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)), DeriveKey: fixedKDF}
    var encrypted bytes.Buffer
    written, err := EncryptWithConfig(&encrypted, bytes.NewReader(plaintext), int64(len(plaintext)), "secret", metadata, cfg)
    if err != nil { t.Fatal(err) }
    want, err := EncryptedSize(int64(len(plaintext)), metadata)
    if err != nil { t.Fatal(err) }
    if written != want || int64(encrypted.Len()) != want { t.Fatalf("size mismatch: %d %d %d", written, encrypted.Len(), want) }
    if binary.LittleEndian.Uint16(encrypted.Bytes()[4:6]) != 2 { t.Fatal("missing V2 version") }
}

func TestGeneratePasswordUsesOnlyAlphanumericCharacters(t *testing.T) {
    password, err := GeneratePassword(bytes.NewReader(bytes.Repeat([]byte{247, 248, 0, 61}, 24)))
    if err != nil { t.Fatal(err) }
    if len(password) != 24 || !regexp.MustCompile(`^[A-Za-z0-9]{24}$`).MatchString(password) { t.Fatalf("bad password %q", password) }
}
```

Also test zero/negative sizes, a partial final frame, a two-frame plaintext, rejection-sampling bytes `248..255`, short random input, and a source shorter/longer than the declared plaintext size.

- [ ] **Step 2: Run the tests and confirm missing symbols**

Run: `go test ./internal/cryptoformat -run 'TestEncrypted|TestGenerate|TestEncrypt'`

Expected: FAIL because the package and functions do not exist.

- [ ] **Step 3: Add V2 constants and dependency injection**

Define these exact public contracts:

```go
type Metadata struct {
    Filename string `json:"filename,omitempty"`
    Type     string `json:"type,omitempty"`
}

type Parameters struct { Time, Memory uint32 }
type DeriveKeyFunc func(password string, salt []byte, parameters Parameters) ([]byte, error)
type Config struct { Random io.Reader; DeriveKey DeriveKeyFunc }

func EncryptedSize(plaintextSize int64, metadata Metadata) (int64, error)
func Encrypt(dst io.Writer, src io.Reader, plaintextSize int64, password string, metadata Metadata) (int64, error)
func EncryptWithConfig(dst io.Writer, src io.Reader, plaintextSize int64, password string, metadata Metadata, cfg Config) (int64, error)
func GeneratePassword(random io.Reader) (string, error)
```

Use version `2`, mode `1`, time `3`, memory `65536`, one MiB frames, 16-byte salt, 12-byte IVs, 8-byte frame nonce prefix, 16-byte GCM tags, and footer magic `CDFT`. The default KDF is:

```go
return argon2.IDKey([]byte(password), salt, parameters.Time, parameters.Memory, 1, 32), nil
```

- [ ] **Step 4: Implement the V2 streaming writer**

Write the four-byte header length and authenticated header exactly as `web/helpers/encryptor.ts` does. Use little-endian integers, `io.ReadFull` for every random field, and `io.LimitedReader` plus a one-byte overflow probe to ensure the source length equals `plaintextSize`.

For each frame use:

```go
nonce := append(append([]byte{}, noncePrefix...), uint32LE(frameIndex)...)
aad := join(header, []byte("cloudflare-drop:v2:frame"), uint32LE(frameIndex))
ciphertext := dataGCM.Seal(nil, nonce, plaintextFrame, aad)
```

Finish with a 16-byte plaintext footer (`CDFT`, frame count, plaintext size) encrypted with footer IV and AAD `header + "cloudflare-drop:v2:footer"`.

- [ ] **Step 5: Implement unbiased generated passwords**

Read random bytes until 24 alphabet indices are accepted. Reject bytes `>= 248`; map accepted bytes with `% 62` into `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789`. Never fall back to time- or math-based randomness.

- [ ] **Step 6: Run crypto tests**

Run: `gofmt -w internal/cryptoformat && go test ./internal/cryptoformat`

Expected: PASS, including declared-size mismatch tests.

- [ ] **Step 7: Commit encryption support**

```bash
git add internal/cryptoformat go.mod go.sum
git commit -m "feat: implement streaming v2 encryption"
```

### Task 3: Implement strict V2 decryption

**Files:**

- Modify: `internal/cryptoformat/v2.go`
- Create: `internal/cryptoformat/decrypt.go`
- Test: `internal/cryptoformat/decrypt_test.go`

- [ ] **Step 1: Write failing round-trip and corruption tests**

Add table tests for correct metadata/plaintext plus every authenticated boundary:

```go
func TestDecryptRoundTrip(t *testing.T) {
    plaintext := bytes.Repeat([]byte("stream me"), 200_000)
    metadata := Metadata{Filename: "../报告.txt", Type: "text/plain"}
    cfg := deterministicConfig()
    var encrypted bytes.Buffer
    _, err := EncryptWithConfig(&encrypted, bytes.NewReader(plaintext), int64(len(plaintext)), "secret", metadata, cfg)
    if err != nil { t.Fatal(err) }
    var decrypted bytes.Buffer
    gotMetadata, written, err := DecryptWithConfig(&decrypted, bytes.NewReader(encrypted.Bytes()), "secret", cfg)
    if err != nil { t.Fatal(err) }
    if gotMetadata != metadata || written != int64(len(plaintext)) || !bytes.Equal(decrypted.Bytes(), plaintext) { t.Fatal("round trip mismatch") }
}
```

Mutate the password, header, first frame, frame order, footer, and total length in separate subtests. Add a minimal version-1 header and assert `errors.Is(err, ErrUnsupportedVersion)`. Add headers with time `0`/`11`, memory `0`/`262145`, and chunk size above 64 MiB to prove untrusted KDF parameters are bounded before Argon2 allocation.

- [ ] **Step 2: Run the tests and confirm decryption is absent**

Run: `go test ./internal/cryptoformat -run 'TestDecrypt|TestReject'`

Expected: FAIL with undefined `DecryptWithConfig` and error values.

- [ ] **Step 3: Implement strict header parsing and V2-only errors**

Add sentinel errors:

```go
var (
    ErrUnsupportedVersion = errors.New("unsupported encrypted format version")
    ErrInvalidFormat      = errors.New("invalid encrypted file format")
    ErrAuthentication     = errors.New("failed to authenticate encrypted share")
)
```

Expose:

```go
func Decrypt(dst io.Writer, src io.ReadSeeker, password string) (Metadata, int64, error)
func DecryptWithConfig(dst io.Writer, src io.ReadSeeker, password string, cfg Config) (Metadata, int64, error)
```

Require version 2/mode 1, time `1..10`, memory `1..262144` KiB, chunk size `1..64MiB`, wrapped key length exactly 48, nonempty authenticated metadata, and exact header length. Wrap GCM-open failures with `ErrAuthentication` without distinguishing password and corruption.

- [ ] **Step 4: Decrypt footer first, then frames sequentially**

Use `io.ReadSeeker` to find the 32-byte encrypted footer, authenticate it, validate `ceil(plaintextSize/chunkSize) == frameCount`, compute the exact ciphertext length, seek to the first frame, and decrypt/write one frame at a time. Only return success after every frame and footer invariant passes.

- [ ] **Step 5: Run all crypto tests and inspect allocation behavior**

Run: `gofmt -w internal/cryptoformat && go test ./internal/cryptoformat`

Expected: PASS. The multi-frame test must not call `io.ReadAll` inside `internal/cryptoformat` (verify with `rg -n 'io\.ReadAll' internal/cryptoformat`, expected no matches).

- [ ] **Step 6: Commit strict V2 decryption**

```bash
git add internal/cryptoformat
git commit -m "feat: implement strict v2 decryption"
```

### Task 4: Lock Go and TypeScript V2 compatibility

**Files:**

- Create: `tests/fixtures/v2/manifest.json`
- Create: `tests/fixtures/v2/ts-v2.bin`
- Create: `tests/fixtures/v2/go-v2.bin`
- Create: `tests/encryptor-interop.test.ts`
- Create: `internal/cryptoformat/interop_test.go`

- [ ] **Step 1: Add a fixed interop manifest**

Use one password, fixed 32-byte derived key, deterministic random byte stream, Unicode/HTML-sensitive metadata, and plaintext larger than one frame:

```json
{
  "password": "InteropPassword123",
  "derivedKeyHex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  "filename": "报告<&>.txt",
  "type": "text/plain;charset=utf-8",
  "plaintextPattern": "cloudflare-drop-v2-interop\n",
  "repeat": 45000
}
```

- [ ] **Step 2: Write failing Go fixture tests**

`interop_test.go` must decrypt `ts-v2.bin` with a KDF that returns `derivedKeyHex`, compare metadata and plaintext, and encrypt with deterministic randomness then byte-compare against `go-v2.bin`. Guard fixture regeneration behind `UPDATE_V2_FIXTURES=1`; in update mode the Go test writes only `go-v2.bin` and skips the `ts-v2.bin` assertion when that file is not present. Normal test runs require both fixtures and never write files.

Run: `go test ./internal/cryptoformat -run Interop`

Expected: FAIL because fixtures do not exist yet.

- [ ] **Step 3: Write the TypeScript compatibility test**

Use `vi.hoisted` and `vi.mock('argon2-browser/dist/argon2-bundled.min.js', ...)` to return the same fixed derived key. Stub `crypto.getRandomValues` with the deterministic stream. Assert that TypeScript encryption matches `ts-v2.bin`, TypeScript decrypts `go-v2.bin`, and metadata/plaintext match the manifest. In update mode this test writes only `ts-v2.bin`; outside update mode both fixture assertions are mandatory.

Run: `pnpm vitest run tests/encryptor-interop.test.ts`

Expected: FAIL because the fixture files do not exist.

- [ ] **Step 4: Generate each fixture once and rerun without update mode**

Run:

```bash
UPDATE_V2_FIXTURES=1 go test ./internal/cryptoformat -run Interop
UPDATE_V2_FIXTURES=1 pnpm vitest run tests/encryptor-interop.test.ts
go test ./internal/cryptoformat -run Interop
pnpm vitest run tests/encryptor-interop.test.ts
```

Expected: both final commands PASS and do not modify fixtures.

- [ ] **Step 5: Add a real Argon2id standard vector test**

In Go, assert `argon2.IDKey` with password `password`, salt `somesalt`, time 2, memory 65536, parallelism 1, length 32 equals this Argon2id v=19 value:

```text
09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7
```

This keeps format injection tests separate from KDF correctness.

- [ ] **Step 6: Commit interop fixtures**

```bash
git add internal/cryptoformat/interop_test.go tests/encryptor-interop.test.ts tests/fixtures/v2
git commit -m "test: lock v2 cross-language compatibility"
```

### Task 5: Implement target parsing and the HTTP client core

**Files:**

- Create: `internal/dropclient/client.go`
- Create: `internal/dropclient/target.go`
- Test: `internal/dropclient/client_test.go`
- Test: `internal/dropclient/target_test.go`

- [ ] **Step 1: Write failing target-resolution tests**

Cover bare code, share URL, environment fallback, conflicting origins, invalid codes, credentials, fragments, unrelated query parameters, HTTPS enforcement, and local HTTP exceptions:

```go
func TestResolveTargetFromShareURL(t *testing.T) {
    target, err := ResolveTarget("https://drop.example.com/?code=123456", "", "")
    if err != nil { t.Fatal(err) }
    if target.Server.String() != "https://drop.example.com" || target.Code != "123456" { t.Fatalf("unexpected target %#v", target) }
}

func TestRejectsHTTPForRemoteServer(t *testing.T) {
    _, err := ResolveServer("http://drop.example.com")
    if !errors.Is(err, ErrInsecureServer) { t.Fatalf("expected insecure server, got %v", err) }
}
```

- [ ] **Step 2: Write failing envelope-decoding tests**

Use `httptest.Server` to return: a 200 success envelope, a 200 `{result:false}` envelope, a 400 text response, invalid JSON, and an oversized error body. Assert stable typed errors and that reported URLs omit query strings.

- [ ] **Step 3: Run tests and confirm package absence**

Run: `go test ./internal/dropclient`

Expected: FAIL because the package does not exist.

- [ ] **Step 4: Implement server/target resolution**

Define:

```go
type Target struct { Server *url.URL; Code string }
func ResolveServer(raw string) (*url.URL, error)
func ResolveTarget(input, explicitServer, environmentServer string) (Target, error)
```

Normalize the server to origin-only form with no trailing slash. Accept only six ASCII digits. Share URLs must contain exactly one `code` query parameter and no other query keys.

- [ ] **Step 5: Implement the HTTP client and envelope**

Define:

```go
type Client struct { base *url.URL; http *http.Client }
func New(server string, client *http.Client) (*Client, error)
type APIError struct { Code, Message string; Status int }
```

Default transport settings: 10-second dial/TLS handshake, 15-second response-header timeout, 30-second idle timeout; command contexts set overall deadlines. Limit parsed JSON/text error bodies to 1 MiB. Treat logical `{result:false}` as failure even with HTTP 200.

- [ ] **Step 6: Run and commit client-core tests**

Run: `gofmt -w internal/dropclient && go test ./internal/dropclient`

Expected: PASS.

```bash
git add internal/dropclient
git commit -m "feat: add cloudflare drop http client core"
```

### Task 6: Implement direct, session, and encrypted uploads

**Files:**

- Create: `internal/dropclient/upload.go`
- Test: `internal/dropclient/upload_test.go`

- [ ] **Step 1: Write failing direct-upload tests**

Use `httptest.Server` to parse multipart form data and assert `file`, JSON-encoded `duration`, `isEphemeral`, `isEncrypted`, `plaintextSize`, `plaintextType`, and `hash`. Verify text uses filename `text` and MIME `plain/string`; verify encrypted text carries encrypted bytes but plaintext size/type metadata.

- [ ] **Step 2: Write failing upload-session tests**

Return a two-byte session part size, capture numbered parts, fail part 2 once with 503, and assert the client retries that uncommitted part with identical bytes before completing. Return 400 for another part and assert no retry. Assert the create payload uses encrypted size for `size`, original size for `plaintextSize`, and an empty hash for encrypted uploads.

- [ ] **Step 3: Run focused tests and confirm missing methods**

Run: `go test ./internal/dropclient -run Upload`

Expected: FAIL because upload APIs are undefined.

- [ ] **Step 4: Implement upload types and direct multipart streaming**

Define:

```go
type UploadMetadata struct {
    Filename, Type, Hash, Duration string
    Size, PlaintextSize int64
    Ephemeral, Encrypted bool
}
type ShareResult struct {
    Hash string `json:"hash"`
    Code string `json:"code"`
    DueDate json.RawMessage `json:"due_date"`
    Ephemeral bool `json:"is_ephemeral"`
    Encrypted bool `json:"is_encrypted"`
}
func (c *Client) UploadDirect(ctx context.Context, metadata UploadMetadata, body io.Reader) (ShareResult, error)
func (c *Client) UploadSession(ctx context.Context, metadata UploadMetadata, body io.Reader) (ShareResult, error)
```

Use `io.Pipe` and `multipart.Writer` for direct file uploads so the file is not buffered. Close the pipe with the writer error and ensure request cancellation unblocks the producer goroutine.

- [ ] **Step 5: Implement session creation, exact part reads, retry, and completion**

Decode `sessionId`, `partSize`, and `uploadedParts`. Validate a positive part size no larger than 64 MiB. Read one part into a reusable buffer, send a bounded slice, and retry only that part up to three total attempts for transport errors, 408, 429, or 5xx using 100/250 ms backoff. Never retry session creation or completion automatically.

- [ ] **Step 6: Verify upload tests and memory boundaries**

Run: `gofmt -w internal/dropclient && go test ./internal/dropclient -run Upload`

Expected: PASS. `rg -n 'io\.ReadAll' internal/dropclient/upload.go` must show no file-body read-all path.

- [ ] **Step 7: Commit upload client support**

```bash
git add internal/dropclient/upload.go internal/dropclient/upload_test.go
git commit -m "feat: add direct and session uploads"
```

### Task 7: Implement lookup, single-use download, and safe files

**Files:**

- Create: `internal/dropclient/download.go`
- Test: `internal/dropclient/download_test.go`
- Create: `internal/cli/files.go`
- Test: `internal/cli/files_test.go`

- [ ] **Step 1: Write failing no-retry lookup/download tests**

Build a custom `RoundTripper` that returns a transport error and counts calls. Assert `Lookup` makes exactly one call because ephemeral lookups have side effects. Do the same for `Download` because tokens are single-use. Verify download request errors redact `?token=...`.

- [ ] **Step 2: Write failing destination safety tests**

Cover `../../secret.txt`, absolute authenticated names, Unicode base names, an explicit directory, an explicit filename, existing destinations, owner-only temporary permissions, cleanup on callback failure, and atomic rename on success.

- [ ] **Step 3: Run focused tests and confirm missing behavior**

Run: `go test ./internal/dropclient ./internal/cli -run 'Lookup|Download|Destination|Publish'`

Expected: FAIL because the APIs do not exist.

- [ ] **Step 4: Implement lookup and download**

Define:

```go
type Share struct {
    ID, Code, Filename, Hash, Type, Token string
    Size int64
    Ephemeral, Encrypted bool
    DueDate json.RawMessage
}
func (c *Client) Lookup(ctx context.Context, code string) (Share, error)
func (c *Client) Download(ctx context.Context, share Share) (io.ReadCloser, http.Header, error)
```

Call `/files/share/:code` and `/files/:id?token=...` exactly once each. Apply response body size limits only to metadata/errors, not file bodies.

- [ ] **Step 5: Implement private temp files and atomic publication**

Expose one orchestration helper:

```go
func publishFile(output, authenticatedName string, write func(*os.File) error) (absolutePath string, err error)
```

Sanitize with `filepath.Base`, reject empty/`.` names, create the destination directory only when it already exists or was explicitly requested, use `os.CreateTemp` followed by `Chmod(0600)`, `Sync`, `Close`, exclusive destination check, then `os.Rename`. Defer removal unless rename succeeds.

- [ ] **Step 6: Run and commit download/file tests**

Run: `gofmt -w internal/dropclient internal/cli && go test ./internal/dropclient ./internal/cli`

Expected: PASS.

```bash
git add internal/dropclient/download.go internal/dropclient/download_test.go internal/cli/files.go internal/cli/files_test.go
git commit -m "feat: add safe share downloads"
```

### Task 8: Wire upload/get commands and JSON results

**Files:**

- Modify: `internal/cli/run.go`
- Modify: `internal/cli/output.go`
- Create: `internal/cli/args.go`
- Create: `internal/cli/upload.go`
- Create: `internal/cli/get.go`
- Test: `internal/cli/args_test.go`
- Test: `internal/cli/upload_test.go`
- Test: `internal/cli/get_test.go`

- [ ] **Step 1: Write failing order-independent argument tests**

Assert both `upload --server URL file.txt` and `upload file.txt --server URL` parse identically. Cover exactly one content source, direct/file password conflict, environment fallback, `--password-file` newline trimming, empty passwords, missing server, `--ephemeral`, duration, output, and unknown flags.

- [ ] **Step 2: Write failing command-level upload tests**

Inject an `httptest.Server` and temporary files. Cover direct file, session file, literal text, stdin UTF-8 validation, encrypted file with supplied password, encrypted text, and generated password. Assert supplied passwords never appear in stdout/stderr; generated passwords match `^[A-Za-z0-9]{24}$` and appear once in JSON.

- [ ] **Step 3: Write failing command-level get tests**

Cover bare code plus environment server, URL-derived server, plaintext text JSON, plaintext SHA-256 mismatch, plaintext file path, encrypted file recovery, wrong password/integrity exit code 4, V1 rejection, and an ephemeral lookup transport failure with exactly one lookup call.

- [ ] **Step 4: Run CLI tests and confirm unimplemented commands**

Run: `go test ./internal/cli -run 'Args|Upload|Get'`

Expected: FAIL because upload/get orchestration is absent.

- [ ] **Step 5: Implement argument normalization and password resolution**

Reorder recognized flags before positional arguments before passing them to `flag.FlagSet`, preserving `--flag=value` and consuming values for known valued flags. Reject multiple positionals and multiple explicit password flags. Direct flag or file overrides `CLOUDFLARE_DROP_PASSWORD`; strip one trailing CRLF/LF from password files without trimming other characters.

- [ ] **Step 6: Implement upload orchestration**

For unencrypted files at most 5 MiB, call direct upload. Hash larger plaintext files with a first streaming pass, seek back, and use a session. For encrypted files, create an `io.Pipe`; run `cryptoformat.Encrypt` in a goroutine and feed its reader to `UploadSession`, propagating errors both directions. Use exact encrypted size before session creation. Buffer only text/direct encrypted text.

Return:

```go
type UploadResponse struct {
    OK        bool    `json:"ok"`
    Operation string  `json:"operation"`
    Code      string  `json:"code"`
    URL       string  `json:"url"`
    Encrypted bool    `json:"encrypted"`
    Ephemeral bool    `json:"ephemeral"`
    Password  *string `json:"password"`
    ExpiresAt *string `json:"expiresAt"`
}
```

Parse `due_date` from null, RFC3339 strings, or epoch milliseconds; normalize non-null values to RFC3339 UTC.

- [ ] **Step 7: Implement get orchestration**

For text, read with a 10 MiB safety limit and validate UTF-8. For plaintext files, stream through SHA-256 into `publishFile` and compare with `subtle.ConstantTimeCompare` after hex decoding. For encrypted files, download ciphertext to a 0600 temp file, then call `cryptoformat.Decrypt` inside `publishFile`; remove ciphertext on every exit path. Map format/authentication errors to exit 4.

- [ ] **Step 8: Run all Go tests and build the local CLI**

Run:

```bash
gofmt -w cmd internal
go test ./...
go build -o /tmp/cloudflare-drop ./cmd/cloudflare-drop
/tmp/cloudflare-drop --version
```

Expected: all tests PASS; version command prints valid JSON.

- [ ] **Step 9: Commit complete CLI commands**

```bash
git add internal/cli cmd/cloudflare-drop
git commit -m "feat: add cloudflare drop upload and get commands"
```

### Task 9: Create and validate the Agent Skill

**Files:**

- Create: `skills/cloudflare-drop/SKILL.md`
- Create: `skills/cloudflare-drop/skill.yaml`
- Create: `skills/cloudflare-drop/references/cli.md`
- Create: `skills/cloudflare-drop/scripts/cloudflare-drop`
- Test: `tests/cloudflare-drop-skill.test.ts`

- [ ] **Step 1: Write failing Skill structure and trigger tests**

Read the files from Vitest and assert legal/matching name, activation-oriented description under 1024 characters, launcher references all four OS/arch targets, ephemeral warning, V2-only boundary, missing-server prompt, password redaction guidance, three Chinese/English should-trigger examples, and three near-miss exclusions.

Run: `pnpm vitest run tests/cloudflare-drop-skill.test.ts`

Expected: FAIL because the Skill does not exist.

- [ ] **Step 2: Create the manifest**

Use:

```yaml
name: cloudflare-drop
version: 0.1.0
description: Upload and retrieve Cloudflare Drop shares with a bundled native CLI.
author: cloudflare-drop
entry: SKILL.md
platforms:
  - claude
  - codex
tools:
  - shell
mcp: []
dependencies:
  npm: []
  python: []
permissions:
  filesystem:
    - read
    - write
  network:
    - '*'
```

- [ ] **Step 3: Write focused Skill instructions**

Use frontmatter name `cloudflare-drop` and a description beginning `Use this skill when...` that contains upload/share/share-code/encrypted-share intents in Chinese and English. The workflow must:

1. Resolve or ask for the instance URL.
2. Confirm the intended source/destination.
3. Use encryption only when requested; allow auto-generated passwords.
4. Use `--ephemeral` only for explicit one-time intent and warn before retrieval.
5. Invoke `scripts/cloudflare-drop` and parse its JSON.
6. Return code/link/path/text and generated password without exposing supplied passwords.

Keep the command matrix and JSON schema in `references/cli.md`, and instruct the agent to read it only when constructing or diagnosing a command.

- [ ] **Step 4: Add the portable launcher**

Create an extensionless POSIX shell script that maps `Darwin:x86_64`, `Darwin:arm64`, `Linux:x86_64`, and `Linux:aarch64|arm64` to the matching directory, errors in JSON for unsupported targets, and uses `exec`:

```sh
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$script_dir/bin/$target/cloudflare-drop" "$@"
```

- [ ] **Step 5: Run Skill tests and the bundled validator**

Run:

```bash
pnpm vitest run tests/cloudflare-drop-skill.test.ts
PYTHONDONTWRITEBYTECODE=1 UV_PROJECT_ENVIRONMENT=$(mktemp -d) uv --project /Users/zengk/.aiskills/packages/create-skill/0.1.2/scripts/skills-ref run skills-ref validate skills/cloudflare-drop
```

Expected: both PASS with no manifest or frontmatter validation errors.

- [ ] **Step 6: Commit the source Skill**

```bash
chmod +x skills/cloudflare-drop/scripts/cloudflare-drop
git add skills/cloudflare-drop tests/cloudflare-drop-skill.test.ts
git commit -m "feat: add cloudflare drop agent skill"
```

### Task 10: Build binaries, wire CI, and document usage

**Files:**

- Create: `scripts/build-cloudflare-drop-skill`
- Create: `skills/cloudflare-drop/scripts/bin/darwin-amd64/cloudflare-drop`
- Create: `skills/cloudflare-drop/scripts/bin/darwin-arm64/cloudflare-drop`
- Create: `skills/cloudflare-drop/scripts/bin/linux-amd64/cloudflare-drop`
- Create: `skills/cloudflare-drop/scripts/bin/linux-arm64/cloudflare-drop`
- Create: `skills/cloudflare-drop/scripts/bin/SHA256SUMS`
- Modify: `.prettierignore`
- Modify: `.github/workflows/deploy.yml`
- Modify: `README.md`

- [ ] **Step 1: Create the reproducible build script**

The extensionless POSIX script must use `set -eu`, require Go 1.25.5, accept `VERSION` with default `dev`, set `CGO_ENABLED=0`, and build the four explicit target pairs with:

```bash
go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$output" ./cmd/cloudflare-drop
```

Generate `SHA256SUMS` in stable lexical order using `shasum -a 256` on macOS or `sha256sum` on Linux. Build into a temporary directory and replace each destination only after all builds succeed.

- [ ] **Step 2: Exclude native artifacts from Prettier**

Append these exact entries to `.prettierignore`:

```text
skills/cloudflare-drop/scripts/bin/
tests/fixtures/v2/*.bin
```

- [ ] **Step 3: Build and inspect all four binaries**

Run:

```bash
chmod +x scripts/build-cloudflare-drop-skill
VERSION=0.1.0 scripts/build-cloudflare-drop-skill
file skills/cloudflare-drop/scripts/bin/*/cloudflare-drop
skills/cloudflare-drop/scripts/cloudflare-drop --version
```

Expected: `file` reports two Mach-O and two ELF executables with the requested architectures; the launcher selects the host binary and reports version `0.1.0` as JSON.

- [ ] **Step 4: Add Go and binary verification to CI**

In `.github/workflows/deploy.yml` verify job, add `actions/setup-go@v5` with `go-version: '1.25.5'`, then run:

```yaml
- run: go test ./...
- run: VERSION=0.1.0 scripts/build-cloudflare-drop-skill
- run: git diff --exit-code -- skills/cloudflare-drop/scripts/bin
```

Place these before the Web build so source tests and committed artifacts are checked on every main deployment.

- [ ] **Step 5: Document agent and direct CLI usage**

Add a concise `Agent Skill / CLI` README section with supported platforms, no-install behavior, `CLOUDFLARE_DROP_URL`, upload/get examples, V2-only encryption, generated 24-character password behavior, and the warning that ephemeral shares are consumed by lookup rather than successful download.

- [ ] **Step 6: Run the complete verification suite**

Run:

```bash
go test ./...
pnpm test
pnpm exec tsc -p tsconfig.worker.json --noEmit
pnpm build:web
PYTHONDONTWRITEBYTECODE=1 UV_PROJECT_ENVIRONMENT=$(mktemp -d) uv --project /Users/zengk/.aiskills/packages/create-skill/0.1.2/scripts/skills-ref run skills-ref validate skills/cloudflare-drop
VERSION=0.1.0 scripts/build-cloudflare-drop-skill
git diff --exit-code -- skills/cloudflare-drop/scripts/bin
git diff --check
```

Expected: every command exits 0; rebuilding produces byte-identical committed binaries.

- [ ] **Step 7: Commit distribution artifacts and docs**

```bash
git add scripts/build-cloudflare-drop-skill skills/cloudflare-drop/scripts/bin .prettierignore .github/workflows/deploy.yml README.md
git commit -m "build: bundle cloudflare drop cli binaries"
```

### Task 11: Final acceptance checks

**Files:**

- Verify only; modify the owning test/source file if a check exposes a defect.

- [ ] **Step 1: Run plaintext mock-server round trips**

Run the CLI integration tests for file, literal text, and stdin against the in-process server:

```bash
go test ./internal/cli -run 'TestUpload.*Plain|TestGet.*Plain' -count=1 -v
```

Expected: PASS with JSON results and verified file hashes.

- [ ] **Step 2: Run encrypted and ephemeral acceptance tests**

```bash
go test ./internal/cli -run 'TestUpload.*Encrypt|TestGet.*Encrypt|TestGet.*Ephemeral' -count=1 -v
pnpm vitest run tests/encryptor-interop.test.ts tests/encryptor.test.ts
```

Expected: PASS; V2 cross-language fixtures round-trip, V1 is rejected by Go, and ephemeral lookup is attempted once.

- [ ] **Step 3: Inspect runtime artifacts and secrets behavior**

Run:

```bash
skills/cloudflare-drop/scripts/cloudflare-drop --version
find skills/cloudflare-drop/scripts/bin -type f -maxdepth 3 -print
rg -n 'password|token' internal/cli internal/dropclient skills/cloudflare-drop
```

Expected: launcher returns version JSON; exactly four executables plus `SHA256SUMS` are present; every password/token occurrence is input handling, redaction, or documented guidance rather than logging.

- [ ] **Step 4: Review the final diff and working tree**

Run:

```bash
git diff --check HEAD~10..HEAD
git status --short
```

Expected: no whitespace errors; only the user's pre-existing unrelated untracked files remain.
