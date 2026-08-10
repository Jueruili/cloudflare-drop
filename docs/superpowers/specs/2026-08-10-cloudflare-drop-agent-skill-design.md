# Cloudflare Drop Agent Skill and CLI Design

## Summary

Add a portable Agent Skill that lets Codex, Claude, and similar agents upload
and retrieve text or files from any deployed Cloudflare Drop instance. The
Skill maps natural-language requests such as "share this file", "use this
share code", and "create an encrypted share" to a bundled native CLI.

The CLI is implemented in Go, supports the current V2 encrypted-file format,
and is distributed as four native binaries inside the Skill. End users do not
need Go, Node.js, a package manager, or a first-run dependency installation.

## Goals

- Upload files, literal text, or standard input to a caller-selected
  Cloudflare Drop instance.
- Resolve either a six-digit share code or a Cloudflare Drop share URL.
- Retrieve plaintext shares and decrypt V2 encrypted shares locally.
- Support expiring and one-time (ephemeral) shares already exposed by the
  application.
- Produce stable JSON on stdout for agent consumption and diagnostics on
  stderr.
- Stream file encryption, uploads, downloads, and decryption so file size does
  not determine CLI memory use.
- Preserve wire compatibility between the Go CLI and the current TypeScript
  V2 implementation.

## Non-goals

- The CLI will not decrypt the historical V1 encrypted-file format.
- The CLI will not expose administration APIs.
- The CLI will not manage Cloudflare deployments or server configuration.
- The CLI will not persist passwords, server addresses, or download tokens.
- The first version will not support Windows.
- The Skill will not infer or bypass a password for an encrypted share.

## Supported Platforms

The Skill contains binaries for:

- macOS amd64
- macOS arm64
- Linux amd64
- Linux arm64

The launcher selects the matching binary from `scripts/bin/<os>-<arch>/` and
returns a clear unsupported-platform error for any other target. The binaries
are committed with the Skill rather than downloaded at runtime.

## Repository Layout

```text
cmd/cloudflare-drop/
  main.go
internal/dropclient/
  client.go
  upload.go
  download.go
internal/cryptoformat/
  v2.go
  encrypt.go
  decrypt.go
internal/cli/
  upload.go
  get.go
  output.go
skills/cloudflare-drop/
  SKILL.md
  skill.yaml
  references/cli.md
  scripts/cloudflare-drop
  scripts/bin/darwin-amd64/cloudflare-drop
  scripts/bin/darwin-arm64/cloudflare-drop
  scripts/bin/linux-amd64/cloudflare-drop
  scripts/bin/linux-arm64/cloudflare-drop
```

The HTTP client, encrypted-file format, and command orchestration are separate
packages with focused tests. Small files may be combined when an individual
file would otherwise contain only a trivial wrapper; package boundaries remain
unchanged.

## Skill Boundary and Triggers

The Skill activates when the user wants to upload, share, retrieve, download,
or decrypt content through Cloudflare Drop. Trigger phrases include nearby
Chinese and English wording such as:

- 分享这个文件、上传并分享、生成分享码
- 用分享码获取、下载这个分享、打开分享链接
- 加密分享、带密码分享、阅后即焚、一次性分享
- share this file, create an encrypted share, download by share code

The Skill does not activate for generic filesystem copy operations, unrelated
cloud storage providers, Cloudflare deployment management, or administrative
share deletion.

If neither the command nor environment supplies an instance URL, the Skill
asks the user for the deployed Cloudflare Drop URL. It does not guess a public
service.

## Command Interface

The CLI exposes two commands:

```text
cloudflare-drop upload <path> [options]
cloudflare-drop upload --text <value> [options]
cloudflare-drop upload --stdin [options]
cloudflare-drop get <share-code-or-url> [options]
```

Common options:

- `--server <url>` selects the Cloudflare Drop instance.
- `CLOUDFLARE_DROP_URL` supplies the default instance URL.
- `--json` is accepted for explicitness, although JSON is the default output.

Upload options:

- `--duration <value>` passes a server duration such as `1hour` or `7day`.
- `--ephemeral` creates a one-time share.
- `--encrypt` enables V2 client-side encryption.
- `--password <value>` supplies a password directly.
- `--password-file <path>` reads the password without shell escaping.
- `CLOUDFLARE_DROP_PASSWORD` supplies the password from the environment.

Get options:

- `--output <path>` selects a destination file or directory.
- `--password`, `--password-file`, and `CLOUDFLARE_DROP_PASSWORD` provide a
  decryption password.

`upload` accepts exactly one of a file path, `--text`, or `--stdin`. A password
may come from `--password` or `--password-file`, but those two flags cannot be
combined. Either explicit flag overrides `CLOUDFLARE_DROP_PASSWORD`. If none is
present, encrypted uploads generate a password. Conflicting content sources or
password flags are usage errors.

## Server and Share URL Resolution

For uploads, the server comes from `--server` or `CLOUDFLARE_DROP_URL`.

For retrieval, a share URL provides both the server origin and the `code`
query parameter. A bare six-digit code requires `--server` or the environment
variable. If an explicit server conflicts with the origin in a share URL, the
CLI returns a usage error instead of silently sending the code elsewhere.

HTTPS is required for non-local servers. Plain HTTP is accepted only for
`localhost`, `127.0.0.1`, and `[::1]` to support local development. Server URLs
must not contain credentials, fragments, or unrelated query parameters.

## Upload Data Flow

### Plain files

1. Validate the input and server URL.
2. For files at or below 5 MiB, matching the current Web client boundary, send
   multipart form data to `PUT /files`.
3. For larger files, create an upload session with `POST /files/uploads`, send
   parts to the returned session, then call the completion endpoint.
4. Compute the plaintext SHA-256 while reading the file and include it where
   required by the current API.
5. Return the share result as JSON.

The CLI follows the server-provided session part size rather than assuming it
will always remain 5 MiB.

### Plain text

Text is uploaded with MIME type `plain/string` through `PUT /files`. Standard
input is treated as bytes and must be valid UTF-8 when used as a text share.

### Encrypted content

1. Use the provided password or generate one.
2. Calculate the exact encrypted size from plaintext size and authenticated
   metadata before creating the upload session.
3. Produce a V2 byte stream and feed it directly into session-sized upload
   parts without writing plaintext or ciphertext temporary files.
4. Mark the upload as encrypted, provide plaintext size and type, and use
   `encrypted-file` as the server-visible filename.
5. Return the generated password only when the CLI generated it.

Encrypted text continues to use the direct `PUT /files` path with MIME type
`plain/string`, matching the Web application's KV storage behavior. The CLI
may buffer encrypted text because text shares are bounded by the direct upload
path; file encryption remains streaming.

## V2 Encryption Format

The Go implementation reproduces the current TypeScript V2 format exactly:

- Argon2id with parameters recorded in the header. New shares use time cost 3,
  memory cost 65536 KiB, and a 32-byte output.
- A random 32-byte AES-256 data key.
- AES-GCM wrapping of the data key with a password-derived key.
- Separately authenticated encrypted metadata containing the original file
  name and MIME type.
- One MiB plaintext frames, each encrypted with AES-GCM using a unique nonce
  derived from an eight-byte random prefix and the frame index.
- Header- and index-bound additional authenticated data for each frame.
- An authenticated footer containing magic bytes, total frame count, and
  plaintext size.

All salts, keys, nonce prefixes, and IVs come from `crypto/rand`. Decryption
rejects unsupported versions, invalid parameters, truncated frames, reordered
frames, footer mismatches, and authentication failures before publishing the
destination file.

When `--encrypt` has no supplied password, the CLI generates 24 characters
from `A-Z`, `a-z`, and `0-9`. It uses rejection sampling rather than modulo
reduction, giving uniform output and approximately 143 bits of entropy without
shell-sensitive symbols.

## Retrieval Data Flow

1. Resolve the server and six-digit code.
2. Call `GET /files/share/:code` to obtain metadata and a five-minute,
   single-use download token.
3. Download once from `GET /files/:id?token=...`.
4. For plaintext text, return its UTF-8 content in JSON.
5. For plaintext files, stream to a temporary file in the destination
   directory, verify the advertised SHA-256, then atomically rename it.
6. For encrypted content, stream ciphertext to a private temporary file,
   validate and decrypt V2 frames into a second private temporary file, then
   atomically publish the recovered filename. Remove temporary files on
   success.

The encrypted download uses a temporary ciphertext file because the footer is
needed to validate the expected frame layout before plaintext is published.
Temporary files use owner-only permissions and are removed when the command
exits. A failed decryption never leaves a partial plaintext file at the
requested destination. The CLI is non-interactive and does not retry a wrong
password; for an ephemeral share, that failure can make the content
unrecoverable because the lookup already consumed the share code.

An output filename supplied by the user takes precedence over authenticated
metadata. Otherwise the CLI sanitizes the authenticated filename to its base
name and prevents path traversal. Existing files are not overwritten unless a
future explicit overwrite option is added.

## Ephemeral Share Semantics

`--ephemeral` maps to the application's current "read once" behavior. The
first metadata lookup atomically claims the share and expires its share code.
The resulting download token remains valid for five minutes and is consumed by
one download.

This means a lookup, not a successful download or decryption, consumes the
share code. The Skill uses `--ephemeral` only when the user explicitly requests
an ephemeral, burn-after-reading, or one-time share. Upload results include a
warning that interruption after lookup may make the share unrecoverable.

## JSON Output

Successful upload output contains:

```json
{
  "ok": true,
  "operation": "upload",
  "code": "123456",
  "url": "https://drop.example.com/?code=123456",
  "encrypted": true,
  "password": "generated-password-or-null",
  "expiresAt": "2026-08-10T12:00:00Z",
  "ephemeral": false
}
```

`password` is non-null only for an automatically generated password. A
caller-supplied password is never echoed.

Successful text retrieval contains `kind: "text"` and a `text` field.
Successful file retrieval contains `kind: "file"`, the recovered metadata,
and an absolute `path`. All successful responses include `ok`, `operation`,
`code`, and `encrypted`.

Errors also use JSON on stdout so agents can parse them consistently:

```json
{
  "ok": false,
  "error": {
    "code": "WRONG_PASSWORD_OR_CORRUPT_DATA",
    "message": "failed to authenticate encrypted share"
  }
}
```

Human-readable progress and retry messages go to stderr. Exit code 0 means
success, 2 means command usage or local validation failure, 3 means network or
server failure, and 4 means integrity, format, or decryption failure.

## Error Handling and Security

- Parse the application's JSON envelope on both successful and unsuccessful
  HTTP responses and preserve a safe server message in the structured error.
- Apply finite connection, response-header, and overall operation timeouts.
- Retry uncommitted upload parts with bounded backoff. Do not automatically
  retry share-code lookups because an ephemeral lookup claims the share, and
  do not repeat downloads because their token is single-use.
- Never log passwords, Authorization-style values, download tokens, plaintext,
  or decrypted file contents to stderr.
- Redact query strings when reporting download request errors.
- Reject V1 with `UNSUPPORTED_ENCRYPTED_FORMAT` and report the encountered
  version.
- Map AES-GCM authentication failures to one stable error that does not claim
  to distinguish a wrong password from corrupt ciphertext.
- Use constant-time comparisons for hashes and authenticated magic where an
  explicit comparison is required.
- Keep generated passwords in memory only and return them once in the upload
  result.

## Build and Distribution

A reproducible build script compiles with a pinned Go toolchain and records the
CLI version. Release builds use `-trimpath` and fixed build metadata. The four
binaries and a generated SHA-256 manifest are committed under the Skill.

The launcher validates that the selected binary exists and is executable. It
does not download, install, or modify dependencies. Checksums are primarily
for repository and release verification; rehashing a sibling checksum file at
every invocation is not treated as a security boundary because both files are
distributed together.

## Testing

### Go unit tests

- Server URL and share URL parsing, including conflict and insecure-origin
  cases.
- Uniform generated-password alphabet and length.
- V2 header size calculations and strict parsing.
- Frame nonce and additional-data construction.
- Upload session part boundaries and retry behavior.
- Output path sanitization, exclusive creation, cleanup, and atomic publish.
- Stable JSON output and exit-code mapping.

### Cross-language compatibility tests

Committed deterministic fixtures cover:

- TypeScript V2 encryption decrypted by Go.
- Go V2 encryption decrypted by TypeScript.
- Unicode filenames and MIME types.
- Empty and partial final frames.
- Multi-frame files.
- Wrong passwords, modified headers, reordered frames, truncated ciphertext,
  and modified footers.
- Explicit rejection of a minimal V1 fixture by the CLI.

Production encryption continues to use fresh randomness. Deterministic random
inputs exist only behind test helpers.

### HTTP integration tests

Use an in-process mock server to verify direct file upload, text upload,
session upload, encrypted upload, share-code lookup, plaintext download,
encrypted download, server errors, and single-use token behavior.

### Skill validation

- Validate the Skill manifest and frontmatter.
- Test Chinese and English should-trigger prompts.
- Test near-miss prompts for unrelated file copy, other cloud providers, and
  Cloudflare deployment administration.
- Execute the Skill launcher on each CI target and verify `--version` plus a
  mock-server upload/download round trip.

## Acceptance Criteria

- An agent can share file or text content against an arbitrary configured
  Cloudflare Drop instance and receive a parseable share result.
- An agent can retrieve by bare code or share URL and receive text or an
  absolute local file path.
- Automatically generated encrypted shares use a 24-character alphanumeric
  password and round-trip between Go and the Web client.
- Caller-supplied passwords are not echoed in output or diagnostics.
- V1 encrypted content is rejected clearly and is not partially written.
- Files larger than a single upload or encryption frame are processed without
  loading the entire file into memory.
- The Skill runs on the four supported targets without installing runtime
  dependencies.
