# Cloudflare Drop CLI Reference

The launcher is `scripts/cloudflare-drop` relative to the Skill directory.
Commands write stdout as one JSON object.
Human-readable progress and diagnostics are written to stderr.

## Configuration

- `--server <url>` selects a deployed Cloudflare Drop instance.
- `CLOUDFLARE_DROP_URL` supplies the default instance URL.
- Remote instances require HTTPS. Localhost and loopback addresses may use HTTP.
- `CLOUDFLARE_DROP_PASSWORD` supplies a password without a CLI flag.

## Upload

```bash
scripts/cloudflare-drop upload ./report.pdf --server https://drop.example.com
scripts/cloudflare-drop upload --text "temporary text" --duration 1hour
scripts/cloudflare-drop upload --stdin --encrypt --ephemeral
scripts/cloudflare-drop upload ./report.pdf --encrypt --password-file ./password
```

`upload` accepts exactly one file path, `--text <value>`, or `--stdin`.

Options:

- `--duration <value>` passes values such as `1hour`, `7day`, or `1month`.
- `--ephemeral` creates a one-time share consumed by its first lookup.
- `--encrypt` creates a V2 encrypted share.
- `--password <value>` supplies a direct password; avoid it for shell-sensitive values.
- `--password-file <path>` reads the password and removes one trailing newline.

Successful upload JSON includes `code`, `url`, `encrypted`, `ephemeral`,
`expiresAt`, and `password`. `password` is non-null only when the CLI generated
it; a supplied password is never echoed.

## Get

```bash
scripts/cloudflare-drop get 123456 --server https://drop.example.com
scripts/cloudflare-drop get "https://drop.example.com/?code=123456"
scripts/cloudflare-drop get 123456 --password-file ./password --output ./downloads/
```

Options:

- `--output <path>` selects a file or directory. Existing files are not overwritten.
- `--password <value>` or `--password-file <path>` decrypts a V2 share.

Text results have `kind: "text"` and a `text` field. File results have
`kind: "file"` and an absolute `path` field.

## Exit codes

- `0`: success
- `2`: usage or local validation error
- `3`: network or Cloudflare Drop API error
- `4`: integrity, unsupported format, or authentication/decryption error

Error JSON has this shape:

```json
{
  "ok": false,
  "error": {
    "code": "WRONG_PASSWORD_OR_CORRUPT_DATA",
    "message": "failed to authenticate encrypted share"
  }
}
```

The CLI intentionally does not distinguish a wrong password from modified
ciphertext. V1 encrypted shares return `UNSUPPORTED_ENCRYPTED_FORMAT`.
