package cli

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/oustn/cloudflare-drop/internal/cryptoformat"
	"github.com/oustn/cloudflare-drop/internal/dropclient"
)

func runGet(ctx context.Context, args []string) (GetResponse, error) {
	options, err := parseGetArgs(args, os.Getenv)
	if err != nil {
		return GetResponse{}, usageError(err)
	}
	target, err := dropclient.ResolveTarget(options.target, options.server, "")
	if err != nil {
		return GetResponse{}, usageError(err)
	}
	client, err := dropclient.New(target.Server.String(), nil)
	if err != nil {
		return GetResponse{}, usageError(err)
	}
	share, err := client.Lookup(ctx, target.Code)
	if err != nil {
		return GetResponse{}, networkError(err)
	}
	if share.Encrypted && options.password == "" {
		return GetResponse{}, usageError(fmt.Errorf(
			"encrypted share requires --password or --password-file; the share code may already be consumed",
		))
	}
	body, _, err := client.Download(ctx, share)
	if err != nil {
		return GetResponse{}, networkError(err)
	}
	defer body.Close()

	if share.Encrypted {
		return getEncrypted(ctx, share, options, body)
	}
	if share.Type == "plain/string" {
		content, err := readBounded(&downloadReader{reader: body}, maxTextSize)
		if err != nil {
			var readErr *downloadReadError
			if errors.As(err, &readErr) {
				return GetResponse{}, networkError(err)
			}
			return GetResponse{}, integrityError("INVALID_TEXT_SHARE", err)
		}
		if !utf8.Valid(content) {
			return GetResponse{}, integrityError(
				"INVALID_TEXT_SHARE",
				fmt.Errorf("text share is not valid UTF-8"),
			)
		}
		if err := verifyHash(content, share.Hash); err != nil {
			return GetResponse{}, integrityError("INTEGRITY_CHECK_FAILED", err)
		}
		return GetResponse{
			OK: true, Operation: "get", Code: share.Code,
			Encrypted: false, Kind: "text", Text: string(content),
			Type: share.Type, Size: int64(len(content)),
		}, nil
	}

	path, err := publishFile(options.output, share.Filename, func(file *os.File) error {
		hash := sha256.New()
		written, copyErr := io.Copy(
			&localWriter{writer: io.MultiWriter(file, hash)},
			&downloadReader{reader: body},
		)
		if copyErr != nil {
			return copyErr
		}
		if share.Size >= 0 && written != share.Size {
			return &downloadIntegrityError{err: fmt.Errorf("download size mismatch")}
		}
		if err := verifyDigest(hash.Sum(nil), share.Hash); err != nil {
			return &downloadIntegrityError{err: err}
		}
		return nil
	})
	if err != nil {
		var readErr *downloadReadError
		var integrityErr *downloadIntegrityError
		switch {
		case errors.As(err, &readErr):
			return GetResponse{}, networkError(err)
		case errors.As(err, &integrityErr):
			return GetResponse{}, integrityError("INTEGRITY_CHECK_FAILED", err)
		default:
			return GetResponse{}, localError("LOCAL_IO_ERROR", err)
		}
	}
	return GetResponse{
		OK: true, Operation: "get", Code: share.Code,
		Encrypted: false, Kind: "file", Path: path,
		Filename: filepath.Base(path), Type: share.Type, Size: share.Size,
	}, nil
}

func getEncrypted(
	_ context.Context,
	share dropclient.Share,
	options getArgs,
	body io.Reader,
) (GetResponse, error) {
	ciphertext, err := os.CreateTemp("", "cloudflare-drop-ciphertext-*")
	if err != nil {
		return GetResponse{}, localError("LOCAL_IO_ERROR", err)
	}
	ciphertextPath := ciphertext.Name()
	defer os.Remove(ciphertextPath)
	if err := ciphertext.Chmod(0o600); err != nil {
		_ = ciphertext.Close()
		return GetResponse{}, localError("LOCAL_IO_ERROR", err)
	}
	if _, err := io.Copy(
		&localWriter{writer: ciphertext},
		&downloadReader{reader: body},
	); err != nil {
		_ = ciphertext.Close()
		var readErr *downloadReadError
		if errors.As(err, &readErr) {
			return GetResponse{}, networkError(err)
		}
		return GetResponse{}, localError("LOCAL_IO_ERROR", err)
	}
	if _, err := ciphertext.Seek(0, io.SeekStart); err != nil {
		_ = ciphertext.Close()
		return GetResponse{}, localError("LOCAL_IO_ERROR", err)
	}
	plaintext, err := os.CreateTemp("", "cloudflare-drop-plaintext-*")
	if err != nil {
		_ = ciphertext.Close()
		return GetResponse{}, localError("LOCAL_IO_ERROR", err)
	}
	plaintextPath := plaintext.Name()
	defer os.Remove(plaintextPath)
	if err := plaintext.Chmod(0o600); err != nil {
		_ = ciphertext.Close()
		_ = plaintext.Close()
		return GetResponse{}, localError("LOCAL_IO_ERROR", err)
	}
	metadata, written, decryptErr := cryptoformat.Decrypt(
		plaintext,
		ciphertext,
		options.password,
	)
	_ = ciphertext.Close()
	if decryptErr != nil {
		_ = plaintext.Close()
		return GetResponse{}, cryptoError(decryptErr)
	}
	if share.Size >= 0 && written != share.Size {
		_ = plaintext.Close()
		return GetResponse{}, integrityError(
			"INTEGRITY_CHECK_FAILED",
			fmt.Errorf("decrypted size mismatch"),
		)
	}
	if _, err := plaintext.Seek(0, io.SeekStart); err != nil {
		_ = plaintext.Close()
		return GetResponse{}, localError("LOCAL_IO_ERROR", err)
	}
	contentType := metadata.Type
	if contentType == "" {
		contentType = share.Type
	}
	if contentType == "plain/string" {
		content, err := readBounded(plaintext, maxTextSize)
		_ = plaintext.Close()
		if err != nil || !utf8.Valid(content) {
			return GetResponse{}, integrityError(
				"INVALID_TEXT_SHARE",
				fmt.Errorf("decrypted text is invalid or too large"),
			)
		}
		return GetResponse{
			OK: true, Operation: "get", Code: share.Code,
			Encrypted: true, Kind: "text", Text: string(content),
			Type: contentType, Size: int64(len(content)),
		}, nil
	}
	name := metadata.Filename
	if name == "" {
		name = share.Filename
	}
	path, err := publishFile(options.output, name, func(file *os.File) error {
		if _, err := plaintext.Seek(0, io.SeekStart); err != nil {
			return err
		}
		_, err := io.Copy(file, plaintext)
		return err
	})
	_ = plaintext.Close()
	if err != nil {
		return GetResponse{}, localError("LOCAL_IO_ERROR", err)
	}
	return GetResponse{
		OK: true, Operation: "get", Code: share.Code,
		Encrypted: true, Kind: "file", Path: path,
		Filename: filepath.Base(path), Type: contentType, Size: written,
	}, nil
}

func verifyHash(content []byte, expected string) error {
	digest := sha256.Sum256(content)
	return verifyDigest(digest[:], expected)
}

func verifyDigest(actual []byte, expectedHex string) error {
	expected, err := hex.DecodeString(expectedHex)
	if err != nil || len(expected) != sha256.Size ||
		subtle.ConstantTimeCompare(actual, expected) != 1 {
		return fmt.Errorf("SHA-256 verification failed")
	}
	return nil
}

type downloadReadError struct{ err error }

func (err *downloadReadError) Error() string { return err.err.Error() }
func (err *downloadReadError) Unwrap() error { return err.err }

type downloadReader struct{ reader io.Reader }

func (reader *downloadReader) Read(data []byte) (int, error) {
	count, err := reader.reader.Read(data)
	if err != nil && err != io.EOF {
		return count, &downloadReadError{err: err}
	}
	return count, err
}

type localWriteError struct{ err error }

func (err *localWriteError) Error() string { return err.err.Error() }
func (err *localWriteError) Unwrap() error { return err.err }

type localWriter struct{ writer io.Writer }

func (writer *localWriter) Write(data []byte) (int, error) {
	count, err := writer.writer.Write(data)
	if err != nil {
		return count, &localWriteError{err: err}
	}
	if count != len(data) {
		return count, &localWriteError{err: io.ErrShortWrite}
	}
	return count, nil
}

type downloadIntegrityError struct{ err error }

func (err *downloadIntegrityError) Error() string { return err.err.Error() }
func (err *downloadIntegrityError) Unwrap() error { return err.err }

func usageError(err error) *commandError {
	return &commandError{exitCode: ExitUsage, code: "USAGE", message: err.Error()}
}

func localError(code string, err error) *commandError {
	return &commandError{exitCode: ExitUsage, code: code, message: err.Error()}
}

func networkError(err error) *commandError {
	return &commandError{
		exitCode: ExitNetwork,
		code:     "API_REQUEST_FAILED",
		message:  err.Error(),
	}
}

func integrityError(code string, err error) *commandError {
	return &commandError{exitCode: ExitIntegrity, code: code, message: err.Error()}
}

func cryptoError(err error) *commandError {
	switch {
	case errors.Is(err, cryptoformat.ErrUnsupportedVersion):
		return integrityError("UNSUPPORTED_ENCRYPTED_FORMAT", err)
	case errors.Is(err, cryptoformat.ErrAuthentication):
		return integrityError("WRONG_PASSWORD_OR_CORRUPT_DATA", err)
	default:
		return integrityError("INVALID_ENCRYPTED_FORMAT", err)
	}
}
