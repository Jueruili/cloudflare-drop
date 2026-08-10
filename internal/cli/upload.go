package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oustn/cloudflare-drop/internal/cryptoformat"
	"github.com/oustn/cloudflare-drop/internal/dropclient"
)

const (
	directUploadLimit = 5 * 1024 * 1024
	maxTextSize       = 10 * 1024 * 1024
)

func runUpload(
	ctx context.Context,
	args []string,
	stdin io.Reader,
) (UploadResponse, error) {
	options, err := parseUploadArgs(args, os.Getenv)
	if err != nil {
		return UploadResponse{}, usageError(err)
	}
	server, err := dropclient.ResolveServer(options.server)
	if err != nil {
		return UploadResponse{}, usageError(err)
	}
	client, err := dropclient.New(server.String(), nil)
	if err != nil {
		return UploadResponse{}, usageError(err)
	}
	password := options.password
	generated := false
	if options.encrypt && password == "" {
		password, err = cryptoformat.GeneratePassword(rand.Reader)
		if err != nil {
			return UploadResponse{}, localError("PASSWORD_GENERATION_FAILED", err)
		}
		generated = true
	}

	var result dropclient.ShareResult
	if options.path != "" {
		result, err = uploadFile(ctx, client, options, password)
	} else {
		result, err = uploadText(ctx, client, options, password, stdin)
	}
	if err != nil {
		return UploadResponse{}, err
	}
	expiresAt, err := normalizeDate(result.DueDate)
	if err != nil {
		return UploadResponse{}, networkError(err)
	}
	var generatedPassword *string
	if generated {
		generatedPassword = &password
	}
	return UploadResponse{
		OK:        true,
		Operation: "upload",
		Code:      result.Code,
		URL:       dropclient.ShareURL(server, result.Code),
		Encrypted: options.encrypt,
		Ephemeral: options.ephemeral,
		Password:  generatedPassword,
		ExpiresAt: expiresAt,
	}, nil
}

func uploadText(
	ctx context.Context,
	client *dropclient.Client,
	options uploadArgs,
	password string,
	stdin io.Reader,
) (dropclient.ShareResult, error) {
	var content []byte
	if options.textSet {
		content = []byte(options.text)
	} else {
		var err error
		content, err = readBounded(stdin, maxTextSize)
		if err != nil {
			return dropclient.ShareResult{}, localError("LOCAL_VALIDATION_FAILED", err)
		}
	}
	if len(content) == 0 {
		return dropclient.ShareResult{}, localError(
			"LOCAL_VALIDATION_FAILED",
			fmt.Errorf("share content is empty"),
		)
	}
	if !utf8.Valid(content) {
		return dropclient.ShareResult{}, localError(
			"LOCAL_VALIDATION_FAILED",
			fmt.Errorf("text share must be valid UTF-8"),
		)
	}
	metadata := dropclient.UploadMetadata{
		Filename:  "text",
		Type:      "plain/string",
		Size:      int64(len(content)),
		Duration:  options.duration,
		Ephemeral: options.ephemeral,
	}
	body := content
	if options.encrypt {
		var encrypted bytes.Buffer
		if _, err := cryptoformat.Encrypt(
			&encrypted,
			bytes.NewReader(content),
			int64(len(content)),
			password,
			cryptoformat.Metadata{Type: "plain/string"},
		); err != nil {
			return dropclient.ShareResult{}, localError("LOCAL_ENCRYPTION_FAILED", err)
		}
		body = encrypted.Bytes()
		metadata.Filename = "encrypted-file"
		metadata.Size = int64(len(body))
		metadata.PlaintextSize = int64(len(content))
		metadata.Encrypted = true
	}
	result, err := client.UploadDirect(ctx, metadata, bytes.NewReader(body))
	if err != nil {
		return dropclient.ShareResult{}, networkError(err)
	}
	return result, nil
}

func uploadFile(
	ctx context.Context,
	client *dropclient.Client,
	options uploadArgs,
	password string,
) (dropclient.ShareResult, error) {
	file, err := os.Open(options.path)
	if err != nil {
		return dropclient.ShareResult{}, localError("LOCAL_IO_ERROR", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return dropclient.ShareResult{}, localError("LOCAL_IO_ERROR", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return dropclient.ShareResult{}, localError(
			"LOCAL_VALIDATION_FAILED",
			fmt.Errorf("upload source must be a non-empty regular file"),
		)
	}
	filename := filepath.Base(options.path)
	contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(filename)))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	metadata := dropclient.UploadMetadata{
		Filename:  filename,
		Type:      contentType,
		Size:      info.Size(),
		Duration:  options.duration,
		Ephemeral: options.ephemeral,
	}
	if options.encrypt {
		encryptedSize, err := cryptoformat.EncryptedSize(
			info.Size(),
			cryptoformat.Metadata{Filename: filename, Type: contentType},
		)
		if err != nil {
			return dropclient.ShareResult{}, localError("LOCAL_ENCRYPTION_FAILED", err)
		}
		metadata.Filename = "encrypted-file"
		metadata.Size = encryptedSize
		metadata.PlaintextSize = info.Size()
		metadata.Encrypted = true
		reader, writer := io.Pipe()
		encryptionDone := make(chan error, 1)
		go func() {
			_, encryptErr := cryptoformat.Encrypt(
				writer,
				file,
				info.Size(),
				password,
				cryptoformat.Metadata{Filename: filename, Type: contentType},
			)
			_ = writer.CloseWithError(encryptErr)
			encryptionDone <- encryptErr
		}()
		result, uploadErr := client.UploadSession(ctx, metadata, reader)
		_ = reader.CloseWithError(uploadErr)
		encryptErr := <-encryptionDone
		var bodyErr *dropclient.UploadBodyError
		if encryptErr != nil && (uploadErr == nil || errors.As(uploadErr, &bodyErr)) {
			return dropclient.ShareResult{}, localError("LOCAL_ENCRYPTION_FAILED", encryptErr)
		}
		if uploadErr != nil {
			return dropclient.ShareResult{}, networkError(uploadErr)
		}
		if encryptErr != nil {
			return dropclient.ShareResult{}, localError("LOCAL_ENCRYPTION_FAILED", encryptErr)
		}
		return result, nil
	}
	if info.Size() <= directUploadLimit {
		result, err := client.UploadDirect(ctx, metadata, file)
		if err != nil {
			return dropclient.ShareResult{}, networkError(err)
		}
		return result, nil
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return dropclient.ShareResult{}, localError("LOCAL_IO_ERROR", err)
	}
	metadata.Hash = hex.EncodeToString(hash.Sum(nil))
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return dropclient.ShareResult{}, localError("LOCAL_IO_ERROR", err)
	}
	result, err := client.UploadSession(ctx, metadata, file)
	if err != nil {
		var bodyErr *dropclient.UploadBodyError
		if errors.As(err, &bodyErr) {
			return dropclient.ShareResult{}, localError("LOCAL_IO_ERROR", err)
		}
		return dropclient.ShareResult{}, networkError(err)
	}
	return result, nil
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	content, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("text share exceeds %d bytes", limit)
	}
	return content, nil
}

func normalizeDate(raw json.RawMessage) (*string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err != nil {
			return nil, fmt.Errorf("invalid due date: %w", err)
		}
		normalized := parsed.UTC().Format(time.RFC3339)
		return &normalized, nil
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return nil, fmt.Errorf("invalid due date")
	}
	value, err := number.Int64()
	if err != nil {
		return nil, fmt.Errorf("invalid due date")
	}
	if value > 1_000_000_000_000 {
		value /= 1000
	}
	normalized := time.Unix(value, 0).UTC().Format(time.RFC3339)
	return &normalized, nil
}
