package dropclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"time"
)

const maxUploadPartSize = 64 * 1024 * 1024

type UploadMetadata struct {
	Filename      string `json:"filename"`
	Type          string `json:"type"`
	Size          int64  `json:"size"`
	PlaintextSize int64  `json:"plaintextSize,omitempty"`
	Hash          string `json:"hash"`
	Duration      string `json:"duration"`
	Ephemeral     bool   `json:"isEphemeral"`
	Encrypted     bool   `json:"isEncrypted"`
}

type ShareResult struct {
	Hash      string          `json:"hash"`
	Code      string          `json:"code"`
	DueDate   json.RawMessage `json:"due_date"`
	Ephemeral bool            `json:"is_ephemeral"`
	Encrypted bool            `json:"is_encrypted"`
}

type uploadSession struct {
	SessionID     string `json:"sessionId"`
	PartSize      int64  `json:"partSize"`
	UploadedParts []struct {
		PartNumber int `json:"partNumber"`
	} `json:"uploadedParts"`
}

type UploadBodyError struct {
	Err error
}

func (err *UploadBodyError) Error() string { return "read upload body: " + err.Err.Error() }
func (err *UploadBodyError) Unwrap() error { return err.Err }

func (client *Client) UploadDirect(
	ctx context.Context,
	metadata UploadMetadata,
	body io.Reader,
) (ShareResult, error) {
	if metadata.Size <= 0 {
		return ShareResult{}, fmt.Errorf("upload size must be positive")
	}
	reader, writer := io.Pipe()
	multipartWriter := multipart.NewWriter(writer)
	request, err := client.newRequest(ctx, http.MethodPut, "/files", reader)
	if err != nil {
		return ShareResult{}, err
	}
	request.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	go func() {
		writeErr := writeMultipartUpload(multipartWriter, metadata, body)
		if closeErr := multipartWriter.Close(); writeErr == nil {
			writeErr = closeErr
		}
		_ = writer.CloseWithError(writeErr)
	}()
	defer reader.Close()

	var result ShareResult
	if err := client.doAPI(request, &result); err != nil {
		return ShareResult{}, err
	}
	return result, nil
}

func writeMultipartUpload(
	writer *multipart.Writer,
	metadata UploadMetadata,
	body io.Reader,
) error {
	contentType := metadata.Type
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	filename := metadata.Filename
	if filename == "" {
		filename = "download"
	}
	header := make(textproto.MIMEHeader)
	header.Set(
		"Content-Disposition",
		mime.FormatMediaType("form-data", map[string]string{
			"name":     "file",
			"filename": filename,
		}),
	)
	header.Set("Content-Type", contentType)
	part, err := writer.CreatePart(header)
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, body); err != nil {
		return err
	}
	fields := map[string]string{
		"duration":      jsonString(metadata.Duration),
		"isEphemeral":   strconv.FormatBool(metadata.Ephemeral),
		"isEncrypted":   strconv.FormatBool(metadata.Encrypted),
		"plaintextType": metadata.Type,
		"hash":          jsonString(metadata.Hash),
	}
	if metadata.PlaintextSize > 0 {
		fields["plaintextSize"] = strconv.FormatInt(metadata.PlaintextSize, 10)
	}
	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			return err
		}
	}
	return nil
}

func jsonString(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func (client *Client) UploadSession(
	ctx context.Context,
	metadata UploadMetadata,
	body io.Reader,
) (ShareResult, error) {
	if metadata.Size <= 0 {
		return ShareResult{}, fmt.Errorf("upload size must be positive")
	}
	session, err := client.createUploadSession(ctx, metadata)
	if err != nil {
		return ShareResult{}, err
	}
	if session.SessionID == "" || session.PartSize <= 0 ||
		session.PartSize > maxUploadPartSize {
		return ShareResult{}, &APIError{
			Code:    "INVALID_RESPONSE",
			Message: "upload session returned an invalid part size",
		}
	}
	uploaded := make(map[int]bool, len(session.UploadedParts))
	for _, part := range session.UploadedParts {
		uploaded[part.PartNumber] = true
	}

	remaining := metadata.Size
	partNumber := 1
	buffer := make([]byte, int(session.PartSize))
	for remaining > 0 {
		expected := session.PartSize
		if remaining < expected {
			expected = remaining
		}
		part := buffer[:int(expected)]
		if _, err := io.ReadFull(body, part); err != nil {
			return ShareResult{}, &UploadBodyError{Err: err}
		}
		if !uploaded[partNumber] {
			if err := client.uploadPart(ctx, session.SessionID, partNumber, part); err != nil {
				return ShareResult{}, err
			}
		}
		remaining -= expected
		partNumber += 1
	}
	probe := make([]byte, 1)
	if count, err := io.ReadFull(body, probe); count > 0 {
		return ShareResult{}, fmt.Errorf("upload body exceeds declared size")
	} else if err != nil && err != io.EOF {
		return ShareResult{}, &UploadBodyError{Err: err}
	}
	return client.completeUploadSession(ctx, session.SessionID)
}

func (client *Client) createUploadSession(
	ctx context.Context,
	metadata UploadMetadata,
) (uploadSession, error) {
	payload, err := json.Marshal(metadata)
	if err != nil {
		return uploadSession{}, err
	}
	request, err := client.newRequest(
		ctx,
		http.MethodPost,
		"/files/uploads",
		bytes.NewReader(payload),
	)
	if err != nil {
		return uploadSession{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	var session uploadSession
	if err := client.doAPI(request, &session); err != nil {
		return uploadSession{}, err
	}
	return session, nil
}

func (client *Client) uploadPart(
	ctx context.Context,
	sessionID string,
	partNumber int,
	part []byte,
) error {
	path := fmt.Sprintf(
		"/files/uploads/%s/parts/%d",
		sessionID,
		partNumber,
	)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		request, err := client.newRequest(
			ctx,
			http.MethodPut,
			path,
			bytes.NewReader(part),
		)
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/octet-stream")
		lastErr = client.doAPI(request, nil)
		if lastErr == nil {
			return nil
		}
		if !isRetryablePartError(lastErr) || attempt == 2 {
			return lastErr
		}
		delay := 100 * time.Millisecond
		if attempt == 1 {
			delay = 250 * time.Millisecond
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func isRetryablePartError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var apiError *APIError
	if !errors.As(err, &apiError) {
		return true
	}
	return apiError.Status == http.StatusRequestTimeout ||
		apiError.Status == http.StatusTooManyRequests ||
		apiError.Status >= 500
}

func (client *Client) completeUploadSession(
	ctx context.Context,
	sessionID string,
) (ShareResult, error) {
	request, err := client.newRequest(
		ctx,
		http.MethodPost,
		fmt.Sprintf("/files/uploads/%s/complete", sessionID),
		nil,
	)
	if err != nil {
		return ShareResult{}, err
	}
	var result ShareResult
	if err := client.doAPI(request, &result); err != nil {
		return ShareResult{}, err
	}
	return result, nil
}
