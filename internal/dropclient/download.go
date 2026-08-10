package dropclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type Share struct {
	ID        string          `json:"id"`
	Code      string          `json:"code"`
	Filename  string          `json:"filename"`
	Hash      string          `json:"hash"`
	Type      string          `json:"type"`
	Token     string          `json:"token"`
	Size      int64           `json:"size"`
	Ephemeral bool            `json:"is_ephemeral"`
	Encrypted bool            `json:"is_encrypted"`
	DueDate   json.RawMessage `json:"due_date"`
}

func (client *Client) Lookup(ctx context.Context, code string) (Share, error) {
	if err := validateCode(code); err != nil {
		return Share{}, err
	}
	request, err := client.newRequest(
		ctx,
		http.MethodGet,
		"/files/share/"+code,
		nil,
	)
	if err != nil {
		return Share{}, err
	}
	var share Share
	if err := client.doAPI(request, &share); err != nil {
		return Share{}, err
	}
	if share.ID == "" || share.Token == "" {
		return Share{}, &APIError{
			Code:    "INVALID_RESPONSE",
			Message: "share response is missing id or download token",
		}
	}
	return share, nil
}

func (client *Client) Download(
	ctx context.Context,
	share Share,
) (io.ReadCloser, http.Header, error) {
	if share.ID == "" || share.Token == "" {
		return nil, nil, fmt.Errorf("share id and download token are required")
	}
	query := url.Values{}
	query.Set("token", share.Token)
	path := fmt.Sprintf(
		"/files/%s?%s",
		url.PathEscape(share.ID),
		query.Encode(),
	)
	request, err := client.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, nil, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, nil, redactedTransportError(request, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		defer response.Body.Close()
		body, readErr := io.ReadAll(io.LimitReader(response.Body, maxEnvelopeSize+1))
		if readErr != nil {
			return nil, nil, fmt.Errorf("read download error: %w", readErr)
		}
		message := strings.TrimSpace(string(body))
		if len(body) > maxEnvelopeSize {
			message = "download error response exceeds 1 MiB"
		}
		if message == "" {
			message = response.Status
		}
		message = strings.ReplaceAll(message, url.QueryEscape(share.Token), "[REDACTED]")
		message = strings.ReplaceAll(message, share.Token, "[REDACTED]")
		return nil, nil, &APIError{
			Code:    "HTTP_ERROR",
			Message: message,
			Status:  response.StatusCode,
		}
	}
	return response.Body, response.Header.Clone(), nil
}
