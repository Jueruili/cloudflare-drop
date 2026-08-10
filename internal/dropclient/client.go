package dropclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxEnvelopeSize = 1024 * 1024

type Client struct {
	base *url.URL
	http *http.Client
}

type APIError struct {
	Code    string
	Message string
	Status  int
}

func (err *APIError) Error() string {
	if err.Status > 0 {
		return fmt.Sprintf("%s (%d): %s", err.Code, err.Status, err.Message)
	}
	return fmt.Sprintf("%s: %s", err.Code, err.Message)
}

type apiEnvelope struct {
	Result  bool            `json:"result"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func New(server string, client *http.Client) (*Client, error) {
	base, err := ResolveServer(server)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = &http.Client{Transport: defaultTransport()}
	}
	return &Client{base: base, http: client}, nil
}

func defaultTransport() *http.Transport {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		IdleConnTimeout:       30 * time.Second,
	}
}

func (client *Client) newRequest(
	ctx context.Context,
	method string,
	path string,
	body io.Reader,
) (*http.Request, error) {
	reference, err := url.Parse(path)
	if err != nil || reference.IsAbs() || !strings.HasPrefix(reference.Path, "/") {
		return nil, fmt.Errorf("invalid API path")
	}
	target := client.base.ResolveReference(reference)
	return http.NewRequestWithContext(ctx, method, target.String(), body)
}

func (client *Client) doAPI(request *http.Request, output any) error {
	response, err := client.http.Do(request)
	if err != nil {
		return redactedTransportError(request, err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxEnvelopeSize+1))
	if err != nil {
		return fmt.Errorf("read API response: %w", err)
	}
	if len(body) > maxEnvelopeSize {
		return &APIError{
			Code:    "INVALID_RESPONSE",
			Message: "API response exceeds 1 MiB",
			Status:  response.StatusCode,
		}
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message := strings.TrimSpace(string(body))
		var envelope apiEnvelope
		if json.Unmarshal(body, &envelope) == nil && envelope.Message != "" {
			message = envelope.Message
		}
		if message == "" {
			message = response.Status
		}
		return &APIError{
			Code:    "HTTP_ERROR",
			Message: message,
			Status:  response.StatusCode,
		}
	}

	var envelope apiEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return &APIError{
			Code:    "INVALID_RESPONSE",
			Message: "API returned invalid JSON",
			Status:  response.StatusCode,
		}
	}
	if !envelope.Result {
		message := envelope.Message
		if message == "" {
			message = "Cloudflare Drop API request failed"
		}
		return &APIError{
			Code:    "API_ERROR",
			Message: message,
			Status:  response.StatusCode,
		}
	}
	if output == nil {
		return nil
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return &APIError{
			Code:    "INVALID_RESPONSE",
			Message: "API response data is missing",
			Status:  response.StatusCode,
		}
	}
	if err := json.Unmarshal(envelope.Data, output); err != nil {
		return &APIError{
			Code:    "INVALID_RESPONSE",
			Message: "API response data is invalid",
			Status:  response.StatusCode,
		}
	}
	return nil
}

func redactedTransportError(request *http.Request, err error) error {
	cause := err
	var urlError *url.Error
	if errors.As(err, &urlError) {
		cause = urlError.Err
	}
	redacted := *request.URL
	redacted.RawQuery = ""
	redacted.Fragment = ""
	causeMessage := cause.Error()
	if request.URL.RawQuery != "" {
		causeMessage = strings.ReplaceAll(causeMessage, request.URL.RawQuery, "[REDACTED]")
	}
	for _, values := range request.URL.Query() {
		for _, value := range values {
			if value == "" {
				continue
			}
			causeMessage = strings.ReplaceAll(causeMessage, url.QueryEscape(value), "[REDACTED]")
			causeMessage = strings.ReplaceAll(causeMessage, value, "[REDACTED]")
		}
	}
	return fmt.Errorf(
		"request %s %s failed: %s",
		request.Method,
		redacted.String(),
		causeMessage,
	)
}
