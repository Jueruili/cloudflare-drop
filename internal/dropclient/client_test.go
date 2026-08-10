package dropclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestClientDecodesSuccessfulAPIEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"result":true,"message":"ok","data":{"code":"123456"}}`)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.newRequest(context.Background(), http.MethodGet, "/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Code string `json:"code"`
	}
	if err := client.doAPI(request, &result); err != nil {
		t.Fatal(err)
	}
	if result.Code != "123456" {
		t.Fatalf("unexpected result %#v", result)
	}
}

func TestClientTreatsLogicalFailureAsErrorEvenWithHTTP200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"result":false,"message":"分享码无效","data":null}`)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	request, _ := client.newRequest(context.Background(), http.MethodGet, "/test", nil)
	var result map[string]any
	err = client.doAPI(request, &result)
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Message != "分享码无效" {
		t.Fatalf("expected logical API error, got %v", err)
	}
}

func TestClientPreservesBoundedTextHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "invalid token", http.StatusBadRequest)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	request, _ := client.newRequest(context.Background(), http.MethodGet, "/test", nil)
	var result map[string]any
	err = client.doAPI(request, &result)
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Status != 400 || apiError.Message != "invalid token" {
		t.Fatalf("unexpected API error: %#v", apiError)
	}
}

func TestClientRejectsInvalidOrOversizedEnvelope(t *testing.T) {
	for name, body := range map[string]string{
		"invalid":   "not-json",
		"oversized": strings.Repeat("x", maxEnvelopeSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(writer, body)
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			request, _ := client.newRequest(context.Background(), http.MethodGet, "/test", nil)
			var result map[string]any
			if err := client.doAPI(request, &result); err == nil {
				t.Fatal("expected envelope error")
			}
		})
	}
}

func TestClientRedactsQueryFromTransportErrors(t *testing.T) {
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection failed")
	})}
	client, err := New("https://drop.example.com", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := client.newRequest(
		context.Background(),
		http.MethodGet,
		"/files/file-id?token=super-secret",
		nil,
	)
	var result map[string]any
	err = client.doAPI(request, &result)
	if err == nil || strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("query leaked in error: %v", err)
	}
}
