package dropclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLookupDecodesShareMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/files/share/123456" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		writeAPIResponse(t, writer, map[string]any{
			"id":           "file-id",
			"code":         "123456",
			"filename":     "report.txt",
			"hash":         "abcd",
			"type":         "text/plain",
			"size":         7,
			"is_ephemeral": false,
			"is_encrypted": true,
			"token":        "download-token",
			"due_date":     nil,
		})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	share, err := client.Lookup(context.Background(), "123456")
	if err != nil {
		t.Fatal(err)
	}
	if share.ID != "file-id" || share.Token != "download-token" || !share.Encrypted {
		t.Fatalf("unexpected share %#v", share)
	}
}

func TestLookupDoesNotRetryTransportFailure(t *testing.T) {
	attempts := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		attempts += 1
		return nil, errors.New("connection lost")
	})}
	client, err := New("https://drop.example.com", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Lookup(context.Background(), "123456"); err == nil {
		t.Fatal("expected lookup failure")
	}
	if attempts != 1 {
		t.Fatalf("expected one lookup, got %d", attempts)
	}
}

func TestDownloadReturnsRawBodyOnce(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempts += 1
		if request.URL.Path != "/files/file-id" || request.URL.Query().Get("token") != "download-token" {
			t.Fatalf("unexpected download URL %s", request.URL)
		}
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(writer, "content")
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	body, headers, err := client.Download(context.Background(), Share{
		ID:    "file-id",
		Token: "download-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	content, err := io.ReadAll(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "content" || headers.Get("Content-Type") != "text/plain" {
		t.Fatalf("unexpected download %q %#v", content, headers)
	}
	if attempts != 1 {
		t.Fatalf("expected one download, got %d", attempts)
	}
}

func TestDownloadRedactsTokenAndDoesNotRetryTransportFailure(t *testing.T) {
	attempts := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		attempts += 1
		return nil, fmt.Errorf("connection lost for %s", request.URL.String())
	})}
	client, err := New("https://drop.example.com", httpClient)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.Download(context.Background(), Share{
		ID:    "file-id",
		Token: "super-secret-token",
	})
	if err == nil || strings.Contains(err.Error(), "super-secret-token") {
		t.Fatalf("unexpected download error %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected one download, got %d", attempts)
	}
}

func TestDownloadRedactsTokenFromHTTPErrorBody(t *testing.T) {
	const token = "super-secret-token"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Error(writer, "failed request "+request.URL.String(), http.StatusBadGateway)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.Download(context.Background(), Share{
		ID:    "file-id",
		Token: token,
	})
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("download token leaked in HTTP error %v", err)
	}
}
