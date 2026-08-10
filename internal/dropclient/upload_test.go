package dropclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func writeAPIResponse(t *testing.T, writer http.ResponseWriter, data any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(map[string]any{
		"result":  true,
		"message": "ok",
		"data":    data,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestUploadDirectStreamsMultipartMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/files" {
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
		if err := request.ParseMultipartForm(1 << 20); err != nil {
			t.Fatal(err)
		}
		file, header, err := request.FormFile("file")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		content, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != "cipher" || header.Filename != "encrypted-file" {
			t.Fatalf("unexpected file %q %q", header.Filename, content)
		}
		if header.Header.Get("Content-Type") != "plain/string" {
			t.Fatalf("unexpected type %q", header.Header.Get("Content-Type"))
		}
		wantFields := map[string]string{
			"duration":      `"1hour"`,
			"isEphemeral":   "true",
			"isEncrypted":   "true",
			"plaintextSize": "5",
			"plaintextType": "plain/string",
			"hash":          `""`,
		}
		for name, want := range wantFields {
			if got := request.FormValue(name); got != want {
				t.Fatalf("field %s: want %q, got %q", name, want, got)
			}
		}
		writeAPIResponse(t, writer, map[string]any{
			"hash":         "",
			"code":         "123456",
			"due_date":     nil,
			"is_ephemeral": true,
			"is_encrypted": true,
		})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.UploadDirect(context.Background(), UploadMetadata{
		Filename:      "encrypted-file",
		Type:          "plain/string",
		Size:          6,
		PlaintextSize: 5,
		Duration:      "1hour",
		Ephemeral:     true,
		Encrypted:     true,
	}, bytes.NewBufferString("cipher"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != "123456" || !result.Encrypted || !result.Ephemeral {
		t.Fatalf("unexpected result %#v", result)
	}
}

func TestUploadSessionUsesServerPartSizeAndRetriesTransientPart(t *testing.T) {
	partAttempts := map[int]int{}
	parts := map[int][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/files/uploads":
			var metadata UploadMetadata
			if err := json.NewDecoder(request.Body).Decode(&metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.Size != 6 || metadata.PlaintextSize != 5 || !metadata.Encrypted {
				t.Fatalf("unexpected session metadata %#v", metadata)
			}
			writeAPIResponse(t, writer, map[string]any{
				"sessionId":     "session-1",
				"partSize":      2,
				"uploadedParts": []any{},
			})
		case request.Method == http.MethodPut:
			var partNumber int
			if _, err := fmt.Sscanf(request.URL.Path, "/files/uploads/session-1/parts/%d", &partNumber); err != nil {
				t.Fatal(err)
			}
			partAttempts[partNumber] += 1
			body, err := io.ReadAll(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			if partNumber == 2 && partAttempts[partNumber] == 1 {
				http.Error(writer, "retry", http.StatusServiceUnavailable)
				return
			}
			parts[partNumber] = body
			writeAPIResponse(t, writer, map[string]any{"partNumber": partNumber})
		case request.Method == http.MethodPost && request.URL.Path == "/files/uploads/session-1/complete":
			writeAPIResponse(t, writer, map[string]any{
				"hash":         "",
				"code":         "654321",
				"due_date":     "2026-08-11T00:00:00.000Z",
				"is_ephemeral": false,
				"is_encrypted": true,
			})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.UploadSession(context.Background(), UploadMetadata{
		Filename:      "encrypted-file",
		Type:          "application/octet-stream",
		Size:          6,
		PlaintextSize: 5,
		Encrypted:     true,
	}, bytes.NewBufferString("abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != "654321" {
		t.Fatalf("unexpected result %#v", result)
	}
	if partAttempts[2] != 2 {
		t.Fatalf("expected part 2 twice, got %d", partAttempts[2])
	}
	wantParts := map[int][]byte{1: []byte("ab"), 2: []byte("cd"), 3: []byte("ef")}
	if !reflect.DeepEqual(parts, wantParts) {
		t.Fatalf("parts mismatch: %#v", parts)
	}
}

func TestUploadSessionDoesNotRetryPermanentPartFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/files/uploads" {
			writeAPIResponse(t, writer, map[string]any{
				"sessionId":     "session-1",
				"partSize":      2,
				"uploadedParts": []any{},
			})
			return
		}
		attempts += 1
		http.Error(writer, "invalid part", http.StatusBadRequest)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.UploadSession(
		context.Background(),
		UploadMetadata{Filename: "x", Type: "text/plain", Size: 2},
		bytes.NewBufferString("ab"),
	)
	if err == nil {
		t.Fatal("expected permanent part failure")
	}
	if attempts != 1 {
		t.Fatalf("expected one attempt, got %d", attempts)
	}
}
