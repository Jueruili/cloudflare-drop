package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oustn/cloudflare-drop/internal/cryptoformat"
)

func successEnvelope(writer http.ResponseWriter, data any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"result": true, "message": "ok", "data": data,
	})
}

func decodeCommandOutput(t *testing.T, output string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal([]byte(output), &value); err != nil {
		t.Fatalf("invalid command JSON %q: %v", output, err)
	}
	return value
}

func TestRunUploadsLiteralText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseMultipartForm(1 << 20); err != nil {
			t.Fatal(err)
		}
		file, _, err := request.FormFile("file")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		content, _ := io.ReadAll(file)
		if string(content) != "hello world" {
			t.Fatalf("unexpected text %q", content)
		}
		successEnvelope(writer, map[string]any{
			"hash": "abc", "code": "123456", "due_date": nil,
			"is_ephemeral": false, "is_encrypted": false,
		})
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"upload", "--text", "hello world", "--server", server.URL},
		strings.NewReader(""),
		&stdout,
		&stderr,
		"dev",
	)
	if code != ExitOK {
		t.Fatalf("exit %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	result := decodeCommandOutput(t, stdout.String())
	if result["code"] != "123456" || result["url"] != server.URL+"/?code=123456" {
		t.Fatalf("unexpected result %#v", result)
	}
}

func TestRunUploadsEncryptedFileWithGeneratedPassword(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "报告.txt")
	plaintext := []byte("encrypted file content")
	if err := os.WriteFile(path, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	var encrypted []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/files/uploads":
			successEnvelope(writer, map[string]any{
				"sessionId": "session-1", "partSize": 5 * 1024 * 1024,
				"uploadedParts": []any{},
			})
		case request.Method == http.MethodPut && strings.Contains(request.URL.Path, "/parts/"):
			encrypted, _ = io.ReadAll(request.Body)
			successEnvelope(writer, map[string]any{"partNumber": 1})
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/complete"):
			successEnvelope(writer, map[string]any{
				"hash": "", "code": "654321", "due_date": nil,
				"is_ephemeral": false, "is_encrypted": true,
			})
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"upload", path, "--encrypt", "--server", server.URL},
		strings.NewReader(""),
		&stdout,
		&stderr,
		"dev",
	)
	if code != ExitOK {
		t.Fatalf("exit %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	result := decodeCommandOutput(t, stdout.String())
	password, _ := result["password"].(string)
	if len(password) != 24 {
		t.Fatalf("expected generated password, got %#v", result["password"])
	}
	var decrypted bytes.Buffer
	metadata, _, err := cryptoformat.Decrypt(
		&decrypted,
		bytes.NewReader(encrypted),
		password,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted.Bytes(), plaintext) || metadata.Filename != "报告.txt" {
		t.Fatalf("encrypted upload mismatch %#v %q", metadata, decrypted.Bytes())
	}
}
