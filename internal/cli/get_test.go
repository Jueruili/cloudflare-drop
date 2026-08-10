package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oustn/cloudflare-drop/internal/cryptoformat"
)

func shareServer(t *testing.T, metadata map[string]any, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/files/share/123456":
			metadata["id"] = "file-id"
			metadata["code"] = "123456"
			metadata["token"] = "token"
			metadata["due_date"] = nil
			successEnvelope(writer, metadata)
		case request.URL.Path == "/files/file-id":
			if request.URL.Query().Get("token") != "token" {
				t.Fatal("missing token")
			}
			_, _ = writer.Write(body)
		default:
			t.Fatalf("unexpected request %s", request.URL)
		}
	}))
}

func TestRunGetsPlainTextFromShareURL(t *testing.T) {
	body := []byte("shared text")
	hash := sha256.Sum256(body)
	server := shareServer(t, map[string]any{
		"filename": "text", "hash": hex.EncodeToString(hash[:]),
		"type": "plain/string", "size": len(body),
		"is_ephemeral": false, "is_encrypted": false,
	}, body)
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"get", server.URL + "/?code=123456"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		"dev",
	)
	if code != ExitOK {
		t.Fatalf("exit %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	result := decodeCommandOutput(t, stdout.String())
	if result["kind"] != "text" || result["text"] != "shared text" {
		t.Fatalf("unexpected result %#v", result)
	}
}

func TestRunDoesNotPublishFileWhenHashMismatches(t *testing.T) {
	server := shareServer(t, map[string]any{
		"filename": "report.bin", "hash": strings.Repeat("00", 32),
		"type": "application/octet-stream", "size": 7,
		"is_ephemeral": false, "is_encrypted": false,
	}, []byte("content"))
	defer server.Close()
	directory := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"get", server.URL + "/?code=123456", "--output", directory},
		strings.NewReader(""),
		&stdout,
		&stderr,
		"dev",
	)
	if code != ExitIntegrity {
		t.Fatalf("exit %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 0 {
		t.Fatalf("hash mismatch published files: %#v", entries)
	}
}

func TestRunGetsAndDecryptsEncryptedFile(t *testing.T) {
	plaintext := []byte("secret report")
	var encrypted bytes.Buffer
	_, err := cryptoformat.Encrypt(
		&encrypted,
		bytes.NewReader(plaintext),
		int64(len(plaintext)),
		"SecretPassword123",
		cryptoformat.Metadata{Filename: "报告.txt", Type: "text/plain"},
	)
	if err != nil {
		t.Fatal(err)
	}
	server := shareServer(t, map[string]any{
		"filename": "encrypted-file", "hash": "", "type": "text/plain",
		"size": len(plaintext), "is_ephemeral": false, "is_encrypted": true,
	}, encrypted.Bytes())
	defer server.Close()
	directory := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{
			"get", server.URL + "/?code=123456",
			"--password", "SecretPassword123",
			"--output", directory,
		},
		strings.NewReader(""),
		&stdout,
		&stderr,
		"dev",
	)
	if code != ExitOK {
		t.Fatalf("exit %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	result := decodeCommandOutput(t, stdout.String())
	path, _ := result["path"].(string)
	if filepath.Base(path) != "报告.txt" {
		t.Fatalf("unexpected path %q", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, plaintext) {
		t.Fatalf("unexpected plaintext %q", content)
	}
}

func TestRunRejectsV1EncryptedShare(t *testing.T) {
	v1 := append([]byte{2, 0, 0, 0, 1, 0}, 0)
	server := shareServer(t, map[string]any{
		"filename": "encrypted-file", "hash": "", "type": "application/octet-stream",
		"size": 1, "is_ephemeral": true, "is_encrypted": true,
	}, v1)
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"get", server.URL + "/?code=123456", "--password", "secret"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		"dev",
	)
	if code != ExitIntegrity {
		t.Fatalf("exit %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "UNSUPPORTED_ENCRYPTED_FORMAT") {
		t.Fatalf("unexpected error %s", stdout.String())
	}
}
