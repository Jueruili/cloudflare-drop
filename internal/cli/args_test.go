package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func emptyEnvironment(string) string { return "" }

func TestParseUploadArgsAllowsFlagsBeforeOrAfterPath(t *testing.T) {
	before, err := parseUploadArgs(
		[]string{"--server", "https://drop.example.com", "report.txt", "--duration", "1hour", "--ephemeral"},
		emptyEnvironment,
	)
	if err != nil {
		t.Fatal(err)
	}
	after, err := parseUploadArgs(
		[]string{"--ephemeral", "--duration=1hour", "--server=https://drop.example.com", "report.txt"},
		emptyEnvironment,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("argument order changed result\n%#v\n%#v", before, after)
	}
}

func TestParseUploadArgsRequiresExactlyOneContentSource(t *testing.T) {
	for _, args := range [][]string{
		{"--server", "https://drop.example.com"},
		{"file.txt", "--text", "hello", "--server", "https://drop.example.com"},
		{"--stdin", "--text", "hello", "--server", "https://drop.example.com"},
	} {
		if _, err := parseUploadArgs(args, emptyEnvironment); err == nil {
			t.Fatalf("expected content-source error for %#v", args)
		}
	}
}

func TestParseUploadArgsResolvesPasswordFileAndEnvironment(t *testing.T) {
	directory := t.TempDir()
	passwordPath := filepath.Join(directory, "password")
	if err := os.WriteFile(passwordPath, []byte("file-secret\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := parseUploadArgs(
		[]string{"--text", "hello", "--encrypt", "--password-file", passwordPath},
		func(name string) string {
			switch name {
			case "CLOUDFLARE_DROP_URL":
				return "https://drop.example.com"
			case "CLOUDFLARE_DROP_PASSWORD":
				return "environment-secret"
			default:
				return ""
			}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.password != "file-secret" || parsed.server != "https://drop.example.com" {
		t.Fatalf("unexpected parsed args %#v", parsed)
	}
}

func TestParseUploadArgsRejectsConflictingExplicitPasswords(t *testing.T) {
	_, err := parseUploadArgs(
		[]string{
			"--text", "hello",
			"--server", "https://drop.example.com",
			"--encrypt",
			"--password", "secret",
			"--password-file", "password.txt",
		},
		emptyEnvironment,
	)
	if err == nil {
		t.Fatal("expected conflicting password error")
	}
}
