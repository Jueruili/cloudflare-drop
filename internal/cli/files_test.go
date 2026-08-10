package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublishFileSanitizesAuthenticatedNameAndUsesPrivateTempFile(t *testing.T) {
	directory := t.TempDir()
	path, err := publishFile(directory, "../../报告.txt", func(file *os.File) error {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected 0600 temp file, got %o", info.Mode().Perm())
		}
		_, err = file.WriteString("content")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(directory, "报告.txt") {
		t.Fatalf("unexpected path %q", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "content" {
		t.Fatalf("unexpected content %q", content)
	}
}

func TestPublishFileDoesNotOverwriteExistingDestination(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "report.txt")
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := publishFile(destination, "ignored.txt", func(file *os.File) error {
		_, writeErr := file.WriteString("replacement")
		return writeErr
	})
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected destination exists, got %v", err)
	}
	content, _ := os.ReadFile(destination)
	if string(content) != "existing" {
		t.Fatalf("existing file changed: %q", content)
	}
}

func TestPublishFileCleansTemporaryFileOnFailure(t *testing.T) {
	directory := t.TempDir()
	writeFailure := errors.New("write failed")
	_, err := publishFile(directory, "report.txt", func(file *os.File) error {
		_, _ = file.WriteString("partial")
		return writeFailure
	})
	if !errors.Is(err, writeFailure) {
		t.Fatalf("expected write failure, got %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("temporary files remain: %s", strings.Join(names, ", "))
	}
}

func TestPublishFileCreatesExplicitTrailingSlashDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "downloads") + string(os.PathSeparator)
	path, err := publishFile(directory, "/absolute/report.txt", func(file *os.File) error {
		_, err := file.WriteString("content")
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Clean(filepath.Join(directory, "report.txt")) {
		t.Fatalf("unexpected path %q", path)
	}
}
