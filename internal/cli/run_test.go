package cli

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func assertJSON(t *testing.T, expected, actual string) {
	t.Helper()
	var want any
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatalf("invalid expected JSON: %v", err)
	}
	var got any
	if err := json.Unmarshal([]byte(actual), &got); err != nil {
		t.Fatalf("invalid actual JSON %q: %v", actual, err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("JSON mismatch\nwant: %s\n got: %s", expected, actual)
	}
}

func TestRunVersionWritesJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"--version"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		"1.2.3",
	)

	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	assertJSON(
		t,
		`{"ok":true,"operation":"version","version":"1.2.3"}`,
		stdout.String(),
	)
	if stderr.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", stderr.String())
	}
}

func TestRunRejectsUnknownCommandWithUsageExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run(
		[]string{"unknown"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		"dev",
	)

	if code != 2 {
		t.Fatalf("expected exit 2, got %d", code)
	}
	assertJSON(
		t,
		`{"ok":false,"error":{"code":"USAGE","message":"unknown command: unknown"}}`,
		stdout.String(),
	)
}
