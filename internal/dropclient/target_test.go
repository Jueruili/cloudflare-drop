package dropclient

import (
	"errors"
	"testing"
)

func TestResolveTargetFromShareURL(t *testing.T) {
	target, err := ResolveTarget(
		"https://drop.example.com/?code=123456",
		"",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if target.Server.String() != "https://drop.example.com" || target.Code != "123456" {
		t.Fatalf("unexpected target %#v", target)
	}
}

func TestResolveTargetFromBareCodeAndEnvironment(t *testing.T) {
	target, err := ResolveTarget("123456", "", "https://drop.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	if target.Server.String() != "https://drop.example.com" || target.Code != "123456" {
		t.Fatalf("unexpected target %#v", target)
	}
}

func TestResolveTargetRejectsConflictingShareURLServer(t *testing.T) {
	_, err := ResolveTarget(
		"https://one.example.com/?code=123456",
		"https://two.example.com",
		"",
	)
	if !errors.Is(err, ErrConflictingServer) {
		t.Fatalf("expected conflicting server, got %v", err)
	}
}

func TestResolveTargetRejectsInvalidInput(t *testing.T) {
	tests := []string{
		"12345",
		"ABCDEF",
		"https://drop.example.com/?code=123456&next=other",
		"https://user:secret@drop.example.com/?code=123456",
		"https://drop.example.com/path?code=123456",
		"https://drop.example.com/?code=123456#fragment",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := ResolveTarget(input, "", ""); err == nil {
				t.Fatal("expected invalid target")
			}
		})
	}
}

func TestResolveServerRejectsHTTPForRemoteServer(t *testing.T) {
	_, err := ResolveServer("http://drop.example.com")
	if !errors.Is(err, ErrInsecureServer) {
		t.Fatalf("expected insecure server, got %v", err)
	}
}

func TestResolveServerAllowsLocalHTTP(t *testing.T) {
	for _, raw := range []string{
		"http://localhost:8787/",
		"http://127.0.0.1:8787",
		"http://[::1]:8787",
	} {
		t.Run(raw, func(t *testing.T) {
			server, err := ResolveServer(raw)
			if err != nil {
				t.Fatal(err)
			}
			if server.Path != "" {
				t.Fatalf("expected normalized origin, got %s", server)
			}
		})
	}
}
