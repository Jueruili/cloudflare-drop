package cryptoformat

import (
	"bytes"
	"io"
	"regexp"
	"testing"
)

func TestGeneratePasswordUsesOnlyAlphanumericCharacters(t *testing.T) {
	random := append([]byte{248, 249, 255}, bytes.Repeat([]byte{247}, 24)...)
	password, err := GeneratePassword(bytes.NewReader(random))
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 24 {
		t.Fatalf("expected 24 characters, got %d", len(password))
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]{24}$`).MatchString(password) {
		t.Fatalf("bad password %q", password)
	}
	if password != "999999999999999999999999" {
		t.Fatalf("rejected bytes affected output: %q", password)
	}
}

func TestGeneratePasswordFailsWhenRandomInputEnds(t *testing.T) {
	_, err := GeneratePassword(bytes.NewReader([]byte{0, 1, 2}))
	if err != io.EOF {
		t.Fatalf("expected EOF, got %v", err)
	}
}
