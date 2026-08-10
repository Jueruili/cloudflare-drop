package cryptoformat

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func fixedKDF(_ string, _ []byte, _ Parameters) ([]byte, error) {
	return bytes.Repeat([]byte{0x11}, 32), nil
}

func deterministicConfig() Config {
	random := make([]byte, 512)
	for index := range random {
		random[index] = byte(index)
	}
	return Config{Random: bytes.NewReader(random), DeriveKey: fixedKDF}
}

func TestEncryptedSizeMatchesWrittenBytes(t *testing.T) {
	plaintext := bytes.Repeat([]byte("abcd"), 300_000)
	metadata := Metadata{
		Filename: "报告.txt",
		Type:     "text/plain;charset=utf-8",
	}
	var encrypted bytes.Buffer
	written, err := EncryptWithConfig(
		&encrypted,
		bytes.NewReader(plaintext),
		int64(len(plaintext)),
		"secret",
		metadata,
		deterministicConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}
	want, err := EncryptedSize(int64(len(plaintext)), metadata)
	if err != nil {
		t.Fatal(err)
	}
	if written != want || int64(encrypted.Len()) != want {
		t.Fatalf(
			"size mismatch: written=%d buffer=%d want=%d",
			written,
			encrypted.Len(),
			want,
		)
	}
	if got := binary.LittleEndian.Uint16(encrypted.Bytes()[4:6]); got != 2 {
		t.Fatalf("expected V2 version, got %d", got)
	}
}

func TestEncryptRejectsSourceShorterThanDeclaredSize(t *testing.T) {
	var encrypted bytes.Buffer
	_, err := EncryptWithConfig(
		&encrypted,
		stringsReader("short"),
		10,
		"secret",
		Metadata{},
		deterministicConfig(),
	)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected unexpected EOF, got %v", err)
	}
}

func TestEncryptRejectsSourceLongerThanDeclaredSize(t *testing.T) {
	var encrypted bytes.Buffer
	_, err := EncryptWithConfig(
		&encrypted,
		stringsReader("too long"),
		3,
		"secret",
		Metadata{},
		deterministicConfig(),
	)
	if !errors.Is(err, ErrPlaintextSizeMismatch) {
		t.Fatalf("expected plaintext size mismatch, got %v", err)
	}
}

func TestEncryptedSizeRejectsNegativePlaintextSize(t *testing.T) {
	if _, err := EncryptedSize(-1, Metadata{}); !errors.Is(err, ErrInvalidFormat) {
		t.Fatalf("expected invalid format, got %v", err)
	}
}

func stringsReader(value string) *bytes.Reader {
	return bytes.NewReader([]byte(value))
}
