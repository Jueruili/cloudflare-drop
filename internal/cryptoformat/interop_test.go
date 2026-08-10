package cryptoformat

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

type interopManifest struct {
	Password         string `json:"password"`
	DerivedKeyHex    string `json:"derivedKeyHex"`
	Filename         string `json:"filename"`
	Type             string `json:"type"`
	PlaintextPattern string `json:"plaintextPattern"`
	Repeat           int    `json:"repeat"`
}

func interopFixtureDirectory(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "tests", "fixtures", "v2")
}

func readInteropManifest(t *testing.T) interopManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(interopFixtureDirectory(t), "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest interopManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func TestV2InteropFixtures(t *testing.T) {
	manifest := readInteropManifest(t)
	derivedKey, err := hex.DecodeString(manifest.DerivedKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	kdf := func(string, []byte, Parameters) ([]byte, error) {
		return append([]byte(nil), derivedKey...), nil
	}
	plaintext := []byte(strings.Repeat(manifest.PlaintextPattern, manifest.Repeat))
	metadata := Metadata{Filename: manifest.Filename, Type: manifest.Type}

	var encrypted bytes.Buffer
	config := deterministicConfig()
	config.DeriveKey = kdf
	if _, err := EncryptWithConfig(
		&encrypted,
		bytes.NewReader(plaintext),
		int64(len(plaintext)),
		manifest.Password,
		metadata,
		config,
	); err != nil {
		t.Fatal(err)
	}

	directory := interopFixtureDirectory(t)
	goFixture := filepath.Join(directory, "go-v2.bin")
	update := os.Getenv("UPDATE_V2_FIXTURES") == "1"
	if update {
		if err := os.WriteFile(goFixture, encrypted.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	} else {
		expected, err := os.ReadFile(goFixture)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(expected, encrypted.Bytes()) {
			t.Fatal("Go V2 fixture changed")
		}
	}

	tsFixture := filepath.Join(directory, "ts-v2.bin")
	tsEncrypted, err := os.ReadFile(tsFixture)
	if err != nil {
		if update && os.IsNotExist(err) {
			return
		}
		t.Fatal(err)
	}
	var decrypted bytes.Buffer
	gotMetadata, _, err := DecryptWithConfig(
		&decrypted,
		bytes.NewReader(tsEncrypted),
		manifest.Password,
		Config{DeriveKey: kdf},
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotMetadata != metadata || !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatal("TypeScript fixture did not decrypt in Go")
	}
}

func TestArgon2idStandardVector(t *testing.T) {
	derived := argon2.IDKey(
		[]byte("password"),
		[]byte("somesalt"),
		2,
		65536,
		1,
		32,
	)
	const expected = "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"
	if hex.EncodeToString(derived) != expected {
		t.Fatalf("unexpected Argon2id output: %x", derived)
	}
}
