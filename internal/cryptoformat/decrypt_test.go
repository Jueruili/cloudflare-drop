package cryptoformat

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

func passwordKDF(password string, salt []byte, _ Parameters) ([]byte, error) {
	digest := sha256.Sum256(append([]byte(password), salt...))
	return digest[:], nil
}

func encryptForDecryptTest(
	t *testing.T,
	plaintext []byte,
	metadata Metadata,
	kdf DeriveKeyFunc,
) []byte {
	t.Helper()
	config := deterministicConfig()
	config.DeriveKey = kdf
	var encrypted bytes.Buffer
	if _, err := EncryptWithConfig(
		&encrypted,
		bytes.NewReader(plaintext),
		int64(len(plaintext)),
		"secret",
		metadata,
		config,
	); err != nil {
		t.Fatal(err)
	}
	return encrypted.Bytes()
}

func TestDecryptRoundTrip(t *testing.T) {
	plaintext := bytes.Repeat([]byte("stream me"), 200_000)
	metadata := Metadata{Filename: "../报告.txt", Type: "text/plain"}
	encrypted := encryptForDecryptTest(t, plaintext, metadata, fixedKDF)
	config := Config{DeriveKey: fixedKDF}
	var decrypted bytes.Buffer

	gotMetadata, written, err := DecryptWithConfig(
		&decrypted,
		bytes.NewReader(encrypted),
		"secret",
		config,
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotMetadata != metadata {
		t.Fatalf("metadata mismatch: %#v", gotMetadata)
	}
	if written != int64(len(plaintext)) || !bytes.Equal(decrypted.Bytes(), plaintext) {
		t.Fatal("plaintext mismatch")
	}
}

func TestDecryptRejectsWrongPassword(t *testing.T) {
	encrypted := encryptForDecryptTest(t, []byte("secret content"), Metadata{}, passwordKDF)
	var decrypted bytes.Buffer
	_, _, err := DecryptWithConfig(
		&decrypted,
		bytes.NewReader(encrypted),
		"wrong",
		Config{DeriveKey: passwordKDF},
	)
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected authentication error, got %v", err)
	}
}

func TestDecryptRejectsAuthenticatedDataMutations(t *testing.T) {
	plaintext := bytes.Repeat([]byte("frame"), 500_000)
	original := encryptForDecryptTest(t, plaintext, Metadata{Filename: "x"}, fixedKDF)
	headerLength := int(binary.LittleEndian.Uint32(original[:4]))
	frameStart := 4 + headerLength
	frameLength := chunkSize + aesGCMTagLength

	tests := map[string]func([]byte) []byte{
		"header": func(data []byte) []byte {
			data[4+16] ^= 0x01
			return data
		},
		"frame": func(data []byte) []byte {
			data[frameStart] ^= 0x01
			return data
		},
		"reordered frames": func(data []byte) []byte {
			first := append([]byte(nil), data[frameStart:frameStart+frameLength]...)
			second := append([]byte(nil), data[frameStart+frameLength:frameStart+2*frameLength]...)
			copy(data[frameStart:], second)
			copy(data[frameStart+frameLength:], first)
			return data
		},
		"footer": func(data []byte) []byte {
			data[len(data)-1] ^= 0x01
			return data
		},
		"truncated": func(data []byte) []byte {
			return data[:len(data)-1]
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			data := mutate(append([]byte(nil), original...))
			var decrypted bytes.Buffer
			_, _, err := DecryptWithConfig(
				&decrypted,
				bytes.NewReader(data),
				"secret",
				Config{DeriveKey: fixedKDF},
			)
			if err == nil {
				t.Fatal("expected corrupted data to fail")
			}
		})
	}
}

func TestDecryptRejectsV1(t *testing.T) {
	data := append(uint32LE(2), uint16LE(1)...)
	data = append(data, 0)
	var decrypted bytes.Buffer
	_, _, err := DecryptWithConfig(
		&decrypted,
		bytes.NewReader(data),
		"secret",
		Config{DeriveKey: fixedKDF},
	)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected unsupported version, got %v", err)
	}
}

func TestDecryptRejectsUnsafeParametersBeforeCallingKDF(t *testing.T) {
	original := encryptForDecryptTest(t, []byte("content"), Metadata{}, fixedKDF)
	tests := map[string]struct {
		offset int
		value  uint32
	}{
		"zero time":        {offset: 4 + 4, value: 0},
		"excessive time":   {offset: 4 + 4, value: 11},
		"zero memory":      {offset: 4 + 8, value: 0},
		"excessive memory": {offset: 4 + 8, value: 262145},
		"excessive chunk":  {offset: 4 + 12, value: 64*1024*1024 + 1},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			data := append([]byte(nil), original...)
			binary.LittleEndian.PutUint32(data[test.offset:test.offset+4], test.value)
			called := false
			derive := func(string, []byte, Parameters) ([]byte, error) {
				called = true
				return fixedKDF("", nil, Parameters{})
			}
			var decrypted bytes.Buffer
			_, _, err := DecryptWithConfig(
				&decrypted,
				bytes.NewReader(data),
				"secret",
				Config{DeriveKey: derive},
			)
			if !errors.Is(err, ErrInvalidFormat) {
				t.Fatalf("expected invalid format, got %v", err)
			}
			if called {
				t.Fatal("unsafe parameters reached KDF")
			}
		})
	}
}
