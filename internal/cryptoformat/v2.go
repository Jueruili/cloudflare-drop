package cryptoformat

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"golang.org/x/crypto/argon2"
)

const (
	versionV2              = uint16(2)
	streamModeV2           = uint16(1)
	headerLengthSize       = int64(4)
	saltLength             = 16
	ivLength               = 12
	noncePrefixLength      = 8
	aesGCMTagLength        = 16
	wrappedKeyLength       = 32 + aesGCMTagLength
	chunkSize              = 1024 * 1024
	footerPlaintextLength  = 16
	footerCiphertextLength = footerPlaintextLength +
		aesGCMTagLength
)

var (
	ErrUnsupportedVersion    = errors.New("unsupported encrypted format version")
	ErrInvalidFormat         = errors.New("invalid encrypted file format")
	ErrAuthentication        = errors.New("failed to authenticate encrypted share")
	ErrPlaintextSizeMismatch = errors.New("plaintext size does not match declared size")
	footerMagic              = []byte{0x43, 0x44, 0x46, 0x54}
	defaultParameters        = Parameters{Time: 3, Memory: 65536}
)

type Metadata struct {
	Filename string `json:"filename,omitempty"`
	Type     string `json:"type,omitempty"`
}

type Parameters struct {
	Time   uint32
	Memory uint32
}

type DeriveKeyFunc func(
	password string,
	salt []byte,
	parameters Parameters,
) ([]byte, error)

type Config struct {
	Random    io.Reader
	DeriveKey DeriveKeyFunc
}

func defaultDeriveKey(
	password string,
	salt []byte,
	parameters Parameters,
) ([]byte, error) {
	return argon2.IDKey(
		[]byte(password),
		salt,
		parameters.Time,
		parameters.Memory,
		1,
		32,
	), nil
}

func metadataJSON(metadata Metadata) ([]byte, error) {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("encode encrypted metadata: %w", err)
	}
	return encoded, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func uint16LE(value uint16) []byte {
	result := make([]byte, 2)
	binary.LittleEndian.PutUint16(result, value)
	return result
}

func uint32LE(value uint32) []byte {
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, value)
	return result
}

func uint64LE(value uint64) []byte {
	result := make([]byte, 8)
	binary.LittleEndian.PutUint64(result, value)
	return result
}

func join(parts ...[]byte) []byte {
	length := 0
	for _, part := range parts {
		length += len(part)
	}
	result := make([]byte, 0, length)
	for _, part := range parts {
		result = append(result, part...)
	}
	return result
}

func frameNonce(prefix []byte, index uint32) []byte {
	return join(prefix, uint32LE(index))
}

func frameAdditionalData(header []byte, index uint32) []byte {
	return join(
		header,
		[]byte("cloudflare-drop:v2:frame"),
		uint32LE(index),
	)
}

func footerAdditionalData(header []byte) []byte {
	return join(header, []byte("cloudflare-drop:v2:footer"))
}

func frameCount(plaintextSize int64) (uint32, error) {
	if plaintextSize < 0 {
		return 0, ErrInvalidFormat
	}
	if plaintextSize == 0 {
		return 0, nil
	}
	count := (plaintextSize + chunkSize - 1) / chunkSize
	if count > math.MaxUint32 {
		return 0, fmt.Errorf("%w: too many frames", ErrInvalidFormat)
	}
	return uint32(count), nil
}

func EncryptedSize(plaintextSize int64, metadata Metadata) (int64, error) {
	frames, err := frameCount(plaintextSize)
	if err != nil {
		return 0, err
	}
	metadataBytes, err := metadataJSON(metadata)
	if err != nil {
		return 0, err
	}
	headerLength := int64(
		2 + 2 + 4 + 4 + 4 + saltLength + ivLength + ivLength +
			noncePrefixLength + ivLength + 2 + wrappedKeyLength + 4 +
			len(metadataBytes) + aesGCMTagLength,
	)
	overhead := headerLengthSize + headerLength +
		int64(frames)*aesGCMTagLength + footerCiphertextLength
	if plaintextSize > math.MaxInt64-overhead {
		return 0, fmt.Errorf("%w: encrypted size overflow", ErrInvalidFormat)
	}
	return plaintextSize + overhead, nil
}
