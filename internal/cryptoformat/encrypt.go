package cryptoformat

import (
	"crypto/rand"
	"fmt"
	"io"
)

type countingWriter struct {
	written int64
	writer  io.Writer
}

func (writer *countingWriter) Write(data []byte) (int, error) {
	written, err := writer.writer.Write(data)
	writer.written += int64(written)
	return written, err
}

func Encrypt(
	dst io.Writer,
	src io.Reader,
	plaintextSize int64,
	password string,
	metadata Metadata,
) (int64, error) {
	return EncryptWithConfig(dst, src, plaintextSize, password, metadata, Config{})
}

func EncryptWithConfig(
	dst io.Writer,
	src io.Reader,
	plaintextSize int64,
	password string,
	metadata Metadata,
	config Config,
) (int64, error) {
	if _, err := EncryptedSize(plaintextSize, metadata); err != nil {
		return 0, err
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if config.DeriveKey == nil {
		config.DeriveKey = defaultDeriveKey
	}

	salt := make([]byte, saltLength)
	wrappingIV := make([]byte, ivLength)
	metadataIV := make([]byte, ivLength)
	noncePrefix := make([]byte, noncePrefixLength)
	footerIV := make([]byte, ivLength)
	dataKey := make([]byte, 32)
	for _, target := range [][]byte{
		salt,
		wrappingIV,
		metadataIV,
		noncePrefix,
		footerIV,
		dataKey,
	} {
		if _, err := io.ReadFull(config.Random, target); err != nil {
			return 0, fmt.Errorf("read secure randomness: %w", err)
		}
	}

	passwordKey, err := config.DeriveKey(password, salt, defaultParameters)
	if err != nil {
		return 0, fmt.Errorf("derive password key: %w", err)
	}
	passwordGCM, err := newGCM(passwordKey)
	if err != nil {
		return 0, fmt.Errorf("create password cipher: %w", err)
	}
	dataGCM, err := newGCM(dataKey)
	if err != nil {
		return 0, fmt.Errorf("create data cipher: %w", err)
	}

	prefix := join(
		uint16LE(versionV2),
		uint16LE(streamModeV2),
		uint32LE(defaultParameters.Time),
		uint32LE(defaultParameters.Memory),
		uint32LE(chunkSize),
		salt,
		wrappingIV,
		metadataIV,
		noncePrefix,
		footerIV,
		uint16LE(wrappedKeyLength),
	)
	encryptedDataKey := passwordGCM.Seal(nil, wrappingIV, dataKey, prefix)
	metadataAdditionalData := join(prefix, encryptedDataKey)
	metadataBytes, err := metadataJSON(metadata)
	if err != nil {
		return 0, err
	}
	encryptedMetadata := dataGCM.Seal(
		nil,
		metadataIV,
		metadataBytes,
		metadataAdditionalData,
	)
	header := join(
		metadataAdditionalData,
		uint32LE(uint32(len(encryptedMetadata))),
		encryptedMetadata,
	)

	output := &countingWriter{writer: dst}
	if _, err := output.Write(uint32LE(uint32(len(header)))); err != nil {
		return output.written, err
	}
	if _, err := output.Write(header); err != nil {
		return output.written, err
	}

	frames, _ := frameCount(plaintextSize)
	remaining := plaintextSize
	buffer := make([]byte, chunkSize)
	for index := uint32(0); index < frames; index++ {
		frameLength := int64(chunkSize)
		if remaining < frameLength {
			frameLength = remaining
		}
		frame := buffer[:int(frameLength)]
		if _, err := io.ReadFull(src, frame); err != nil {
			return output.written, err
		}
		encryptedFrame := dataGCM.Seal(
			nil,
			frameNonce(noncePrefix, index),
			frame,
			frameAdditionalData(header, index),
		)
		if _, err := output.Write(encryptedFrame); err != nil {
			return output.written, err
		}
		remaining -= frameLength
	}

	probe := make([]byte, 1)
	if count, err := io.ReadFull(src, probe); count > 0 {
		return output.written, ErrPlaintextSizeMismatch
	} else if err != nil && err != io.EOF {
		return output.written, err
	}

	footerPlaintext := join(
		footerMagic,
		uint32LE(frames),
		uint64LE(uint64(plaintextSize)),
	)
	encryptedFooter := dataGCM.Seal(
		nil,
		footerIV,
		footerPlaintext,
		footerAdditionalData(header),
	)
	if _, err := output.Write(encryptedFooter); err != nil {
		return output.written, err
	}
	return output.written, nil
}
