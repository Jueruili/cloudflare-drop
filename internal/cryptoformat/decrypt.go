package cryptoformat

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
)

const (
	maxHeaderLength = 16 * 1024 * 1024
	maxArgonTime    = 10
	maxArgonMemory  = 256 * 1024
	maxChunkSize    = 64 * 1024 * 1024
	minimumV2Header = 2 + 2 + 4 + 4 + 4 + saltLength + ivLength +
		ivLength + noncePrefixLength + ivLength + 2 + wrappedKeyLength + 4 +
		aesGCMTagLength
)

type parsedHeader struct {
	bytes             []byte
	prefix            []byte
	parameters        Parameters
	chunkSize         uint32
	salt              []byte
	wrappingIV        []byte
	metadataIV        []byte
	noncePrefix       []byte
	footerIV          []byte
	encryptedDataKey  []byte
	encryptedMetadata []byte
}

func Decrypt(
	dst io.Writer,
	src io.ReadSeeker,
	password string,
) (Metadata, int64, error) {
	return DecryptWithConfig(dst, src, password, Config{})
}

func DecryptWithConfig(
	dst io.Writer,
	src io.ReadSeeker,
	password string,
	config Config,
) (Metadata, int64, error) {
	if config.DeriveKey == nil {
		config.DeriveKey = defaultDeriveKey
	}
	header, dataStart, err := readV2Header(src)
	if err != nil {
		return Metadata{}, 0, err
	}

	passwordKey, err := config.DeriveKey(password, header.salt, header.parameters)
	if err != nil {
		return Metadata{}, 0, fmt.Errorf("derive password key: %w", err)
	}
	passwordGCM, err := newGCM(passwordKey)
	if err != nil {
		return Metadata{}, 0, fmt.Errorf("create password cipher: %w", err)
	}
	dataKey, err := openAuthenticated(
		passwordGCM,
		header.wrappingIV,
		header.encryptedDataKey,
		header.prefix,
	)
	if err != nil {
		return Metadata{}, 0, err
	}
	if len(dataKey) != 32 {
		return Metadata{}, 0, ErrInvalidFormat
	}
	dataGCM, err := newGCM(dataKey)
	if err != nil {
		return Metadata{}, 0, fmt.Errorf("create data cipher: %w", err)
	}

	metadataAdditionalData := join(header.prefix, header.encryptedDataKey)
	metadataBytes, err := openAuthenticated(
		dataGCM,
		header.metadataIV,
		header.encryptedMetadata,
		metadataAdditionalData,
	)
	if err != nil {
		return Metadata{}, 0, err
	}
	var metadata Metadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return Metadata{}, 0, fmt.Errorf("%w: metadata JSON", ErrInvalidFormat)
	}

	end, err := src.Seek(0, io.SeekEnd)
	if err != nil {
		return Metadata{}, 0, err
	}
	if end < dataStart+footerCiphertextLength {
		return Metadata{}, 0, ErrInvalidFormat
	}
	footerStart := end - footerCiphertextLength
	if _, err := src.Seek(footerStart, io.SeekStart); err != nil {
		return Metadata{}, 0, err
	}
	encryptedFooter := make([]byte, footerCiphertextLength)
	if _, err := io.ReadFull(src, encryptedFooter); err != nil {
		return Metadata{}, 0, ErrInvalidFormat
	}
	footer, err := openAuthenticated(
		dataGCM,
		header.footerIV,
		encryptedFooter,
		footerAdditionalData(header.bytes),
	)
	if err != nil {
		return Metadata{}, 0, err
	}
	if len(footer) != footerPlaintextLength ||
		subtle.ConstantTimeCompare(footer[:4], footerMagic) != 1 {
		return Metadata{}, 0, ErrInvalidFormat
	}
	totalFrames := binary.LittleEndian.Uint32(footer[4:8])
	plaintextSizeValue := binary.LittleEndian.Uint64(footer[8:16])
	if plaintextSizeValue > math.MaxInt64 {
		return Metadata{}, 0, ErrInvalidFormat
	}
	plaintextSize := int64(plaintextSizeValue)
	expectedFrames, err := frameCountForSize(plaintextSize, header.chunkSize)
	if err != nil || totalFrames != expectedFrames {
		return Metadata{}, 0, ErrInvalidFormat
	}
	expectedCiphertext := plaintextSize + int64(totalFrames)*aesGCMTagLength
	if footerStart-dataStart != expectedCiphertext {
		return Metadata{}, 0, ErrInvalidFormat
	}

	if _, err := src.Seek(dataStart, io.SeekStart); err != nil {
		return Metadata{}, 0, err
	}
	output := &countingWriter{writer: dst}
	remaining := plaintextSize
	for index := uint32(0); index < totalFrames; index++ {
		plaintextFrameSize := int64(header.chunkSize)
		if remaining < plaintextFrameSize {
			plaintextFrameSize = remaining
		}
		encryptedFrame := make([]byte, int(plaintextFrameSize)+aesGCMTagLength)
		if _, err := io.ReadFull(src, encryptedFrame); err != nil {
			return Metadata{}, output.written, ErrInvalidFormat
		}
		frame, err := openAuthenticated(
			dataGCM,
			frameNonce(header.noncePrefix, index),
			encryptedFrame,
			frameAdditionalData(header.bytes, index),
		)
		if err != nil {
			return Metadata{}, output.written, err
		}
		if _, err := output.Write(frame); err != nil {
			return Metadata{}, output.written, err
		}
		remaining -= plaintextFrameSize
	}
	return metadata, output.written, nil
}

func readV2Header(src io.ReadSeeker) (parsedHeader, int64, error) {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return parsedHeader{}, 0, err
	}
	headerLengthBytes := make([]byte, headerLengthSize)
	if _, err := io.ReadFull(src, headerLengthBytes); err != nil {
		return parsedHeader{}, 0, ErrInvalidFormat
	}
	headerLength := binary.LittleEndian.Uint32(headerLengthBytes)
	if headerLength < 2 || headerLength > maxHeaderLength {
		return parsedHeader{}, 0, ErrInvalidFormat
	}
	header := make([]byte, headerLength)
	if _, err := io.ReadFull(src, header); err != nil {
		return parsedHeader{}, 0, ErrInvalidFormat
	}
	version := binary.LittleEndian.Uint16(header[:2])
	if version != versionV2 {
		return parsedHeader{}, 0, fmt.Errorf("%w: %d", ErrUnsupportedVersion, version)
	}
	if len(header) < minimumV2Header {
		return parsedHeader{}, 0, ErrInvalidFormat
	}

	offset := 2
	mode := binary.LittleEndian.Uint16(header[offset : offset+2])
	offset += 2
	if mode != streamModeV2 {
		return parsedHeader{}, 0, ErrInvalidFormat
	}
	parameters := Parameters{
		Time:   binary.LittleEndian.Uint32(header[offset : offset+4]),
		Memory: binary.LittleEndian.Uint32(header[offset+4 : offset+8]),
	}
	offset += 8
	parsedChunkSize := binary.LittleEndian.Uint32(header[offset : offset+4])
	offset += 4
	if parameters.Time < 1 || parameters.Time > maxArgonTime ||
		parameters.Memory < 1 || parameters.Memory > maxArgonMemory ||
		parsedChunkSize < 1 || parsedChunkSize > maxChunkSize {
		return parsedHeader{}, 0, ErrInvalidFormat
	}

	take := func(length int) []byte {
		result := header[offset : offset+length]
		offset += length
		return result
	}
	salt := take(saltLength)
	wrappingIV := take(ivLength)
	metadataIV := take(ivLength)
	noncePrefix := take(noncePrefixLength)
	footerIV := take(ivLength)
	parsedWrappedKeyLength := binary.LittleEndian.Uint16(header[offset : offset+2])
	offset += 2
	if parsedWrappedKeyLength != wrappedKeyLength {
		return parsedHeader{}, 0, ErrInvalidFormat
	}
	prefix := header[:offset]
	encryptedDataKey := take(int(parsedWrappedKeyLength))
	metadataLength := binary.LittleEndian.Uint32(header[offset : offset+4])
	offset += 4
	if metadataLength < aesGCMTagLength ||
		uint64(offset)+uint64(metadataLength) != uint64(len(header)) {
		return parsedHeader{}, 0, ErrInvalidFormat
	}
	encryptedMetadata := take(int(metadataLength))

	return parsedHeader{
		bytes:             header,
		prefix:            prefix,
		parameters:        parameters,
		chunkSize:         parsedChunkSize,
		salt:              salt,
		wrappingIV:        wrappingIV,
		metadataIV:        metadataIV,
		noncePrefix:       noncePrefix,
		footerIV:          footerIV,
		encryptedDataKey:  encryptedDataKey,
		encryptedMetadata: encryptedMetadata,
	}, headerLengthSize + int64(headerLength), nil
}

func frameCountForSize(plaintextSize int64, size uint32) (uint32, error) {
	if plaintextSize < 0 || size == 0 {
		return 0, ErrInvalidFormat
	}
	if plaintextSize == 0 {
		return 0, nil
	}
	count := (plaintextSize + int64(size) - 1) / int64(size)
	if count > math.MaxUint32 {
		return 0, ErrInvalidFormat
	}
	return uint32(count), nil
}

func openAuthenticated(
	gcm cipher.AEAD,
	nonce []byte,
	ciphertext []byte,
	additionalData []byte,
) ([]byte, error) {
	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}
