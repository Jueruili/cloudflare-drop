package cryptoformat

import "io"

const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func GeneratePassword(random io.Reader) (string, error) {
	result := make([]byte, 0, 24)
	buffer := make([]byte, 1)
	for len(result) < 24 {
		if _, err := io.ReadFull(random, buffer); err != nil {
			return "", err
		}
		if buffer[0] >= 248 {
			continue
		}
		result = append(result, passwordAlphabet[int(buffer[0])%len(passwordAlphabet)])
	}
	return string(result), nil
}
