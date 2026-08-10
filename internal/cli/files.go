package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func publishFile(
	output string,
	authenticatedName string,
	write func(*os.File) error,
) (absolutePath string, err error) {
	filename := filepath.Base(authenticatedName)
	if filename == "" || filename == "." || filename == string(os.PathSeparator) {
		filename = "download"
	}
	destination, err := resolveDestination(output, filename)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(destination); err == nil {
		return "", fmt.Errorf("%w: %s", os.ErrExist, destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	directory := filepath.Dir(destination)
	temporary, err := os.CreateTemp(directory, ".cloudflare-drop-*")
	if err != nil {
		return "", err
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := write(temporary); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Link(temporaryPath, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("%w: %s", os.ErrExist, destination)
		}
		return "", err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return "", err
	}
	removeTemporary = false
	return destination, nil
}

func resolveDestination(output, filename string) (string, error) {
	if output == "" {
		output = filename
	} else {
		trailingSeparator := strings.HasSuffix(output, string(os.PathSeparator))
		info, err := os.Stat(output)
		switch {
		case err == nil && info.IsDir():
			output = filepath.Join(output, filename)
		case err == nil:
			return "", fmt.Errorf("%w: %s", os.ErrExist, output)
		case errors.Is(err, os.ErrNotExist) && trailingSeparator:
			directory := filepath.Clean(output)
			if err := os.MkdirAll(directory, 0o700); err != nil {
				return "", err
			}
			output = filepath.Join(directory, filename)
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return "", err
		}
	}
	absolute, err := filepath.Abs(filepath.Clean(output))
	if err != nil {
		return "", err
	}
	parent, err := os.Stat(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	if !parent.IsDir() {
		return "", fmt.Errorf("output parent is not a directory")
	}
	return absolute, nil
}
