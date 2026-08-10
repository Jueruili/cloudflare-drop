package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"
)

func Run(
	args []string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	version string,
) int {
	_ = stdin
	_ = stderr
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		return writeResponse(stdout, Response{
			OK:        true,
			Operation: "version",
			Version:   version,
		}, ExitOK)
	}

	if len(args) > 0 && args[0] == "upload" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		response, err := runUpload(ctx, args[1:], stdin)
		if err != nil {
			return writeCommandError(stdout, err)
		}
		return writeResponse(stdout, response, ExitOK)
	}
	if len(args) > 0 && args[0] == "get" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		response, err := runGet(ctx, args[1:])
		if err != nil {
			return writeCommandError(stdout, err)
		}
		return writeResponse(stdout, response, ExitOK)
	}

	command := ""
	if len(args) > 0 {
		command = args[0]
	}
	if command == "" {
		return writeError(stdout, ExitUsage, "USAGE", "command required")
	}
	return writeError(stdout, ExitUsage, "USAGE", "unknown command: "+command)
}

func writeCommandError(stdout io.Writer, err error) int {
	var commandErr *commandError
	if !errors.As(err, &commandErr) {
		commandErr = localError("LOCAL_ERROR", err)
	}
	return writeError(
		stdout,
		commandErr.exitCode,
		commandErr.code,
		commandErr.message,
	)
}

func writeResponse(stdout io.Writer, response any, code int) int {
	if err := json.NewEncoder(stdout).Encode(response); err != nil {
		return ExitUsage
	}
	return code
}

func writeError(stdout io.Writer, exitCode int, code, message string) int {
	return writeResponse(stdout, Response{
		OK: false,
		Error: &ErrorBody{
			Code:    code,
			Message: message,
		},
	}, exitCode)
}
