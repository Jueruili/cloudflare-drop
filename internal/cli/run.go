package cli

import (
	"encoding/json"
	"fmt"
	"io"
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

	if len(args) > 0 && (args[0] == "upload" || args[0] == "get") {
		return writeError(stdout, ExitUsage, "NOT_IMPLEMENTED", fmt.Sprintf("command not implemented: %s", args[0]))
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
