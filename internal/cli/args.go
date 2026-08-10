package cli

import (
	"fmt"
	"os"
	"strings"
)

type uploadArgs struct {
	path      string
	text      string
	textSet   bool
	stdin     bool
	server    string
	duration  string
	password  string
	ephemeral bool
	encrypt   bool
}

type getArgs struct {
	target   string
	server   string
	password string
	output   string
}

type environmentLookup func(string) string

func parseUploadArgs(args []string, getenv environmentLookup) (uploadArgs, error) {
	var result uploadArgs
	var positionals []string
	var password, passwordFile string
	var passwordSet, passwordFileSet bool

	for index := 0; index < len(args); index++ {
		token := args[index]
		if token == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(token, "--") {
			positionals = append(positionals, token)
			continue
		}
		name, value, hasValue := splitFlag(token)
		switch name {
		case "--stdin", "--ephemeral", "--encrypt", "--json":
			if hasValue {
				return uploadArgs{}, fmt.Errorf("flag %s does not accept a value", name)
			}
			switch name {
			case "--stdin":
				result.stdin = true
			case "--ephemeral":
				result.ephemeral = true
			case "--encrypt":
				result.encrypt = true
			}
		case "--server", "--duration", "--text", "--password", "--password-file":
			if !hasValue {
				index++
				if index >= len(args) {
					return uploadArgs{}, fmt.Errorf("flag %s requires a value", name)
				}
				value = args[index]
			}
			switch name {
			case "--server":
				result.server = value
			case "--duration":
				result.duration = value
			case "--text":
				result.text = value
				result.textSet = true
			case "--password":
				password = value
				passwordSet = true
			case "--password-file":
				passwordFile = value
				passwordFileSet = true
			}
		default:
			return uploadArgs{}, fmt.Errorf("unknown flag: %s", name)
		}
	}
	if len(positionals) > 1 {
		return uploadArgs{}, fmt.Errorf("upload accepts only one file path")
	}
	if len(positionals) == 1 {
		result.path = positionals[0]
	}
	sources := 0
	if result.path != "" {
		sources++
	}
	if result.textSet {
		sources++
	}
	if result.stdin {
		sources++
	}
	if sources != 1 {
		return uploadArgs{}, fmt.Errorf("provide exactly one file path, --text, or --stdin")
	}
	if result.server == "" {
		result.server = strings.TrimSpace(getenv("CLOUDFLARE_DROP_URL"))
	}
	if result.server == "" {
		return uploadArgs{}, fmt.Errorf("Cloudflare Drop server URL is required")
	}
	resolvedPassword, err := resolvePassword(
		password,
		passwordSet,
		passwordFile,
		passwordFileSet,
		getenv,
	)
	if err != nil {
		return uploadArgs{}, err
	}
	if !result.encrypt && resolvedPassword != "" {
		return uploadArgs{}, fmt.Errorf("password requires --encrypt")
	}
	result.password = resolvedPassword
	return result, nil
}

func parseGetArgs(args []string, getenv environmentLookup) (getArgs, error) {
	var result getArgs
	var positionals []string
	var password, passwordFile string
	var passwordSet, passwordFileSet bool
	for index := 0; index < len(args); index++ {
		token := args[index]
		if token == "--" {
			positionals = append(positionals, args[index+1:]...)
			break
		}
		if !strings.HasPrefix(token, "--") {
			positionals = append(positionals, token)
			continue
		}
		name, value, hasValue := splitFlag(token)
		if name == "--json" {
			if hasValue {
				return getArgs{}, fmt.Errorf("flag --json does not accept a value")
			}
			continue
		}
		if name != "--server" && name != "--output" &&
			name != "--password" && name != "--password-file" {
			return getArgs{}, fmt.Errorf("unknown flag: %s", name)
		}
		if !hasValue {
			index++
			if index >= len(args) {
				return getArgs{}, fmt.Errorf("flag %s requires a value", name)
			}
			value = args[index]
		}
		switch name {
		case "--server":
			result.server = value
		case "--output":
			result.output = value
		case "--password":
			password = value
			passwordSet = true
		case "--password-file":
			passwordFile = value
			passwordFileSet = true
		}
	}
	if len(positionals) != 1 {
		return getArgs{}, fmt.Errorf("get requires one share code or URL")
	}
	result.target = positionals[0]
	if result.server == "" {
		result.server = strings.TrimSpace(getenv("CLOUDFLARE_DROP_URL"))
	}
	resolvedPassword, err := resolvePassword(
		password,
		passwordSet,
		passwordFile,
		passwordFileSet,
		getenv,
	)
	if err != nil {
		return getArgs{}, err
	}
	result.password = resolvedPassword
	return result, nil
}

func splitFlag(token string) (name, value string, hasValue bool) {
	name, value, found := strings.Cut(token, "=")
	return name, value, found
}

func resolvePassword(
	direct string,
	directSet bool,
	passwordFile string,
	passwordFileSet bool,
	getenv environmentLookup,
) (string, error) {
	if directSet && passwordFileSet {
		return "", fmt.Errorf("--password and --password-file cannot be combined")
	}
	password := ""
	switch {
	case directSet:
		password = direct
	case passwordFileSet:
		content, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("read password file: %w", err)
		}
		password = string(content)
		password = strings.TrimSuffix(password, "\r\n")
		password = strings.TrimSuffix(password, "\n")
	default:
		password = getenv("CLOUDFLARE_DROP_PASSWORD")
	}
	if (directSet || passwordFileSet) && password == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return password, nil
}
