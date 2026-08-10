package dropclient

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	ErrInvalidServer     = errors.New("invalid Cloudflare Drop server URL")
	ErrInsecureServer    = errors.New("Cloudflare Drop server must use HTTPS")
	ErrInvalidTarget     = errors.New("invalid Cloudflare Drop share code or URL")
	ErrMissingServer     = errors.New("Cloudflare Drop server URL is required")
	ErrConflictingServer = errors.New("share URL conflicts with explicit server")
)

type Target struct {
	Server *url.URL
	Code   string
}

func ResolveServer(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" || parsed.Host == "" {
		return nil, ErrInvalidServer
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, ErrInvalidServer
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.RawPath != "" {
		return nil, ErrInvalidServer
	}
	if parsed.Scheme == "http" && !isLocalHostname(parsed.Hostname()) {
		return nil, ErrInsecureServer
	}
	parsed.Path = ""
	parsed.RawPath = ""
	parsed.ForceQuery = false
	return parsed, nil
}

func ResolveTarget(input, explicitServer, environmentServer string) (Target, error) {
	input = strings.TrimSpace(input)
	if isShareCode(input) {
		serverValue := strings.TrimSpace(explicitServer)
		if serverValue == "" {
			serverValue = strings.TrimSpace(environmentServer)
		}
		if serverValue == "" {
			return Target{}, ErrMissingServer
		}
		server, err := ResolveServer(serverValue)
		if err != nil {
			return Target{}, err
		}
		return Target{Server: server, Code: input}, nil
	}

	shareURL, err := url.Parse(input)
	if err != nil || !shareURL.IsAbs() || shareURL.Opaque != "" ||
		shareURL.User != nil || shareURL.Fragment != "" ||
		(shareURL.Path != "" && shareURL.Path != "/") || shareURL.RawPath != "" {
		return Target{}, ErrInvalidTarget
	}
	query := shareURL.Query()
	if len(query) != 1 || len(query["code"]) != 1 || !isShareCode(query.Get("code")) {
		return Target{}, ErrInvalidTarget
	}
	server, err := ResolveServer((&url.URL{
		Scheme: shareURL.Scheme,
		Host:   shareURL.Host,
	}).String())
	if err != nil {
		return Target{}, err
	}
	if strings.TrimSpace(explicitServer) != "" {
		explicit, err := ResolveServer(explicitServer)
		if err != nil {
			return Target{}, err
		}
		if explicit.String() != server.String() {
			return Target{}, ErrConflictingServer
		}
	}
	return Target{Server: server, Code: query.Get("code")}, nil
}

func isShareCode(value string) bool {
	if len(value) != 6 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func isLocalHostname(hostname string) bool {
	switch strings.ToLower(hostname) {
	case "localhost", "127.0.0.1", "::1":
		return true
	default:
		return false
	}
}

func ShareURL(server *url.URL, code string) string {
	result := *server
	result.Path = "/"
	query := url.Values{}
	query.Set("code", code)
	result.RawQuery = query.Encode()
	return result.String()
}

func validateCode(code string) error {
	if !isShareCode(code) {
		return fmt.Errorf("%w: share code must contain six digits", ErrInvalidTarget)
	}
	return nil
}
