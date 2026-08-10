package cli

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Response struct {
	OK        bool       `json:"ok"`
	Operation string     `json:"operation,omitempty"`
	Version   string     `json:"version,omitempty"`
	Error     *ErrorBody `json:"error,omitempty"`
}

const (
	ExitOK        = 0
	ExitUsage     = 2
	ExitNetwork   = 3
	ExitIntegrity = 4
)
