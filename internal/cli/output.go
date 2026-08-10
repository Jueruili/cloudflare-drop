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

type UploadResponse struct {
	OK        bool    `json:"ok"`
	Operation string  `json:"operation"`
	Code      string  `json:"code"`
	URL       string  `json:"url"`
	Encrypted bool    `json:"encrypted"`
	Ephemeral bool    `json:"ephemeral"`
	Password  *string `json:"password"`
	ExpiresAt *string `json:"expiresAt"`
}

type GetResponse struct {
	OK        bool   `json:"ok"`
	Operation string `json:"operation"`
	Code      string `json:"code"`
	Encrypted bool   `json:"encrypted"`
	Kind      string `json:"kind"`
	Text      string `json:"text,omitempty"`
	Path      string `json:"path,omitempty"`
	Filename  string `json:"filename,omitempty"`
	Type      string `json:"type,omitempty"`
	Size      int64  `json:"size"`
}

type commandError struct {
	exitCode int
	code     string
	message  string
}

func (err *commandError) Error() string { return err.message }

const (
	ExitOK        = 0
	ExitUsage     = 2
	ExitNetwork   = 3
	ExitIntegrity = 4
)
