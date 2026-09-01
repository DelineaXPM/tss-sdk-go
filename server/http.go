package server

import (
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	delinea "github.com/DelineaXPM/delinea-common/api"
)

const errorBodyLength = 255
const withheldDiagnostic = "(response body withheld because the request contained sensitive data)"

// HTTPError is returned for a non-2xx response. Error retains the historical
// "<status>: <body>" form while exposing structured status information.
type HTTPError struct {
	StatusCode int
	Status     string
	Body       string
	RetryAfter string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("%s: %s", e.Status, e.Body) }

func handleBufferedResponse(response *delinea.BufferedResponse, limit int64, withholdDiagnostic bool) ([]byte, error) {
	if response == nil {
		return nil, fmt.Errorf("HTTP request returned neither a response nor an error")
	}
	oversize := int64(len(response.Body)) > limit
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if oversize {
			return nil, fmt.Errorf("response body exceeded %d bytes", limit)
		}
		return response.Body, nil
	}
	status := fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode))
	status = strings.TrimSpace(status)
	diagnostic := withheldDiagnostic
	if !withholdDiagnostic {
		diagnostic = truncateDiagnostic(response.DiagnosticSnippet(), errorBodyLength)
	}
	if oversize {
		diagnostic += fmt.Sprintf(" (response body exceeded %d bytes)", limit)
	}
	return nil, &HTTPError{
		StatusCode: response.StatusCode,
		Status:     status,
		Body:       diagnostic,
		RetryAfter: response.Header.Get("Retry-After"),
	}
}

func truncateDiagnostic(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if unsafeRecordRune(r) {
			return ' '
		}
		return r
	}, value)
	if len(value) > limit {
		end := limit
		for end > 0 && !utf8.RuneStart(value[end]) {
			end--
		}
		return value[:end] + "..."
	}
	return value
}
