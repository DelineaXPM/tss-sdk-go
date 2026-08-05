package server

import (
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"strings"
)

const errorBodyLength = 255

// defaultMaxResponseBytes bounds how much of an API response body the SDK will read
// into memory, so a compromised or misdirected endpoint cannot exhaust memory with an
// arbitrarily large response. File attachments download through handleResponse, so the
// cap must stay comfortably above Secret Server's attachment size limit: the default
// is 10MB (fixed on Secret Server Cloud), and Delinea's hardening guidance recommends
// at most 30MB. An on-premises server configured beyond 100 MiB needs
// Configuration.MaxResponseBytes. An oversized response is an error, never a silent
// truncation.
const defaultMaxResponseBytes = 100 << 20

const (
	maxAuthenticationResponseBytes = 1 << 20
	maxMetadataResponseBytes       = 10 << 20
)

// HTTPError is returned for a non-2xx HTTP response. Error retains the historical
// "<status>: <body>" form for callers that display it, while StatusCode lets callers
// make decisions without parsing error strings. Body is bounded and has control
// characters replaced to prevent an upstream response from injecting log lines.
type HTTPError struct {
	StatusCode int
	Status     string
	Body       string
	RetryAfter string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s: %s", e.Status, e.Body)
}

// maxResponseBytes returns the response-body cap for this Server: the configured
// MaxResponseBytes when positive, otherwise defaultMaxResponseBytes. The cap is
// clamped below math.MaxInt64 because handleResponse reads limit+1 bytes to detect an
// oversized body; without room for that sentinel byte the addition would overflow and
// every response would read as empty.
func (s Server) maxResponseBytes() int64 {
	if s.MaxResponseBytes > 0 {
		if s.MaxResponseBytes == math.MaxInt64 {
			return math.MaxInt64 - 1
		}
		return s.MaxResponseBytes
	}
	return defaultMaxResponseBytes
}

// handleResponse processes the response according to the HTTP status
func (s Server) handleResponse(res *http.Response, err error) ([]byte, *http.Response, error) {
	return s.handleResponseWithLimit(res, err, s.maxResponseBytes())
}

func (s Server) handleResponseWithLimit(res *http.Response, err error, limit int64) ([]byte, *http.Response, error) {
	if err != nil { // fall-through if there was an underlying err
		return nil, res, err
	}
	if res == nil {
		return nil, nil, fmt.Errorf("HTTP request returned neither a response nor an error")
	}
	defer res.Body.Close()

	data, err := ioutil.ReadAll(io.LimitReader(res.Body, limit+1))

	if err != nil {
		return nil, res, err
	}

	if int64(len(data)) > limit {
		return nil, res, fmt.Errorf("response body exceeded %d bytes", limit)
	}

	// if the response was 2xx then return it, otherwise, consider it an error
	if res.StatusCode > 199 && res.StatusCode < 300 {
		return data, res, nil
	}

	// truncate the data to errorBodyLength bytes before returning it as part of the error
	if len(data) >= errorBodyLength {
		data = append(data[:errorBodyLength], []byte("...")...)
	}

	return nil, res, &HTTPError{
		StatusCode: res.StatusCode,
		Status:     res.Status,
		Body:       sanitizeDiagnostic(string(data)),
		RetryAfter: res.Header.Get("Retry-After"),
	}
}

func sanitizeDiagnostic(value string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == '\u007f' {
			return ' '
		}
		return r
	}, value)
}
