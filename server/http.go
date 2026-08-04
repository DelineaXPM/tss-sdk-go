package server

import (
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
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
	if err != nil { // fall-through if there was an underlying err
		return nil, res, err
	}
	defer res.Body.Close()

	limit := s.maxResponseBytes()
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

	return nil, res, fmt.Errorf("%s: %s", res.Status, string(data))
}
