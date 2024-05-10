package server

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

const errorBodyLength = 255

// handleResponse processes the response according to the HTTP status
func handleResponse(res *http.Response, err error) ([]byte, *http.Response, error) {
	if err != nil { // fall-through if there was an underlying err
		return nil, res, err
	}

	data, err := ioutil.ReadAll(res.Body)

	if err != nil {
		return nil, res, err
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
