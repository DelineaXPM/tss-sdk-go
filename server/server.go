package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	apiPathURI           string = "/api/v1"
	tokenPathURI         string = "/oauth2/token"
	cloudBaseURLTemplate string = "https://%s.secretservercloud.com"
)

// Configuration settings for the API
type Configuration struct {
	Username, Password, ServerURL, Tenant string
}

// Server provides access to secrets stored in Thycotic Secret Server
type Server struct {
	config Configuration
}

// New returns an initialized Secrets object
func New(config Configuration) *Server {
	return &Server{config}
}

// baseURL constructs the base URL of the server by either returning the
// interpolation of the configured tenant into the cloudBaseURLTemplate,
// or returning the configured server_url
func baseURL(config Configuration) string {
	if config.Tenant != "" {
		return fmt.Sprintf(cloudBaseURLTemplate, config.Tenant)
	}
	return strings.TrimRight(config.ServerURL, "/")
}

// accessResource uses the accessToken to access the API resource.
// It assumes an appropriate combination of method, resource, path and input.
func accessResource(method, resource, path string, input interface{}, config Configuration) ([]byte, error) {
	switch resource {
	case "secrets":
	default:
		message := "unknown resource"

		log.Printf("[DEBUG] %s: %s", message, resource)
		return nil, fmt.Errorf(message)
	}

	url := fmt.Sprintf("%s/%s/%s/%s", baseURL(config), apiPathURI, resource, strings.TrimLeft(path, "/"))
	body := bytes.NewBuffer([]byte{})

	if input != nil {
		if data, err := json.Marshal(input); err == nil {
			body = bytes.NewBuffer(data)
		} else {
			log.Print("[DEBUG] marshaling the request body to JSON:", err)
			return nil, err
		}
	}

	req, err := http.NewRequest(method, url, body)

	if err != nil {
		log.Printf("[DEBUG] creating req: %s /%s/%s: %s", method, resource, path, err)
		return nil, err
	}

	accessToken, err := getAccessToken(config)

	if err != nil {
		log.Print("[DEBUG] error getting accessToken:", err)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	switch method {
	case "POST", "PUT":
		req.Header.Set("Content-Type", "application/json")
	}

	log.Printf("[DEBUG] calling %s", req.URL.String())

	data, _, err := handleResponse((&http.Client{}).Do(req))

	return data, err
}

// accessGrant is the response of a successful getAccessToken call
type accessGrant struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// grant is the (cached) accessGrant
var grant *accessGrant // TODO proper caching and expiration checking

// getAccessToken uses the username and password, to call the token
// endpoint and get an accessGrant.
func getAccessToken(config Configuration) (string, error) {
	if grant != nil {
		return grant.AccessToken, nil
	}

	endpoint := baseURL(config) + tokenPathURI

	log.Printf("[DEBUG] calling %s as %s", endpoint, config.Username)

	body := strings.NewReader(url.Values{
		"username":   {config.Username},
		"password":   {config.Password},
		"grant_type": {"password"},
	}.Encode())
	data, _, err := handleResponse(http.Post(endpoint, "application/x-www-form-urlencoded", body))

	if err != nil {
		log.Print("[DEBUG] grant response error:", err)
		return "", err
	}

	newGrant := new(accessGrant)

	if err = json.Unmarshal(data, &newGrant); err != nil {
		log.Print("[INFO] parsing grant response:", err)
		return "", err
	}

	grant = newGrant

	return grant.AccessToken, nil
}

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

	// truncate the data to 64 bytes before returning it as part of the error
	if len(data) > 64 {
		data = append(data[:64], []byte("...")...)
	}

	return nil, res, fmt.Errorf("%s: %s", res.Status, string(data))
}
