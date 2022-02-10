package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	cloudBaseURLTemplate string = "https://%s.secretservercloud.%s/"
	defaultAPIPathURI    string = "/api/v1"
	defaultTokenPathURI  string = "/oauth2/token"
	defaultTLD           string = "com"
)

// UserCredential holds the username and password that the API should use to
// authenticate to the REST API
type UserCredential struct {
	Username, Password string
}

// Configuration settings for the API
type Configuration struct {
	Credentials                                      UserCredential
	ServerURL, TLD, Tenant, apiPathURI, tokenPathURI string
}

// Server provides access to secrets stored in Thycotic Secret Server
type Server struct {
	Configuration
}

// New returns an initialized Secrets object
func New(config Configuration) (*Server, error) {
	if config.ServerURL == "" && config.Tenant == "" || config.ServerURL != "" && config.Tenant != "" {
		return nil, fmt.Errorf("either ServerURL or Tenant must be set")
	}
	if config.TLD == "" {
		config.TLD = defaultTLD
	}
	if config.apiPathURI == "" {
		config.apiPathURI = defaultAPIPathURI
	}
	config.apiPathURI = strings.Trim(config.apiPathURI, "/")
	if config.tokenPathURI == "" {
		config.tokenPathURI = defaultTokenPathURI
	}
	config.tokenPathURI = strings.Trim(config.tokenPathURI, "/")
	return &Server{config}, nil
}

// urlFor is the URL for the given resource and path
func (s Server) urlFor(resource, path string) string {
	var baseURL string

	if s.ServerURL == "" {
		baseURL = fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	} else {
		baseURL = s.ServerURL
	}

	switch {
	case resource == "token":
		return fmt.Sprintf("%s/%s", baseURL, s.tokenPathURI)
	default:
		return fmt.Sprintf("%s/%s/%s/%s",
			strings.Trim(baseURL, "/"),
			strings.Trim(s.apiPathURI, "/"),
			strings.Trim(resource, "/"),
			strings.Trim(path, "/"))
	}
}

// accessResource uses the accessToken to access the API resource.
// It assumes an appropriate combination of method, resource, path and input.
func (s Server) accessResource(method, resource, path string, input interface{}) ([]byte, error) {
	switch resource {
	case "secrets":
	case "secret-templates":
	default:
		message := "unknown resource"

		log.Printf("[ERROR] %s: %s", message, resource)
		return nil, fmt.Errorf(message)
	}

	body := bytes.NewBuffer([]byte{})

	if input != nil {
		if data, err := json.Marshal(input); err == nil {
			body = bytes.NewBuffer(data)
		} else {
			log.Print("[ERROR] marshaling the request body to JSON:", err)
			return nil, err
		}
	}

	req, err := http.NewRequest(method, s.urlFor(resource, path), body)

	if err != nil {
		log.Printf("[ERROR] creating req: %s /%s/%s: %s", method, resource, path, err)
		return nil, err
	}

	accessToken, err := s.getAccessToken()

	if err != nil {
		log.Print("[ERROR] error getting accessToken:", err)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	switch method {
	case "POST", "PUT", "PATCH":
		req.Header.Set("Content-Type", "application/json")
	}

	log.Printf("[DEBUG] calling %s %s", method, req.URL.String())

	data, _, err := handleResponse((&http.Client{}).Do(req))

	return data, err
}

// uploadFile uploads the file described in the given fileField to the
// secret at the given secretId as a multipart/form-data request.
func (s Server) uploadFile(secretId int, fileField SecretField) error {
	log.Printf("[DEBUG] uploading a file to the '%s' field with filename '%s'", fileField.Slug, fileField.Filename)
	body := bytes.NewBuffer([]byte{})
	path := fmt.Sprintf("%d/fields/%s", secretId, fileField.Slug)

	// Fetch the access token
	accessToken, err := s.getAccessToken()
	if err != nil {
		log.Print("[ERROR] error getting accessToken:", err)
		return err
	}

	// Create the multipart form
	multipartWriter := multipart.NewWriter(body)
	filename := fileField.Filename
	if filename == "" {
		filename = "File.txt"
		log.Printf("[DEBUG] field has no filename, setting its filename to '%s'", filename)
	} else if match, _ := regexp.Match("[^.]+\\.\\w+$", []byte(filename)); !match {
		filename = filename + ".txt"
		log.Printf("[DEBUG] field has no filename extension, setting its filename to '%s'", filename)
	}
	form, err := multipartWriter.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	_, err = io.Copy(form, strings.NewReader(fileField.ItemValue))
	if err != nil {
		return err
	}
	err = multipartWriter.Close()
	if err != nil {
		return err
	}

	// Make the request
	req, err := http.NewRequest("PUT", s.urlFor(resource, path), body)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer " + accessToken)
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	log.Printf("[DEBUG] uploading file with PUT %s", req.URL.String())
	_, _, err = handleResponse((&http.Client{}).Do(req))

	return err
}

// getAccessToken gets an OAuth2 Access Grant and returns the token
// endpoint and get an accessGrant.
func (s Server) getAccessToken() (string, error) {
	body := strings.NewReader(url.Values{
		"username":   {s.Credentials.Username},
		"password":   {s.Credentials.Password},
		"grant_type": {"password"},
	}.Encode())
	data, _, err := handleResponse(http.Post(s.urlFor("token", ""), "application/x-www-form-urlencoded", body))

	if err != nil {
		log.Print("[ERROR] grant response error:", err)
		return "", err
	}

	grant := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
	}{}

	if err = json.Unmarshal(data, &grant); err != nil {
		log.Print("[ERROR] parsing grant response:", err)
		return "", err
	}
	return grant.AccessToken, nil
}
