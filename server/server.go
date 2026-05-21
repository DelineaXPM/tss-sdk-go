package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	cloudBaseURLTemplate string = "https://%s.secretservercloud.%s/"
	defaultAPIPathURI    string = "/api/v1"
	defaultTokenPathURI  string = "/oauth2/token"
	defaultTLD           string = "com"
)

// Logger is an interface for logging in the SDK. It matches the standard log package interface.
// Consumers can provide their own implementation to customize logging behavior.
type Logger interface {
	Printf(format string, v ...interface{})
	Print(v ...interface{})
	Println(v ...interface{})
}

// DiscardLogger is a Logger implementation that discards all output (no-op).
// Use this to completely disable logging from the SDK.
type DiscardLogger struct{}

func (d *DiscardLogger) Printf(format string, v ...interface{}) {
	// Intentionally empty - DiscardLogger is a no-op implementation
}

func (d *DiscardLogger) Print(v ...interface{}) {
	// Intentionally empty - DiscardLogger is a no-op implementation
}

func (d *DiscardLogger) Println(v ...interface{}) {
	// Intentionally empty - DiscardLogger is a no-op implementation
}

// stdLogger wraps the standard log package and implements the Logger interface
type stdLogger struct{}

func (s *stdLogger) Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

func (s *stdLogger) Print(v ...interface{}) {
	log.Print(v...)
}

func (s *stdLogger) Println(v ...interface{}) {
	log.Println(v...)
}

// defaultLoggerInstance is the default logger used when no Logger is configured.
// Following Go library conventions, logging is disabled by default.
// To enable logging, set Configuration.Logger to log.Default() or a custom logger.
var defaultLoggerInstance Logger = &DiscardLogger{}

// UserCredential holds the username and password that the API should use to
// authenticate to the REST API
type UserCredential struct {
	Domain, Username, Password, Token string
}

// Configuration settings for the API
type Configuration struct {
	Credentials                                      UserCredential
	ServerURL, TLD, Tenant, apiPathURI, tokenPathURI string
	TLSClientConfig                                  *tls.Config
	Logger                                           Logger
}

// Server provides access to secrets stored in Delinea Secret Server
type Server struct {
	Configuration
}

type TokenCache struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// New returns an initialized Secrets object
func New(config Configuration) (*Server, error) {
	if config.ServerURL == "" && config.Tenant == "" || config.ServerURL != "" && config.Tenant != "" {
		return nil, fmt.Errorf("either ServerURL of Secret Server/Platform or Tenant of Secret Server Cloud must be set")
	}
	if config.TLD == "" {
		config.TLD = defaultTLD
	}
	if config.TLSClientConfig != nil {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = config.TLSClientConfig
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

// log returns the logger to use for this Server. If no Logger is configured,
// it returns the default logger that uses the standard log package.
func (s *Server) log() Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return defaultLoggerInstance
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
		return fmt.Sprintf("%s/%s",
			strings.Trim(baseURL, "/"),
			strings.Trim(s.tokenPathURI, "/"))
	default:
		return fmt.Sprintf("%s/%s/%s/%s",
			strings.Trim(baseURL, "/"),
			strings.Trim(s.apiPathURI, "/"),
			strings.Trim(resource, "/"),
			strings.Trim(path, "/"))
	}
}

func (s Server) urlForSearch(resource, searchText, fieldName string) string {
	var baseURL string

	if s.ServerURL == "" {
		baseURL = fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	} else {
		baseURL = s.ServerURL
	}
	switch {
	case resource == "secrets":
		url := fmt.Sprintf("%s/%s/%s?paging.filter.searchText=%s&paging.filter.searchField=%s&paging.filter.doNotCalculateTotal=true&paging.take=30&&paging.skip=0",
			strings.Trim(baseURL, "/"),
			strings.Trim(s.apiPathURI, "/"),
			strings.Trim(resource, "/"),
			searchText,
			fieldName)
		if fieldName == "" {
			return fmt.Sprintf("%s%s", url, "&paging.filter.extendedFields=Machine&paging.filter.extendedFields=Notes&paging.filter.extendedFields=Username")
		}
		return fmt.Sprintf("%s%s", url, "&paging.filter.isExactMatch=true")
	default:
		return ""
	}
}

// accessResource uses the accessToken to access the API resource.
// It assumes an appropriate combination of method, resource, path and input.
// ctx controls cancellation and deadlines for all HTTP requests made within this call.
func (s Server) accessResource(ctx context.Context, method, resource, path string, input interface{}) ([]byte, error) {
	switch resource {
	case "secrets":
	case "secret-templates":
	default:
		message := "unknown resource"

		s.log().Printf("[ERROR] %s: %s", message, resource)
		return nil, fmt.Errorf(message)
	}

	body := bytes.NewBuffer([]byte{})

	if input != nil {
		if data, err := json.Marshal(input); err == nil {
			body = bytes.NewBuffer(data)
		} else {
			s.log().Print("[ERROR] marshaling the request body to JSON:", err)
			return nil, err
		}
	}

	accessToken, err := s.getAccessToken(ctx)

	if err != nil {
		s.log().Print("[ERROR] error getting accessToken:", err)
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, s.urlFor(resource, path), body)

	if err != nil {
		s.log().Printf("[ERROR] creating req: %s /%s/%s: %s", method, resource, path, err)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	switch method {
	case "POST", "PUT", "PATCH":
		req.Header.Set("Content-Type", "application/json")
	}

	s.log().Printf("[DEBUG] calling %s %s", method, req.URL.String())

	data, statusCode, err := handleResponse((&http.Client{}).Do(req))

	// Check for unauthorized or access denied
	if statusCode.StatusCode == http.StatusUnauthorized || statusCode.StatusCode == http.StatusForbidden {
		s.clearTokenCache()
		s.log().Printf("[ERROR] Token cache cleared due to unauthorized or access denied response.")
	}

	return data, err
}

// searchResources uses the accessToken to search for API resources.
// It assumes an appropriate combination of resource, search text.
// field is optional.
// ctx controls cancellation and deadlines for all HTTP requests made within this call.
func (s Server) searchResources(ctx context.Context, resource, searchText, field string) ([]byte, error) {
	switch resource {
	case "secrets":
	default:
		message := "unknown resource"

		s.log().Printf("[ERROR] %s: %s", message, resource)
		return nil, fmt.Errorf(message)
	}

	method := "GET"
	body := bytes.NewBuffer([]byte{})

	accessToken, err := s.getAccessToken(ctx)

	if err != nil {
		s.log().Print("[ERROR] error getting accessToken:", err)
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, s.urlForSearch(resource, searchText, field), body)

	if err != nil {
		s.log().Printf("[ERROR] creating req: %s /%s/%s/%s: %s", method, resource, searchText, field, err)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	s.log().Printf("[DEBUG] calling %s %s", method, req.URL.String())

	data, _, err := handleResponse((&http.Client{}).Do(req))

	return data, err
}

// uploadFile uploads the file described in the given fileField to the
// secret at the given secretId as a multipart/form-data request.
// ctx controls cancellation and deadlines for all HTTP requests made within this call.
func (s Server) uploadFile(ctx context.Context, secretId int, fileField SecretField) error {
	s.log().Printf("[DEBUG] uploading a file to the '%s' field with filename '%s'", fileField.Slug, fileField.Filename)
	body := bytes.NewBuffer([]byte{})
	path := fmt.Sprintf("%d/fields/%s", secretId, fileField.Slug)

	// Fetch the access token
	accessToken, err := s.getAccessToken(ctx)
	if err != nil {
		s.log().Print("[ERROR] error getting accessToken:", err)
		return err
	}

	// Create the multipart form
	multipartWriter := multipart.NewWriter(body)
	filename := fileField.Filename
	if filename == "" {
		filename = "File.txt"
		s.log().Printf("[DEBUG] field has no filename, setting its filename to '%s'", filename)
	} else if match, _ := regexp.Match("[^.]+\\.\\w+$", []byte(filename)); !match {
		filename = filename + ".txt"
		s.log().Printf("[DEBUG] field has no filename extension, setting its filename to '%s'", filename)
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
	req, err := http.NewRequestWithContext(ctx, "PUT", s.urlFor(resource, path), body)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	s.log().Printf("[DEBUG] uploading file with PUT %s", req.URL.String())
	_, _, err = handleResponse((&http.Client{}).Do(req))

	return err
}

func (s *Server) setCacheAccessToken(value string, expiresIn int, baseURL string) error {
	cache := TokenCache{}
	cache.AccessToken = value
	cache.ExpiresIn = (int(time.Now().Unix()) + expiresIn) - int(math.Floor(float64(expiresIn)*0.9))

	data, _ := json.Marshal(cache)
	os.Setenv(s.cacheKey(baseURL), string(data))
	return nil
}

func (s *Server) getCacheAccessToken(baseURL string) (string, bool) {
	// Try the new per-username key first
	data, ok := os.LookupEnv(s.cacheKey(baseURL))
	if ok && data != "" {
		cache := TokenCache{}
		if err := json.Unmarshal([]byte(data), &cache); err == nil {
			if time.Now().Unix() < int64(cache.ExpiresIn) {
				return cache.AccessToken, true
			}
		}
	}
	s.clearTokenCache()
	return "", false
}

func (s *Server) clearTokenCache() {
	var baseURL string

	if s.ServerURL == "" {
		baseURL = fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	} else {
		baseURL = s.ServerURL
	}

	// Clear the new per-username cache key
	os.Setenv(s.cacheKey(baseURL), "")

	// Also clear the legacy cache key to avoid leftover stale tokens
	legacyKey := "SS_AT_" + url.QueryEscape(baseURL)
	os.Setenv(legacyKey, "")
}

// cacheKey returns an environment variable key unique to the base URL and
// credentials (username). This prevents token collisions when multiple Server
// instances use the same ServerURL but different credentials.
func (s *Server) cacheKey(baseURL string) string {
	key := "SS_AT_" + url.QueryEscape(baseURL)
	if s.Credentials.Username != "" {
		key = key + "_" + url.QueryEscape(s.Credentials.Username)
	}
	return key
}

// getAccessToken gets an OAuth2 Access Grant and returns the token
// endpoint and get an accessGrant.
// ctx controls cancellation and deadlines for all HTTP requests made within this call.
func (s *Server) getAccessToken(ctx context.Context) (string, error) {
	if s.Credentials.Token != "" {
		return s.Credentials.Token, nil
	}
	var baseURL string

	if s.ServerURL == "" {
		baseURL = fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	} else {
		baseURL = s.ServerURL
	}

	response, err := s.checkPlatformDetails(ctx, baseURL)
	if err != nil {
		s.log().Print("Error while checking server details:", err)
		return "", err
	}

	if response == "" {
		accessToken, found := s.getCacheAccessToken(baseURL)
		if found {
			return accessToken, nil
		}

		values := url.Values{
			"username":   {s.Credentials.Username},
			"password":   {s.Credentials.Password},
			"grant_type": {"password"},
		}
		if s.Credentials.Domain != "" {
			values["domain"] = []string{s.Credentials.Domain}
		}

		requestUrl := s.urlFor("token", "")

		// Use NewRequestWithContext so the caller's context (deadlines, cancellation) is honoured.
		req, err := http.NewRequestWithContext(ctx, "POST", requestUrl, strings.NewReader(values.Encode()))
		if err != nil {
			s.log().Print("[ERROR] creating request for token endpoint:", err)
			return "", err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		data, _, err := handleResponse((&http.Client{}).Do(req))

		if err != nil {
			s.log().Print("[ERROR] grant response error:", err)
			return "", err
		}

		grant := struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
			TokenType    string `json:"token_type"`
			ExpiresIn    int    `json:"expires_in"`
		}{}

		if err = json.Unmarshal(data, &grant); err != nil {
			s.log().Print("[ERROR] parsing grant response:", err)
			return "", err
		}
		if err = s.setCacheAccessToken(grant.AccessToken, grant.ExpiresIn, baseURL); err != nil {
			s.log().Print("[ERROR] caching access token:", err)
			return "", err
		}
		return grant.AccessToken, nil
	}

	return response, nil
}

func (s *Server) checkPlatformDetails(ctx context.Context, baseURL string) (string, error) {
	platformHelthCheckUrl := fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "health")
	ssHealthCheckUrl := fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "api/v1/healthcheck")

	isHealthy := checkJSONResponse(ctx, ssHealthCheckUrl, s.log())
	if isHealthy {
		return "", nil
	}
	// If the context was cancelled or timed out while probing the health endpoint,
	// propagate that error instead of falling through to "invalid URL".
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", ctxErr
	}

	isHealthy = checkJSONResponse(ctx, platformHelthCheckUrl, s.log())
	if isHealthy {

		accessToken, found := s.getCacheAccessToken(baseURL)
		if !found {
			requestData := url.Values{}
			requestData.Set("grant_type", "client_credentials")
			requestData.Set("client_id", s.Credentials.Username)
			requestData.Set("client_secret", s.Credentials.Password)
			requestData.Set("scope", "xpmheadless")

			req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "identity/api/oauth2/token/xpmplatform"), bytes.NewBufferString(requestData.Encode()))
			if err != nil {
				s.log().Print("Error creating HTTP request:", err)
				return "", err
			}

			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			data, _, err := handleResponse((&http.Client{}).Do(req))
			if err != nil {
				s.log().Print("[ERROR] get token response error:", err)
				return "", err
			}

			var tokenjsonResponse OAuthTokens
			if err = json.Unmarshal(data, &tokenjsonResponse); err != nil {
				s.log().Print("[ERROR] parsing get token response:", err)
				return "", err
			}
			accessToken = tokenjsonResponse.AccessToken

			if err = s.setCacheAccessToken(tokenjsonResponse.AccessToken, tokenjsonResponse.ExpiresIn, baseURL); err != nil {
				s.log().Print("[ERROR] caching access token:", err)
				return "", err
			}
		}

		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "vaultbroker/api/vaults"), bytes.NewBuffer([]byte{}))
		if err != nil {
			s.log().Print("Error creating HTTP request:", err)
			return "", err
		}
		req.Header.Add("Authorization", "Bearer "+accessToken)

		data, _, err := handleResponse((&http.Client{}).Do(req))
		if err != nil {
			s.log().Print("[ERROR] get vaults response error:", err)
			return "", err
		}

		var vaultJsonResponse VaultsResponseModel
		if err = json.Unmarshal(data, &vaultJsonResponse); err != nil {
			s.log().Print("[ERROR] parsing vaults response:", err)
			return "", err
		}

		var vaultURL string
		for _, vault := range vaultJsonResponse.Vaults {
			if vault.IsDefault && vault.IsActive {
				vaultURL = vault.Connection.Url
				break
			}
		}
		if vaultURL != "" {
			s.ServerURL = vaultURL
		} else {
			return "", fmt.Errorf("no configured vault found")
		}

		return accessToken, nil
	}
	// Propagate context errors rather than masking them as "invalid URL".
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", ctxErr
	}
	return "", fmt.Errorf("invalid URL")
}

// checkJSONResponse makes a GET request to url and returns true when the
// response body indicates a healthy JSON service.
// ctx controls cancellation and deadlines for the underlying HTTP request.
func checkJSONResponse(ctx context.Context, url string, logger Logger) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		logger.Println("Error creating GET request:", err)
		return false
	}

	response, err := (&http.Client{}).Do(req)
	if err != nil {
		logger.Println("Error making GET request:", err)
		return false
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		logger.Println("Error reading response body:", err)
		return false
	}

	var jsonResponse Response
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		return jsonResponse.Healthy
	} else {
		return strings.Contains(string(body), "Healthy")
	}
}

type Response struct {
	Healthy               bool `json:"healthy"`
	DatabaseHealthy       bool `json:"databaseHealthy"`
	ServiceBusHealthy     bool `json:"serviceBusHealthy"`
	StorageAccountHealthy bool `json:"storageAccountHealthy"`
	ScheduledForDeletion  bool `json:"scheduledForDeletion"`
}

type OAuthTokens struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IdToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	SessionExpiresIn int    `json:"session_expires_in"`
	Scope            string `json:"scope"`
}

type Connection struct {
	Url            string `json:"url"`
	OAuthProfileId string `json:"oAuthProfileId"`
}

type Vault struct {
	VaultId         string     `json:"vaultId"`
	Name            string     `json:"name"`
	Type            string     `json:"type"`
	IsDefault       bool       `json:"isDefault"`
	IsGlobalDefault bool       `json:"isGlobalDefault"`
	IsActive        bool       `json:"isActive"`
	Connection      Connection `json:"connection"`
}

type VaultsResponseModel struct {
	Vaults []Vault `json:"vaults"`
}
