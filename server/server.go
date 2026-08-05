package server

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
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
	// Timeout, when non-zero, bounds each HTTP request made by the Server.
	// A zero value keeps the previous behavior of no client-imposed timeout.
	Timeout time.Duration
}

// Server provides access to secrets stored in Delinea Secret Server
type Server struct {
	Configuration
	httpClient *http.Client
}

type TokenCache struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// tokenCache holds cached access tokens in process memory, keyed by cacheKey.
// It replaces the previous os.Setenv-based cache: storing a bearer token in the
// process environment exposed it to child processes and any reader of the
// process environment (CWE-526). An in-memory store keeps the intra-process
// reuse and the per-URL/per-credential collision keying without that exposure.
var (
	tokenCacheMu sync.Mutex
	tokenCache   = map[string]TokenCache{}
)

// New returns an initialized Secrets object
func New(config Configuration) (*Server, error) {
	if config.ServerURL == "" && config.Tenant == "" || config.ServerURL != "" && config.Tenant != "" {
		return nil, fmt.Errorf("either ServerURL of Secret Server/Platform or Tenant of Secret Server Cloud must be set")
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
	return &Server{Configuration: config, httpClient: newHTTPClient(config)}, nil
}

// newHTTPClient builds an *http.Client scoped to a single Server. A caller-supplied
// TLSClientConfig is applied to a fresh transport that copies http.DefaultTransport's
// tuning, so the process-global transport is never mutated. Mutating it would change TLS
// verification for all other HTTPS traffic in the process (CWE-295), race with concurrent
// use, and panic if the default transport had been replaced with a non-*http.Transport.
// (We copy the default's fields rather than calling Clone(), because Clone() forces the
// default transport's one-time HTTP/2 initialization, which itself writes to the global.)
// It returns nil when no per-Server client is needed, in which case the Server falls back
// to http.DefaultClient.
func newHTTPClient(config Configuration) *http.Client {
	if config.TLSClientConfig == nil && config.Timeout == 0 {
		return nil
	}
	client := &http.Client{Timeout: config.Timeout}
	if config.TLSClientConfig != nil {
		transport := &http.Transport{}
		if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
			transport.Proxy = defaultTransport.Proxy
			transport.DialContext = defaultTransport.DialContext
			transport.ForceAttemptHTTP2 = defaultTransport.ForceAttemptHTTP2
			transport.MaxIdleConns = defaultTransport.MaxIdleConns
			transport.IdleConnTimeout = defaultTransport.IdleConnTimeout
			transport.TLSHandshakeTimeout = defaultTransport.TLSHandshakeTimeout
			transport.ExpectContinueTimeout = defaultTransport.ExpectContinueTimeout
		}
		transport.TLSClientConfig = config.TLSClientConfig
		client.Transport = transport
	}
	return client
}

// client returns the per-Server HTTP client, or http.DefaultClient when the Server
// was configured with neither a TLSClientConfig nor a Timeout.
func (s Server) client() *http.Client {
	if s.httpClient != nil {
		return s.httpClient
	}
	return http.DefaultClient
}

// log returns the logger to use for this Server. If no Logger is configured,
// it returns the default logger that uses the standard log package.
func (s *Server) log() Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return defaultLoggerInstance
}

// baseURL is the root URL of the Secret Server this Server talks to: the configured
// ServerURL, or the URL derived from the Secret Server Cloud tenant when no ServerURL
// is set. New guarantees exactly one of the two is configured.
func (s Server) baseURL() string {
	if s.ServerURL == "" {
		return fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	}
	return s.ServerURL
}

// urlFor is the URL for the given resource and path
func (s Server) urlFor(resource, path string) string {
	baseURL := s.baseURL()

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
	baseURL := s.baseURL()
	switch {
	case resource == "secrets":
		// Build the query with url.Values so searchText/fieldName are encoded and
		// cannot inject or override query parameters (e.g. a searchText of
		// "foo&paging.take=100000").
		query := url.Values{}
		query.Set("paging.filter.searchText", searchText)
		query.Set("paging.filter.searchField", fieldName)
		query.Set("paging.filter.doNotCalculateTotal", "true")
		query.Set("paging.take", "30")
		query.Set("paging.skip", "0")
		if fieldName == "" {
			query.Add("paging.filter.extendedFields", "Machine")
			query.Add("paging.filter.extendedFields", "Notes")
			query.Add("paging.filter.extendedFields", "Username")
		} else {
			query.Set("paging.filter.isExactMatch", "true")
		}
		return fmt.Sprintf("%s/%s/%s?%s",
			strings.Trim(baseURL, "/"),
			strings.Trim(s.apiPathURI, "/"),
			strings.Trim(resource, "/"),
			query.Encode())
	default:
		return ""
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

		s.log().Printf("[ERROR] %s: %s", message, resource)
		return nil, fmt.Errorf("%s", message)
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

	// The base URL that keys the token cache, captured before getAccessToken runs,
	// since Platform discovery rewrites ServerURL to the vault it found.
	tokenBaseURL := s.baseURL()

	accessToken, err := s.getAccessToken()

	if err != nil {
		s.log().Print("[ERROR] error getting accessToken:", err)
		return nil, err
	}

	req, err := http.NewRequest(method, s.urlFor(resource, path), body)

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

	data, statusCode, err := handleResponse(s.client().Do(req))

	s.evictOnAuthFailure(statusCode, tokenBaseURL)

	return data, err
}

// evictOnAuthFailure drops the cached token when the server rejects a request as
// unauthorized or forbidden, so the next call re-authenticates instead of replaying a
// token the server no longer honors. res is nil on a transport error. tokenBaseURL must
// be the base URL captured before getAccessToken ran, since against a Platform,
// discovery rewrites ServerURL to the vault it found.
func (s Server) evictOnAuthFailure(res *http.Response, tokenBaseURL string) {
	if res == nil || (res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden) {
		return
	}
	s.clearTokenCacheFor(tokenBaseURL)
	s.log().Printf("[ERROR] Token cache cleared due to unauthorized or access denied response.")
}

// searchResources uses the accessToken to search for API resources.
// It assumes an appropriate combination of resource, search text.
// field is optional
func (s Server) searchResources(resource, searchText, field string) ([]byte, error) {
	switch resource {
	case "secrets":
	default:
		message := "unknown resource"

		s.log().Printf("[ERROR] %s: %s", message, resource)
		return nil, fmt.Errorf("%s", message)
	}

	method := "GET"
	body := bytes.NewBuffer([]byte{})

	tokenBaseURL := s.baseURL()

	accessToken, err := s.getAccessToken()

	if err != nil {
		s.log().Print("[ERROR] error getting accessToken:", err)
		return nil, err
	}

	req, err := http.NewRequest(method, s.urlForSearch(resource, searchText, field), body)

	if err != nil {
		s.log().Printf("[ERROR] creating req: %s /%s/%s/%s: %s", method, resource, searchText, field, err)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

	s.log().Printf("[DEBUG] calling %s %s", method, req.URL.String())

	data, statusCode, err := handleResponse(s.client().Do(req))

	s.evictOnAuthFailure(statusCode, tokenBaseURL)

	return data, err
}

// uploadFile uploads the file described in the given fileField to the
// secret at the given secretId as a multipart/form-data request.
func (s Server) uploadFile(secretId int, fileField SecretField) error {
	s.log().Printf("[DEBUG] uploading a file to the '%s' field with filename '%s'", fileField.Slug, fileField.Filename)
	body := bytes.NewBuffer([]byte{})
	path := fmt.Sprintf("%d/fields/%s", secretId, url.PathEscape(fileField.Slug))

	tokenBaseURL := s.baseURL()

	// Fetch the access token
	accessToken, err := s.getAccessToken()
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
	req, err := http.NewRequest("PUT", s.urlFor(resource, path), body)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	s.log().Printf("[DEBUG] uploading file with PUT %s", req.URL.String())
	_, statusCode, err := handleResponse(s.client().Do(req))

	s.evictOnAuthFailure(statusCode, tokenBaseURL)

	return err
}

func (s *Server) setCacheAccessToken(value string, expiresIn int, baseURL string) error {
	cache := TokenCache{}
	cache.AccessToken = value
	// Serve the cached token for 90% of its lifetime, refreshing before it
	// expires. The previous formula subtracted the 90% instead of the 10%
	// safety margin, so tokens were re-fetched after a tenth of their
	// lifetime, forcing ~10x more credential round trips than necessary.
	cache.ExpiresIn = int(time.Now().Unix()) + int(math.Floor(float64(expiresIn)*0.9))

	tokenCacheMu.Lock()
	// Sweep expired entries while holding the lock: an entry is otherwise deleted
	// only when its exact key is queried again, and a key embeds the credential
	// digest, so entries orphaned by a password rotation would accumulate for the
	// life of the process.
	now := time.Now().Unix()
	for key, entry := range tokenCache {
		if int64(entry.ExpiresIn) <= now {
			delete(tokenCache, key)
		}
	}
	tokenCache[s.cacheKey(baseURL)] = cache
	tokenCacheMu.Unlock()
	return nil
}

func (s *Server) getCacheAccessToken(baseURL string) (string, bool) {
	tokenCacheMu.Lock()
	cache, ok := tokenCache[s.cacheKey(baseURL)]
	tokenCacheMu.Unlock()
	if ok && time.Now().Unix() < int64(cache.ExpiresIn) {
		return cache.AccessToken, true
	}
	// Evict under the key that was just looked up, not under s.baseURL(): after
	// Platform discovery rewrites ServerURL, the two name different entries, and
	// clearing by the current base URL would drop a live token instead of the
	// expired one this miss found.
	s.clearTokenCacheFor(baseURL)
	return "", false
}

func (s *Server) clearTokenCache() {
	s.clearTokenCacheFor(s.baseURL())
}

// clearTokenCacheFor evicts the entry cached under an explicit base URL. Callers that
// evict after a request must use this with the base URL captured *before*
// getAccessToken ran: against a Platform, discovery rewrites ServerURL to the vault it
// found, so s.baseURL() afterwards no longer names the key the token was stored under,
// and clearing by it would leave the rejected token in place.
func (s *Server) clearTokenCacheFor(baseURL string) {
	tokenCacheMu.Lock()
	delete(tokenCache, s.cacheKey(baseURL))
	tokenCacheMu.Unlock()
}

// cacheKey returns an in-memory cache key unique to the base URL and the whole
// credential: domain, username, and a digest of the password. This prevents token
// collisions when multiple Server instances use the same ServerURL but different
// credentials, including two accounts that share a username and differ only by Domain
// (e.g. a local account and a directory account). The first three fields are joined
// with "&", which url.QueryEscape always escapes, and the digest is hex, so no two
// distinct credentials can produce the same key.
//
// The password belongs in the key because a cache hit returns before the grant is
// built, so the password of the Server making the call is never presented to the
// server. Keying without it means a Server whose password is stale, rotated or simply
// wrong is served a token obtained with a different password, so a bad credential
// succeeds and a rotated one is not adopted until the entry expires.
func (s *Server) cacheKey(baseURL string) string {
	return url.QueryEscape(baseURL) +
		"&" + url.QueryEscape(s.Credentials.Domain) +
		"&" + url.QueryEscape(s.Credentials.Username) +
		"&" + passwordDigest(s.Credentials.Password)
}

// passwordDigest reduces a password to something that can key a cache entry without
// being the password: the key lives in a package-level map for the life of the
// process, which is not somewhere a credential should sit in cleartext (the same
// reasoning that moved the token itself out of the environment). The digest is
// unsalted, which is not password storage and is not meant to be: the plaintext is
// already in this process's memory, in Credentials, so the digest adds no exposure it
// does not already have. It exists to distinguish credentials, not to protect them.
func passwordDigest(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

// getAccessToken gets an OAuth2 Access Grant and returns the token
// endpoint and get an accessGrant.
func (s *Server) getAccessToken() (string, error) {
	if s.Credentials.Token != "" {
		return s.Credentials.Token, nil
	}
	baseURL := s.baseURL()

	response, err := s.checkPlatformDetails(baseURL)
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

		body := strings.NewReader(values.Encode())
		requestUrl := s.urlFor("token", "")
		data, _, err := handleResponse(s.client().Post(requestUrl, "application/x-www-form-urlencoded", body))

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

func (s *Server) checkPlatformDetails(baseURL string) (string, error) {
	platformHelthCheckUrl := fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "health")
	ssHealthCheckUrl := fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "api/v1/healthcheck")

	isHealthy, ssErr := s.checkJSONResponse(ssHealthCheckUrl)
	if isHealthy {
		return "", nil
	}
	if ssErr != nil {
		s.log().Println("[ERROR] Secret Server health check:", ssErr)
	}

	isHealthy, platformErr := s.checkJSONResponse(platformHelthCheckUrl)
	if !isHealthy {
		if platformErr != nil {
			s.log().Println("[ERROR] Platform health check:", platformErr)
		}
		return "", healthCheckError(ssHealthCheckUrl, ssErr, platformHelthCheckUrl, platformErr)
	}

	accessToken, found := s.getCacheAccessToken(baseURL)
	if !found {
		requestData := url.Values{}
		requestData.Set("grant_type", "client_credentials")
		requestData.Set("client_id", s.Credentials.Username)
		requestData.Set("client_secret", s.Credentials.Password)
		requestData.Set("scope", "xpmheadless")

		req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "identity/api/oauth2/token/xpmplatform"), bytes.NewBufferString(requestData.Encode()))
		if err != nil {
			s.log().Print("Error creating HTTP request:", err)
			return "", err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		data, _, err := handleResponse(s.client().Do(req))
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

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "vaultbroker/api/vaults"), bytes.NewBuffer([]byte{}))
	if err != nil {
		s.log().Print("Error creating HTTP request:", err)
		return "", err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)

	data, vaultsResponse, err := handleResponse(s.client().Do(req))
	if err != nil {
		// This is the first use of the cached Platform token. If the Platform refuses
		// it, evict it: otherwise a revoked or rotated token is served from cache for
		// the rest of its lifetime and every call fails, because this error returns
		// before accessResource's own eviction can run.
		if vaultsResponse != nil && (vaultsResponse.StatusCode == http.StatusUnauthorized ||
			vaultsResponse.StatusCode == http.StatusForbidden) {
			s.clearTokenCacheFor(baseURL)
			s.log().Printf("[ERROR] Platform rejected the cached token; cleared it so the next call re-authenticates.")
		}
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
	if vaultURL == "" {
		return "", fmt.Errorf("no configured vault found")
	}
	s.ServerURL = vaultURL

	return accessToken, nil
}

// healthCheckError reports why neither health check identified a Secret Server or a
// Platform at the configured URL. Both probes previously collapsed into a bare
// "invalid URL", with the transport error reaching only the logger: an untrusted CA,
// blocked egress, a DNS failure, an unhealthy or proxied endpoint, and a genuinely
// wrong URL were indistinguishable to the caller and to anything reporting on its
// behalf. The underlying error is wrapped so callers can still match it with errors.As.
func healthCheckError(ssURL string, ssErr error, platformURL string, platformErr error) error {
	switch {
	case ssErr != nil && platformErr != nil:
		return fmt.Errorf("could not reach Secret Server at %s (%v) or Platform at %s: %w", ssURL, ssErr, platformURL, platformErr)
	case ssErr != nil:
		return fmt.Errorf("could not reach Secret Server at %s: %w (Platform at %s responded but did not report healthy)", ssURL, ssErr, platformURL)
	case platformErr != nil:
		return fmt.Errorf("could not reach Platform at %s: %w (Secret Server at %s responded but did not report healthy)", platformURL, platformErr, ssURL)
	default:
		return fmt.Errorf("%s and %s responded but neither reported a healthy Secret Server or Platform", ssURL, platformURL)
	}
}

func (s *Server) checkJSONResponse(url string) (bool, error) {
	response, err := s.client().Get(url)
	if err != nil {
		return false, fmt.Errorf("probing %s: %w", url, err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, fmt.Errorf("reading response from %s: %w", url, err)
	}

	var jsonResponse Response
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		return strings.Contains(string(body), "Healthy"), nil
	}
	return jsonResponse.Healthy, nil
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
