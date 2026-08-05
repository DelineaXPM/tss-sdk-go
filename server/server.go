package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	cloudBaseURLTemplate  string = "https://%s.secretservercloud.%s/"
	defaultAPIPathURI     string = "/api/v1"
	defaultTokenPathURI   string = "/oauth2/token"
	defaultTLD            string = "com"
	defaultHTTPTimeout           = 60 * time.Second
	defaultMaxRetries            = 2
	defaultRetryBaseDelay        = 100 * time.Millisecond
	maximumRetryDelay            = 5 * time.Second
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

func init() {
	if _, err := io.ReadFull(rand.Reader, passwordDigestKey[:]); err != nil {
		panic(fmt.Sprintf("server: initializing token-cache key: %v", err))
	}
}

// UserCredential holds the username and password that the API should use to
// authenticate to the REST API
type UserCredential struct {
	Domain, Username, Password, Token string
}

// String redacts the secret fields of a credential. Server embeds Configuration and
// Configuration's fields are exported, so printing either with %v or %+v — which is what
// a consumer reaches for when a call is misbehaving — would otherwise write the password
// and any supplied token wherever that output goes. fmt consults this method for a
// UserCredential nested inside another value, so the redaction holds for a Configuration
// and for a Server.
//
// An unset secret prints as empty rather than as the redaction: whether a password is
// configured at all is the first thing worth knowing from such a dump, and it is not
// what the redaction is protecting.
func (c UserCredential) String() string {
	return fmt.Sprintf("{Domain:%s Username:%s Password:%s Token:%s}",
		c.Domain, c.Username, redactSecret(c.Password), redactSecret(c.Token))
}

// GoString covers %#v, which prints a Go-syntax representation and ignores String. The
// redacted fields stay quoted so the result is still the Go syntax the verb promises.
func (c UserCredential) GoString() string {
	return fmt.Sprintf("server.UserCredential{Domain:%q, Username:%q, Password:%q, Token:%q}",
		c.Domain, c.Username, redactSecret(c.Password), redactSecret(c.Token))
}

// MarshalJSON prevents a Configuration copied into diagnostics, telemetry, or an API
// response from serializing a live password or bearer token. UnmarshalJSON is
// intentionally not implemented: credential configuration files continue to decode
// normally, but marshaling credentials is a redacted diagnostic representation rather
// than a round trip suitable for writing a new credential file.
func (c UserCredential) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Domain   string
		Username string
		Password string
		Token    string
	}{
		Domain:   c.Domain,
		Username: c.Username,
		Password: redactSecret(c.Password),
		Token:    redactSecret(c.Token),
	})
}

func redactSecret(secret string) string {
	if secret == "" {
		return ""
	}
	return "<redacted>"
}

// Configuration settings for the API
type Configuration struct {
	Credentials                                      UserCredential
	ServerURL, TLD, Tenant, apiPathURI, tokenPathURI string
	TLSClientConfig                                  *tls.Config `json:"-"`
	Logger                                           Logger      `json:"-"`
	// HTTPClient is an optional base client. New makes a shallow copy, preserving
	// its transport, cookie jar and redirect policy while keeping SDK-specific
	// timeout and redirect protections scoped to this Server.
	HTTPClient *http.Client `json:"-"`
	// Timeout bounds each HTTP request made by the Server. Zero selects the safe
	// default of 60 seconds; set DisableTimeout only when a caller-supplied context
	// provides the required bound.
	Timeout time.Duration
	// DisableTimeout explicitly disables both the safe default and an injected
	// HTTPClient's timeout.
	DisableTimeout bool
	// MaxRetries is the number of retries after the initial request for safe reads.
	// Zero selects the default of two. DisableRetries explicitly selects none.
	MaxRetries     int
	DisableRetries bool
	// RetryBaseDelay is the initial backoff before jitter. Zero selects 100ms.
	RetryBaseDelay time.Duration
	// AllowedVaultHosts contains exact hostnames (or host:port values) that
	// Platform discovery may select in addition to same-origin and Delinea Cloud
	// vaults. It is intended for on-premises Platform deployments whose vault is
	// hosted on a different origin.
	AllowedVaultHosts []string
	// VaultURLValidator may authorize a discovered HTTPS vault URL that is not
	// covered by the built-in policy. It cannot authorize plaintext HTTP, URLs
	// containing user information, or URLs containing a query or fragment.
	VaultURLValidator func(platformURL, vaultURL *url.URL) error `json:"-"`
	// MaxResponseBytes, when positive, overrides the default cap
	// (defaultMaxResponseBytes) on the size of an API response body the SDK
	// will read into memory. Raise it only for an on-premises Secret Server
	// whose file-attachment size limit has been configured above the default
	// cap.
	MaxResponseBytes int64
}

// Server provides access to secrets stored in Delinea Secret Server
type Server struct {
	Configuration
	httpClient *http.Client
}

type TokenCache struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	generation  uint64
	expiresAt   int64
}

type tokenSource uint8

const (
	tokenSourceSupplied tokenSource = iota
	tokenSourceCache
)

type accessTokenDetails struct {
	value      string
	cacheKey   string
	generation uint64
	source     tokenSource
}

type tokenGrant struct {
	accessToken string
	expiresIn   int
}

type tokenFlight struct {
	done  chan struct{}
	token accessTokenDetails
	err   error
}

// tokenCache holds cached access tokens in process memory, keyed by cacheKey.
// It replaces the previous os.Setenv-based cache: storing a bearer token in the
// process environment exposed it to child processes and any reader of the
// process environment (CWE-526). An in-memory store keeps the intra-process
// reuse and the per-URL/per-credential collision keying without that exposure.
var (
	tokenCacheMu        sync.Mutex
	tokenCache          = map[string]TokenCache{}
	tokenFlights        = map[string]*tokenFlight{}
	nextTokenGeneration uint64
	passwordDigestKey   [32]byte
)

const (
	maxTokenCacheEntries         = 1024
	maxOAuthTokenLifetimeSeconds = 365 * 24 * 60 * 60
)

// New returns an initialized Secrets object
func New(config Configuration) (*Server, error) {
	if config.ServerURL == "" && config.Tenant == "" || config.ServerURL != "" && config.Tenant != "" {
		return nil, fmt.Errorf("either ServerURL of Secret Server/Platform or Tenant of Secret Server Cloud must be set")
	}
	if config.TLD == "" {
		config.TLD = defaultTLD
	}
	if config.MaxRetries < 0 {
		return nil, fmt.Errorf("max retries must not be negative")
	}
	if config.RetryBaseDelay < 0 {
		return nil, fmt.Errorf("retry base delay must not be negative")
	}
	if config.apiPathURI == "" {
		config.apiPathURI = defaultAPIPathURI
	}
	config.apiPathURI = strings.Trim(config.apiPathURI, "/")
	if config.tokenPathURI == "" {
		config.tokenPathURI = defaultTokenPathURI
	}
	config.tokenPathURI = strings.Trim(config.tokenPathURI, "/")
	httpClient, err := newHTTPClient(config)
	if err != nil {
		return nil, err
	}
	return &Server{Configuration: config, httpClient: httpClient}, nil
}

// newHTTPClient makes a Server-scoped copy of the configured client. Transport.Clone
// preserves every standard transport option, including fields added by newer Go
// releases, while a non-standard RoundTripper is preserved unless TLSClientConfig must
// be applied. In that case New fails closed rather than silently bypassing the wrapper
// or ignoring the requested TLS policy.
func newHTTPClient(config Configuration) (*http.Client, error) {
	baseClient := http.DefaultClient
	if config.HTTPClient != nil {
		baseClient = config.HTTPClient
	}
	client := *baseClient

	if config.Timeout < 0 {
		return nil, fmt.Errorf("timeout must not be negative")
	}
	switch {
	case config.DisableTimeout:
		client.Timeout = 0
	case config.Timeout > 0:
		client.Timeout = config.Timeout
	case client.Timeout == 0:
		client.Timeout = defaultHTTPTimeout
	}

	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	if config.TLSClientConfig != nil {
		standardTransport, ok := transport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("TLSClientConfig requires an *http.Transport, got %T", transport)
		}
		clonedTransport := standardTransport.Clone()
		clonedTransport.TLSClientConfig = config.TLSClientConfig.Clone()
		client.Transport = clonedTransport
	} else {
		client.Transport = transport
	}

	configuredRedirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 {
			return nil
		}
		if sensitiveRedirectsDisabled(via[0].Context()) {
			return http.ErrUseLastResponse
		}
		if !sameOrigin(via[0].URL, req.URL) {
			return fmt.Errorf("refusing redirect from %s to a different origin %s", via[0].URL, req.URL)
		}
		if configuredRedirect != nil {
			return configuredRedirect(req, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}

	return &client, nil
}

type sensitiveRedirectContextKey struct{}

func withoutRedirects(req *http.Request) *http.Request {
	ctx := context.WithValue(req.Context(), sensitiveRedirectContextKey{}, true)
	return req.WithContext(ctx)
}

func sensitiveRedirectsDisabled(ctx context.Context) bool {
	disabled, _ := ctx.Value(sensitiveRedirectContextKey{}).(bool)
	return disabled
}

func sameOrigin(first, second *url.URL) bool {
	return strings.EqualFold(first.Scheme, second.Scheme) && strings.EqualFold(first.Host, second.Host)
}

// client returns the per-Server HTTP client. The fallback keeps manually constructed
// zero-value Servers usable in package tests; New always installs a scoped client.
func (s Server) client() *http.Client {
	if s.httpClient != nil {
		return s.httpClient
	}
	return http.DefaultClient
}

// do sends a request and retries only methods that are safe to repeat. Credential
// grants, creates, updates, deletes and uploads therefore remain single-attempt even
// when a transport fails after the server may have acted on the request.
func (s Server) do(req *http.Request) (*http.Response, error) {
	retries := s.retryCount(req.Method)
	current := req
	for attempt := 0; ; attempt++ {
		response, err := s.client().Do(current)
		if attempt >= retries || !shouldRetryResponse(current.Context(), response, err) {
			return response, err
		}
		if response != nil && response.Body != nil {
			response.Body.Close()
		}

		delay := s.retryDelay(attempt, response)
		timer := time.NewTimer(delay)
		select {
		case <-current.Context().Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, current.Context().Err()
		case <-timer.C:
		}
		current = req.Clone(req.Context())
	}
}

func (s Server) retryCount(method string) int {
	if s.DisableRetries || (method != http.MethodGet && method != http.MethodHead) {
		return 0
	}
	if s.MaxRetries > 0 {
		return s.MaxRetries
	}
	return defaultMaxRetries
}

func shouldRetryResponse(ctx context.Context, response *http.Response, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if err != nil {
		var networkError net.Error
		// Temporary is deprecated because the standard library cannot define it
		// precisely, but a net.Error that reports itself temporary is exactly the
		// class a safe read should retry, and dropping the check would silently
		// narrow retry coverage for connection resets. Retrying is safe here
		// regardless: only GET and HEAD reach this function.
		//lint:ignore SA1019 deliberate; see above
		return errors.As(err, &networkError) && (networkError.Timeout() || networkError.Temporary()) ||
			errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
	}
	return response != nil && (response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500)
}

func (s Server) retryDelay(attempt int, response *http.Response) time.Duration {
	if response != nil {
		if delay, ok := parseRetryAfter(response.Header.Get("Retry-After")); ok {
			return delay
		}
	}
	base := s.RetryBaseDelay
	if base == 0 {
		base = defaultRetryBaseDelay
	}
	for i := 0; i < attempt && base < maximumRetryDelay; i++ {
		base *= 2
	}
	if base > maximumRetryDelay {
		base = maximumRetryDelay
	}
	var randomByte [1]byte
	if _, err := rand.Read(randomByte[:]); err != nil {
		randomByte[0] = 128
	}
	// Apply 50%-150% jitter, then retain the hard upper bound.
	delay := base/2 + time.Duration(uint64(base)*uint64(randomByte[0])/255)
	if delay > maximumRetryDelay {
		return maximumRetryDelay
	}
	return delay
}

func parseRetryAfter(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		if seconds > int(maximumRetryDelay/time.Second) {
			return maximumRetryDelay, true
		}
		delay := time.Duration(seconds) * time.Second
		if delay > maximumRetryDelay {
			delay = maximumRetryDelay
		}
		return delay, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := time.Until(when)
	if delay < 0 {
		delay = 0
	}
	if delay > maximumRetryDelay {
		delay = maximumRetryDelay
	}
	return delay, true
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
	return s.accessResourceContext(context.Background(), method, resource, path, input)
}

func (s Server) accessResourceContext(ctx context.Context, method, resource, path string, input interface{}) ([]byte, error) {
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

	accessToken, err := s.getAccessTokenDetailsContext(ctx)

	if err != nil {
		s.log().Print("[ERROR] error getting accessToken:", err)
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, s.urlFor(resource, path), body)

	if err != nil {
		s.log().Printf("[ERROR] creating req: %s /%s/%s: %s", method, resource, path, err)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken.value)

	switch method {
	case "POST", "PUT", "PATCH":
		req.Header.Set("Content-Type", "application/json")
	}

	s.log().Printf("[DEBUG] calling %s %s", method, req.URL.String())

	data, statusCode, err := s.handleResponse(s.do(req))

	s.evictOnAuthFailure(statusCode, accessToken)

	return data, err
}

// evictOnAuthFailure drops the cached token when the server rejects a request as
// unauthorized or forbidden, so the next call re-authenticates instead of replaying a
// token the server no longer honors. Supplied tokens are caller-owned and never touch
// the password-grant cache. res is nil on a transport error.
func (s Server) evictOnAuthFailure(res *http.Response, token accessTokenDetails) {
	if res == nil || (res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden) {
		return
	}
	if s.clearTokenCacheIfCurrent(token) {
		s.log().Printf("[ERROR] Token cache cleared due to unauthorized or access denied response.")
	}
}

// searchResources uses the accessToken to search for API resources.
// It assumes an appropriate combination of resource, search text.
// field is optional
func (s Server) searchResources(resource, searchText, field string) ([]byte, error) {
	return s.searchResourcesContext(context.Background(), resource, searchText, field)
}

func (s Server) searchResourcesContext(ctx context.Context, resource, searchText, field string) ([]byte, error) {
	switch resource {
	case "secrets":
	default:
		message := "unknown resource"

		s.log().Printf("[ERROR] %s: %s", message, resource)
		return nil, fmt.Errorf("%s", message)
	}

	method := "GET"
	body := bytes.NewBuffer([]byte{})

	accessToken, err := s.getAccessTokenDetailsContext(ctx)

	if err != nil {
		s.log().Print("[ERROR] error getting accessToken:", err)
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, method, s.urlForSearch(resource, searchText, field), body)

	if err != nil {
		s.log().Printf("[ERROR] creating req: %s /%s/%s/%s: %s", method, resource, searchText, field, err)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken.value)

	s.log().Printf("[DEBUG] calling %s %s", method, req.URL.String())

	data, statusCode, err := s.handleResponse(s.do(req))

	s.evictOnAuthFailure(statusCode, accessToken)

	return data, err
}

// uploadFile uploads the file described in the given fileField to the
// secret at the given secretId as a multipart/form-data request.
func (s Server) uploadFile(secretId int, fileField SecretField) error {
	return s.uploadFileContext(context.Background(), secretId, fileField)
}

func (s Server) uploadFileContext(ctx context.Context, secretId int, fileField SecretField) error {
	s.log().Printf("[DEBUG] uploading a file to the '%s' field with filename '%s'", fileField.Slug, fileField.Filename)
	body := bytes.NewBuffer([]byte{})
	path := fmt.Sprintf("%d/fields/%s", secretId, url.PathEscape(fileField.Slug))

	// Fetch the access token
	accessToken, err := s.getAccessTokenDetailsContext(ctx)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.urlFor(resource, path), body)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken.value)
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	s.log().Printf("[DEBUG] uploading file with PUT %s", req.URL.String())
	_, statusCode, err := s.handleResponse(s.do(req))

	s.evictOnAuthFailure(statusCode, accessToken)

	return err
}

func (s *Server) setCacheAccessToken(value string, expiresIn int, baseURL string) error {
	_, err := s.storeCacheAccessToken(value, expiresIn, baseURL)
	return err
}

func (s *Server) storeCacheAccessToken(value string, expiresIn int, baseURL string) (accessTokenDetails, error) {
	cache := TokenCache{}
	cache.AccessToken = value
	// Serve the cached token for 90% of its lifetime, refreshing before it
	// expires. The previous formula subtracted the 90% instead of the 10%
	// safety margin, so tokens were re-fetched after a tenth of their
	// lifetime, forcing ~10x more credential round trips than necessary.
	if expiresIn < 0 || expiresIn > maxOAuthTokenLifetimeSeconds {
		return accessTokenDetails{}, fmt.Errorf("token lifetime is outside the supported range")
	}
	cache.expiresAt = time.Now().Unix() + int64(expiresIn*9/10)
	if strconv.IntSize == 64 {
		cache.ExpiresIn = int(cache.expiresAt)
	} else {
		// Retain the historical exported field without using it for runtime expiry on
		// 32-bit systems, where current Unix seconds do not fit in int.
		cache.ExpiresIn = int(^uint(0) >> 1)
	}

	key := s.cacheKey(baseURL)
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	// Sweep expired entries while holding the lock: an entry is otherwise deleted
	// only when its exact key is queried again, and a key embeds the credential
	// digest, so entries orphaned by a password rotation would accumulate for the
	// life of the process.
	now := time.Now().Unix()
	for key, entry := range tokenCache {
		if tokenExpiresAt(entry) <= now {
			delete(tokenCache, key)
		}
	}
	if _, replacing := tokenCache[key]; !replacing && len(tokenCache) >= maxTokenCacheEntries {
		evictOldestTokenLocked()
	}
	nextTokenGeneration++
	cache.generation = nextTokenGeneration
	tokenCache[key] = cache
	return accessTokenDetails{
		value:      cache.AccessToken,
		cacheKey:   key,
		generation: cache.generation,
		source:     tokenSourceCache,
	}, nil
}

func (s *Server) getCacheAccessToken(baseURL string) (string, bool) {
	token, ok := s.getCachedToken(baseURL)
	return token.value, ok
}

func (s *Server) getCachedToken(baseURL string) (accessTokenDetails, bool) {
	key := s.cacheKey(baseURL)
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	cache, ok := tokenCache[key]
	if ok && time.Now().Unix() < tokenExpiresAt(cache) {
		return accessTokenDetails{
			value:      cache.AccessToken,
			cacheKey:   key,
			generation: cache.generation,
			source:     tokenSourceCache,
		}, true
	}
	// Evict under the key that was just looked up, not under s.baseURL(): after
	// Platform discovery rewrites ServerURL, the two name different entries, and
	// clearing by the current base URL would drop a live token instead of the
	// expired one this miss found.
	delete(tokenCache, key)
	return accessTokenDetails{}, false
}

func evictOldestTokenLocked() {
	var oldestKey string
	var oldestExpiry int64
	for key, cache := range tokenCache {
		if oldestKey == "" || tokenExpiresAt(cache) < oldestExpiry {
			oldestKey = key
			oldestExpiry = tokenExpiresAt(cache)
		}
	}
	if oldestKey != "" {
		delete(tokenCache, oldestKey)
	}
}

func tokenExpiresAt(cache TokenCache) int64 {
	if cache.expiresAt != 0 {
		return cache.expiresAt
	}
	return int64(cache.ExpiresIn)
}

// cachedOrGrantToken coalesces concurrent cache misses for one credential key. The
// grant runs without the global cache lock, so unrelated servers and credentials can
// authenticate concurrently. Waiters receive the exact generation stored by the
// leader, which later makes auth-failure eviction compare-and-delete safe.
func (s *Server) cachedOrGrantToken(ctx context.Context, baseURL string, grant func(context.Context) (tokenGrant, error)) (accessTokenDetails, error) {
	key := s.cacheKey(baseURL)
	now := time.Now().Unix()
	tokenCacheMu.Lock()
	if cached, ok := tokenCache[key]; ok && now < tokenExpiresAt(cached) {
		tokenCacheMu.Unlock()
		return accessTokenDetails{value: cached.AccessToken, cacheKey: key, generation: cached.generation, source: tokenSourceCache}, nil
	}
	delete(tokenCache, key)
	if flight, ok := tokenFlights[key]; ok {
		tokenCacheMu.Unlock()
		select {
		case <-flight.done:
			return flight.token, flight.err
		case <-ctx.Done():
			return accessTokenDetails{}, ctx.Err()
		}
	}
	flight := &tokenFlight{done: make(chan struct{})}
	tokenFlights[key] = flight
	tokenCacheMu.Unlock()

	granted, err := grant(ctx)
	if err == nil {
		flight.token, err = s.storeCacheAccessToken(granted.accessToken, granted.expiresIn, baseURL)
	}
	flight.err = err

	tokenCacheMu.Lock()
	delete(tokenFlights, key)
	close(flight.done)
	tokenCacheMu.Unlock()
	return flight.token, flight.err
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

// clearTokenCacheIfCurrent removes only the cache generation actually used by a
// rejected request. A delayed 401 for an older token must not evict a newer token that
// another goroutine has already refreshed.
func (s *Server) clearTokenCacheIfCurrent(token accessTokenDetails) bool {
	if token.source != tokenSourceCache || token.cacheKey == "" {
		return false
	}
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	cached, ok := tokenCache[token.cacheKey]
	if !ok || cached.generation != token.generation {
		return false
	}
	delete(tokenCache, token.cacheKey)
	return true
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

// passwordDigest uses a process-random HMAC key so a memory disclosure of cache keys
// does not turn each key into a reusable offline verifier for a low-entropy password.
// It still deterministically distinguishes credentials within this process.
func passwordDigest(password string) string {
	digest := hmac.New(sha256.New, passwordDigestKey[:])
	_, _ = digest.Write([]byte(password))
	return hex.EncodeToString(digest.Sum(nil))
}

// getAccessToken gets an OAuth2 Access Grant and returns the token
// endpoint and get an accessGrant.
func (s *Server) getAccessToken() (string, error) {
	token, err := s.getAccessTokenDetailsContext(context.Background())
	return token.value, err
}

func (s *Server) getAccessTokenDetailsContext(ctx context.Context) (accessTokenDetails, error) {
	if s.Credentials.Token != "" {
		return accessTokenDetails{value: s.Credentials.Token, source: tokenSourceSupplied}, nil
	}
	baseURL := s.baseURL()

	details, err := s.checkPlatformDetailsContext(ctx, baseURL)
	if err != nil {
		s.log().Print("Error while checking server details:", err)
		return accessTokenDetails{}, err
	}

	if !details.isPlatform {
		return s.cachedOrGrantToken(ctx, baseURL, func(ctx context.Context) (tokenGrant, error) {
			values := url.Values{
				"username":   {s.Credentials.Username},
				"password":   {s.Credentials.Password},
				"grant_type": {"password"},
			}
			if s.Credentials.Domain != "" {
				values["domain"] = []string{s.Credentials.Domain}
			}

			requestURL := s.urlFor("token", "")
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, strings.NewReader(values.Encode()))
			if err != nil {
				return tokenGrant{}, fmt.Errorf("creating token request: %w", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req = withoutRedirects(req)
			response, requestErr := s.do(req)
			data, _, err := s.handleResponseWithLimit(response, requestErr, maxAuthenticationResponseBytes)

			if err != nil {
				s.log().Print("[ERROR] grant response error:", err)
				return tokenGrant{}, err
			}

			grant := struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
				TokenType    string `json:"token_type"`
				ExpiresIn    int    `json:"expires_in"`
			}{}

			if err = json.Unmarshal(data, &grant); err != nil {
				s.log().Print("[ERROR] parsing grant response:", err)
				return tokenGrant{}, err
			}
			if err = validateTokenGrant(grant.AccessToken, grant.TokenType, grant.ExpiresIn); err != nil {
				return tokenGrant{}, fmt.Errorf("invalid token response from %s: %w", requestURL, err)
			}
			return tokenGrant{accessToken: grant.AccessToken, expiresIn: grant.ExpiresIn}, nil
		})
	}

	return details.accessToken, nil
}

type platformDetails struct {
	isPlatform  bool
	accessToken accessTokenDetails
}

func (s *Server) checkPlatformDetails(baseURL string) (platformDetails, error) {
	return s.checkPlatformDetailsContext(context.Background(), baseURL)
}

func (s *Server) checkPlatformDetailsContext(ctx context.Context, baseURL string) (platformDetails, error) {
	platformHelthCheckUrl := fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "health")
	ssHealthCheckUrl := fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "api/v1/healthcheck")

	isHealthy, ssErr := s.checkJSONResponseContext(ctx, ssHealthCheckUrl)
	if isHealthy {
		return platformDetails{}, nil
	}
	if ssErr != nil {
		s.log().Println("[ERROR] Secret Server health check:", ssErr)
	}

	isHealthy, platformErr := s.checkJSONResponseContext(ctx, platformHelthCheckUrl)
	if !isHealthy {
		if platformErr != nil {
			s.log().Println("[ERROR] Platform health check:", platformErr)
		}
		return platformDetails{}, healthCheckError(ssHealthCheckUrl, ssErr, platformHelthCheckUrl, platformErr)
	}

	accessToken, err := s.cachedOrGrantToken(ctx, baseURL, func(ctx context.Context) (tokenGrant, error) {
		requestData := url.Values{}
		requestData.Set("grant_type", "client_credentials")
		requestData.Set("client_id", s.Credentials.Username)
		requestData.Set("client_secret", s.Credentials.Password)
		requestData.Set("scope", "xpmheadless")

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "identity/api/oauth2/token/xpmplatform"), bytes.NewBufferString(requestData.Encode()))
		if err != nil {
			s.log().Print("Error creating HTTP request:", err)
			return tokenGrant{}, err
		}

		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req = withoutRedirects(req)

		response, requestErr := s.do(req)
		data, _, err := s.handleResponseWithLimit(response, requestErr, maxAuthenticationResponseBytes)
		if err != nil {
			s.log().Print("[ERROR] get token response error:", err)
			return tokenGrant{}, err
		}

		var tokenjsonResponse OAuthTokens
		if err = json.Unmarshal(data, &tokenjsonResponse); err != nil {
			s.log().Print("[ERROR] parsing get token response:", err)
			return tokenGrant{}, err
		}
		if err = validateTokenGrant(tokenjsonResponse.AccessToken, tokenjsonResponse.TokenType, tokenjsonResponse.ExpiresIn); err != nil {
			return tokenGrant{}, fmt.Errorf("invalid Platform token response: %w", err)
		}
		return tokenGrant{accessToken: tokenjsonResponse.AccessToken, expiresIn: tokenjsonResponse.ExpiresIn}, nil
	})
	if err != nil {
		return platformDetails{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "vaultbroker/api/vaults"), nil)
	if err != nil {
		s.log().Print("Error creating HTTP request:", err)
		return platformDetails{}, err
	}
	req.Header.Add("Authorization", "Bearer "+accessToken.value)

	response, requestErr := s.do(req)
	data, vaultsResponse, err := s.handleResponseWithLimit(response, requestErr, maxMetadataResponseBytes)
	if err != nil {
		// This is the first use of the cached Platform token. If the Platform refuses
		// it, evict it: otherwise a revoked or rotated token is served from cache for
		// the rest of its lifetime and every call fails, because this error returns
		// before accessResource's own eviction can run.
		if vaultsResponse != nil && (vaultsResponse.StatusCode == http.StatusUnauthorized ||
			vaultsResponse.StatusCode == http.StatusForbidden) {
			if s.clearTokenCacheIfCurrent(accessToken) {
				s.log().Printf("[ERROR] Platform rejected the cached token; cleared it so the next call re-authenticates.")
			}
		}
		s.log().Print("[ERROR] get vaults response error:", err)
		return platformDetails{}, err
	}

	var vaultJsonResponse VaultsResponseModel
	if err = json.Unmarshal(data, &vaultJsonResponse); err != nil {
		s.log().Print("[ERROR] parsing vaults response:", err)
		return platformDetails{}, err
	}

	var vaultURL string
	for _, vault := range vaultJsonResponse.Vaults {
		if vault.IsDefault && vault.IsActive {
			vaultURL = vault.Connection.Url
			break
		}
	}
	if vaultURL == "" {
		return platformDetails{}, fmt.Errorf("no configured vault found")
	}
	validatedVaultURL, err := s.validateDiscoveredVaultURL(baseURL, vaultURL)
	if err != nil {
		return platformDetails{}, err
	}
	s.ServerURL = validatedVaultURL.String()

	return platformDetails{isPlatform: true, accessToken: accessToken}, nil
}

func validateTokenGrant(accessToken, tokenType string, expiresIn int) error {
	if accessToken == "" || strings.IndexFunc(accessToken, func(r rune) bool { return r <= ' ' || r == '\u007f' }) >= 0 {
		return fmt.Errorf("access_token is missing or contains whitespace or control characters")
	}
	if tokenType != "" && !strings.EqualFold(tokenType, "Bearer") {
		return fmt.Errorf("unsupported token_type %q", tokenType)
	}
	if expiresIn <= 0 {
		return fmt.Errorf("expires_in must be greater than zero")
	}
	if expiresIn > maxOAuthTokenLifetimeSeconds {
		return fmt.Errorf("expires_in exceeds the supported maximum of %d seconds", maxOAuthTokenLifetimeSeconds)
	}
	return nil
}

var delineaCloudVaultDomains = []string{
	"devsecretservercloud.com",
	"secretservercloud.com",
	"secretservercloud.eu",
	"secretservercloud.com.au",
	"secretservercloud.com.sg",
	"secretservercloud.ca",
	"secretservercloud.co.uk",
	"secretservercloud.ae",
}

func (s *Server) validateDiscoveredVaultURL(platformRawURL, vaultRawURL string) (*url.URL, error) {
	platformURL, err := url.Parse(platformRawURL)
	if err != nil || platformURL.Scheme == "" || platformURL.Host == "" {
		return nil, fmt.Errorf("configured platform URL is invalid")
	}
	vaultURL, err := url.Parse(vaultRawURL)
	if err != nil || vaultURL.Scheme == "" || vaultURL.Host == "" {
		return nil, fmt.Errorf("platform returned an invalid vault URL")
	}
	if !strings.EqualFold(vaultURL.Scheme, "https") {
		return nil, fmt.Errorf("platform returned a vault URL that does not use HTTPS")
	}
	if vaultURL.User != nil {
		return nil, fmt.Errorf("platform returned a vault URL containing user information")
	}
	if vaultURL.RawQuery != "" || vaultURL.Fragment != "" {
		return nil, fmt.Errorf("platform returned a vault URL containing a query or fragment")
	}

	if sameOrigin(platformURL, vaultURL) || isDelineaCloudVaultHost(vaultURL.Hostname()) || s.isAllowedVaultHost(vaultURL) {
		return vaultURL, nil
	}
	if s.VaultURLValidator != nil {
		platformForValidation := *platformURL
		vaultForValidation := *vaultURL
		if err := s.VaultURLValidator(&platformForValidation, &vaultForValidation); err == nil {
			return vaultURL, nil
		} else {
			return nil, fmt.Errorf("platform vault URL was rejected by VaultURLValidator: %w", err)
		}
	}
	return nil, fmt.Errorf("platform returned untrusted vault host %q; add it to AllowedVaultHosts if this on-premises deployment is expected", vaultURL.Host)
}

func isDelineaCloudVaultHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, domain := range delineaCloudVaultDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func (s *Server) isAllowedVaultHost(vaultURL *url.URL) bool {
	host := strings.ToLower(strings.TrimSuffix(vaultURL.Host, "."))
	hostname := strings.ToLower(strings.TrimSuffix(vaultURL.Hostname(), "."))
	for _, configured := range s.AllowedVaultHosts {
		allowed := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(configured), "."))
		if allowed != "" && (allowed == host || allowed == hostname) {
			return true
		}
	}
	return false
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
		return fmt.Errorf("could not reach Secret Server at %s (%w) or Platform at %s: %w", ssURL, ssErr, platformURL, platformErr)
	case ssErr != nil:
		return fmt.Errorf("could not reach Secret Server at %s: %w (Platform at %s responded but did not report healthy)", ssURL, ssErr, platformURL)
	case platformErr != nil:
		return fmt.Errorf("could not reach Platform at %s: %w (Secret Server at %s responded but did not report healthy)", platformURL, platformErr, ssURL)
	default:
		return fmt.Errorf("%s and %s responded but neither reported a healthy Secret Server or Platform", ssURL, platformURL)
	}
}

// maxHealthResponseBytes bounds a health-probe response; genuine health checks are
// tiny, so anything larger is not a healthy Secret Server or Platform.
const maxHealthResponseBytes = 1 << 20

func (s *Server) checkJSONResponse(url string) (bool, error) {
	return s.checkJSONResponseContext(context.Background(), url)
}

func (s *Server) checkJSONResponseContext(ctx context.Context, url string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("creating health probe for %s: %w", url, err)
	}
	response, err := s.do(req)
	if err != nil {
		return false, fmt.Errorf("probing %s: %w", url, err)
	}
	body, _, err := s.handleResponseWithLimit(response, nil, maxHealthResponseBytes)
	if err != nil {
		return false, fmt.Errorf("probing %s: %w", url, err)
	}

	var jsonResponse Response
	if err := json.Unmarshal(body, &jsonResponse); err != nil {
		if strings.EqualFold(strings.TrimSpace(string(body)), "Healthy") {
			return true, nil
		}
		return false, fmt.Errorf("health response from %s was neither valid JSON nor the legacy Healthy value", url)
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
