package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	delinea "github.com/DelineaXPM/delinea-tools/api"
)

const (
	defaultAPIPathURI       = "/api/v1"
	defaultTLD              = "com"
	defaultHTTPTimeout      = 60 * time.Second
	defaultMaxResponseBytes = 100 << 20
	defaultMaxAttachments   = 100
)

// Logger is an interface for logging in the SDK. It matches the standard log package interface.
// Consumers can provide their own implementation to customize logging behavior.
type Logger interface {
	Printf(format string, v ...interface{})
	Print(v ...interface{})
	Println(v ...interface{})
}

// DiscardLogger is a Logger implementation that discards all output (no-op).
type DiscardLogger struct{}

func (*DiscardLogger) Printf(string, ...interface{}) {}
func (*DiscardLogger) Print(...interface{})          {}
func (*DiscardLogger) Println(...interface{})        {}

type stdLogger struct{}

func (*stdLogger) Printf(format string, v ...interface{}) { log.Printf(format, v...) }
func (*stdLogger) Print(v ...interface{})                 { log.Print(v...) }
func (*stdLogger) Println(v ...interface{})               { log.Println(v...) }

var defaultLoggerInstance Logger = &DiscardLogger{}

// UserCredential holds the username and password that the API should use to
// authenticate to the REST API.
type UserCredential struct {
	Domain, Username, Password, Token string
}

func (c UserCredential) String() string {
	return fmt.Sprintf("{Domain:%q Username:%q Password:%s Token:%s}",
		sanitizeLogText(c.Domain), sanitizeLogText(c.Username), redactSecret(c.Password), redactSecret(c.Token))
}

func (c UserCredential) GoString() string {
	return fmt.Sprintf("server.UserCredential{Domain:%q, Username:%q, Password:%q, Token:%q}",
		sanitizeLogText(c.Domain), sanitizeLogText(c.Username), redactSecret(c.Password), redactSecret(c.Token))
}

func (c UserCredential) MarshalJSON() ([]byte, error) {
	type redactedCredential struct{ Domain, Username, Password, Token string }
	return json.Marshal(redactedCredential{
		Domain: sanitizeLogText(c.Domain), Username: sanitizeLogText(c.Username),
		Password: redactSecret(c.Password), Token: redactSecret(c.Token),
	})
}

func redactSecret(value string) string {
	if value == "" {
		return ""
	}
	return "<redacted>"
}

// Configuration settings for the API. Configuration is snapshotted by New;
// mutating it through the returned Server does not reconfigure the live client.
type Configuration struct {
	Credentials                        UserCredential
	ServerURL, TLD, Tenant, apiPathURI string
	TLSClientConfig                    *tls.Config `json:"-"`
	// CACertPEM adds PEM-encoded private roots while retaining safe cross-Server
	// token sharing. Prefer it to TLSClientConfig when custom roots are the only
	// TLS customization required.
	CACertPEM         string
	Logger            Logger `json:"-"`
	AllowInsecureHTTP bool
	Timeout           time.Duration
	MaxRetries        int
	DisableRetries    bool
	RetryBaseDelay    time.Duration
	// AllowedVaultHosts is a comma-separated list of exact host or host:port
	// values trusted for Platform-discovered vault URLs. A string keeps the
	// published Configuration and Server types comparable.
	AllowedVaultHosts      string
	MaxResponseBytes       int64
	MaxAttachmentDownloads int

	runtime *serverRuntime
}

// Server provides access to secrets stored in Delinea Secret Server. Runtime
// state is carried in the private portion of the embedded Configuration.
type Server struct {
	Configuration
}

// TokenCache is retained for v3 source and wire compatibility. Token storage is
// implemented by delinea-tools and no longer uses this type internally.
type TokenCache struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type clientInitialization struct {
	done        chan struct{}
	client      *delinea.Client
	err         error
	leaderLocal bool
}

type serverRuntime struct {
	mu             sync.Mutex
	client         *delinea.Client
	starting       *clientInitialization
	config         delinea.Config
	logger         Logger
	responseLimit  int64
	timeout        time.Duration
	maxAttachments int
}

type operationBudget struct {
	initialBytes   int64
	remainingBytes int64
	attachments    int
	maxAttachments int
}

func (b *operationBudget) consume(body []byte) error {
	if int64(len(body)) > b.remainingBytes {
		return fmt.Errorf("operation response bodies exceeded %d bytes", b.initialBytes)
	}
	b.remainingBytes -= int64(len(body))
	return nil
}

func (b *operationBudget) claimAttachment() error {
	if b.attachments >= b.maxAttachments {
		return fmt.Errorf("operation exceeded %d attachment downloads", b.maxAttachments)
	}
	b.attachments++
	return nil
}

// New validates and snapshots config without performing network I/O. Backend
// probing, authentication, and vault discovery happen lazily on the first call.
func New(config Configuration) (*Server, error) {
	if (config.ServerURL == "") == (config.Tenant == "") {
		return nil, fmt.Errorf("either ServerURL of Secret Server/Platform or Tenant of Secret Server Cloud must be set")
	}
	if config.TLD == "" {
		config.TLD = defaultTLD
	}
	if config.MaxRetries < 0 {
		return nil, fmt.Errorf("max retries must not be negative")
	}
	if config.MaxRetries == math.MaxInt {
		return nil, fmt.Errorf("max retries is too large")
	}
	if config.RetryBaseDelay < 0 {
		return nil, fmt.Errorf("retry base delay must not be negative")
	}
	if config.Timeout < 0 {
		return nil, fmt.Errorf("timeout must not be negative")
	}
	if config.MaxResponseBytes < 0 {
		return nil, fmt.Errorf("max response bytes must not be negative")
	}
	if config.MaxAttachmentDownloads < 0 {
		return nil, fmt.Errorf("max attachment downloads must not be negative")
	}
	if config.TLSClientConfig != nil && config.CACertPEM != "" {
		return nil, fmt.Errorf("TLSClientConfig and CACertPEM cannot both be set")
	}
	if config.CACertPEM != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(config.CACertPEM)) {
			return nil, fmt.Errorf("CACertPEM contains no certificates")
		}
	}
	if config.apiPathURI == "" {
		config.apiPathURI = defaultAPIPathURI
	}
	config.apiPathURI = strings.Trim(config.apiPathURI, "/")
	baseURL, err := configuredURL(config)
	if err != nil {
		return nil, err
	}
	apiConfig := delinea.Config{
		URL:               baseURL,
		AllowInsecureHTTP: config.AllowInsecureHTTP,
		Username:          config.Credentials.Username,
		Password:          config.Credentials.Password,
		Domain:            config.Credentials.Domain,
		Timeout:           config.Timeout,
		AllowedVaultHosts: parseAllowedVaultHosts(config.AllowedVaultHosts),
		Logger:            slogFor(config.Logger),
		CACert:            []byte(config.CACertPEM),
	}
	if apiConfig.Timeout == 0 {
		apiConfig.Timeout = defaultHTTPTimeout
	}
	if config.Credentials.Token != "" {
		apiConfig.Token = config.Credentials.Token
		apiConfig.Target = delinea.TargetSecretServer
	}
	if config.DisableRetries {
		apiConfig.Retries = 1
	} else if config.MaxRetries > 0 {
		apiConfig.Retries = config.MaxRetries + 1
	}
	if config.RetryBaseDelay > 0 {
		base := config.RetryBaseDelay
		apiConfig.Backoff = func(attempt int) time.Duration {
			factor := time.Duration(1 << min(attempt, 20))
			if base > time.Duration(math.MaxInt64)/factor {
				return time.Duration(math.MaxInt64)
			}
			return base * factor
		}
	}
	if config.TLSClientConfig != nil {
		transport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("TLSClientConfig requires an *http.Transport, got %T", http.DefaultTransport)
		}
		clone := transport.Clone()
		clone.TLSClientConfig = config.TLSClientConfig.Clone()
		apiConfig.Transport = clone
		config.TLSClientConfig = config.TLSClientConfig.Clone()
	}
	logger := config.Logger
	if logger == nil {
		logger = defaultLoggerInstance
	}
	responseLimit := config.MaxResponseBytes
	if responseLimit <= 0 {
		responseLimit = defaultMaxResponseBytes
	} else if responseLimit == math.MaxInt64 {
		responseLimit--
	}
	maxAttachments := config.MaxAttachmentDownloads
	if maxAttachments == 0 {
		maxAttachments = defaultMaxAttachments
	}
	config.runtime = &serverRuntime{
		config: apiConfig, logger: logger, responseLimit: responseLimit,
		timeout: apiConfig.Timeout, maxAttachments: maxAttachments,
	}
	return &Server{Configuration: config}, nil
}

func parseAllowedVaultHosts(value string) []string {
	var hosts []string
	for _, host := range strings.Split(value, ",") {
		if host = strings.TrimSpace(host); host != "" {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func configuredURL(config Configuration) (string, error) {
	if config.Tenant != "" {
		return delinea.CloudURL(config.Tenant, config.TLD)
	}
	return delinea.NormalizeURL(config.ServerURL, config.AllowInsecureHTTP)
}

func (s Server) operationContext() (context.Context, context.CancelFunc) {
	timeout := defaultHTTPTimeout
	if s.runtime != nil {
		timeout = s.runtime.timeout
	} else if s.Timeout > 0 {
		timeout = s.Timeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (s Server) newOperationBudget() *operationBudget {
	maxAttachments := defaultMaxAttachments
	if s.runtime != nil {
		maxAttachments = s.runtime.maxAttachments
	} else if s.MaxAttachmentDownloads > 0 {
		maxAttachments = s.MaxAttachmentDownloads
	}
	responseLimit := s.maxResponseBytes()
	return &operationBudget{
		initialBytes:   responseLimit,
		remainingBytes: responseLimit,
		maxAttachments: maxAttachments,
	}
}

func (s Server) log() Logger {
	if s.runtime != nil {
		return s.runtime.logger
	}
	if s.Logger != nil {
		return s.Logger
	}
	return defaultLoggerInstance
}

func (s Server) apiClient(ctx context.Context) (*delinea.Client, error) {
	if s.runtime == nil {
		return nil, fmt.Errorf("server was not initialized by New")
	}
	rt := s.runtime
	for {
		rt.mu.Lock()
		if rt.client != nil {
			client := rt.client
			rt.mu.Unlock()
			return client, nil
		}
		if flight := rt.starting; flight != nil {
			rt.mu.Unlock()
			select {
			case <-flight.done:
				if flight.err != nil && flight.leaderLocal {
					continue
				}
				return flight.client, flight.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		flight := &clientInitialization{done: make(chan struct{})}
		rt.starting = flight
		rt.mu.Unlock()
		return rt.runInitialization(ctx, flight)
	}
}

func (rt *serverRuntime) runInitialization(ctx context.Context, flight *clientInitialization) (client *delinea.Client, err error) {
	completed := false
	publish := func(client *delinea.Client, err error, leaderLocal bool) {
		rt.mu.Lock()
		flight.client, flight.err, flight.leaderLocal = client, err, leaderLocal
		if err == nil {
			rt.client = client
		}
		rt.starting = nil
		close(flight.done)
		rt.mu.Unlock()
		completed = true
	}
	defer func() {
		if !completed {
			// Caller-supplied TLS callbacks and transports are arbitrary code. A
			// panic must not strand every waiter behind an unclosed flight.
			publish(nil, fmt.Errorf("API client initialization aborted"), true)
		}
	}()
	client, err = initializeAPIClient(ctx, rt.config)
	publish(client, err, ctx.Err() != nil && errors.Is(err, ctx.Err()))
	return client, err
}

func initializeAPIClient(ctx context.Context, config delinea.Config) (*delinea.Client, error) {
	resolved, err := config.WithProbedTarget(ctx)
	if err != nil {
		return nil, err
	}
	return delinea.New(resolved)
}

func (s Server) requestPath(resource, path string) string {
	base := "/" + strings.Trim(s.apiPathURI, "/") + "/" + strings.Trim(resource, "/")
	if path == "" {
		return base + "/"
	}
	if path == "/" {
		return base + "/"
	}
	return base + "/" + strings.TrimPrefix(path, "/")
}

func (s Server) accessResourceContextWithBudget(ctx context.Context, method, resource, path string, input interface{}, budget *operationBudget) ([]byte, error) {
	if resource != "secrets" && resource != "secret-templates" {
		return nil, fmt.Errorf("unknown resource")
	}
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	withholdDiagnostic := input != nil || strings.Contains(path, "?")
	return s.doWithBudget(ctx, delinea.Request{Method: method, Path: s.requestPath(resource, path), Body: body}, budget, withholdDiagnostic)
}

func (s Server) searchResourcesContextWithBudget(ctx context.Context, resource, searchText, field string, budget *operationBudget) ([]byte, error) {
	if resource != "secrets" {
		return nil, fmt.Errorf("unknown resource")
	}
	query := url.Values{}
	query.Set("paging.filter.searchText", searchText)
	query.Set("paging.filter.searchField", field)
	query.Set("paging.filter.doNotCalculateTotal", "true")
	query.Set("paging.take", "30")
	query.Set("paging.skip", "0")
	if field == "" {
		for _, name := range []string{"Machine", "Notes", "Username"} {
			query.Add("paging.filter.extendedFields", name)
		}
	} else {
		query.Set("paging.filter.isExactMatch", "true")
	}
	path := strings.TrimSuffix(s.requestPath(resource, ""), "/") + "?" + query.Encode()
	return s.doWithBudget(ctx, delinea.Request{Method: http.MethodGet, Path: path}, budget, true)
}

func (s Server) doWithBudget(ctx context.Context, request delinea.Request, budget *operationBudget, withholdDiagnostic bool) ([]byte, error) {
	client, err := s.apiClient(ctx)
	if err != nil {
		return nil, err
	}
	request.UseVault = client.Target() == delinea.TargetPlatform
	limit := budget.remainingBytes
	response, err := client.DoBufferedResponse(ctx, request, limit+1)
	if err != nil {
		return nil, err
	}
	body, err := handleBufferedResponse(response, limit, withholdDiagnostic)
	if err != nil {
		return nil, err
	}
	if err := budget.consume(body); err != nil {
		return nil, err
	}
	return body, nil
}

func (s Server) uploadFile(secretID int, field SecretField) error {
	ctx, cancel := s.operationContext()
	defer cancel()
	return s.uploadFileContext(ctx, secretID, field)
}

func (s Server) uploadFileContext(ctx context.Context, secretID int, field SecretField) error {
	return s.uploadFileContextWithBudget(ctx, secretID, field, s.newOperationBudget())
}

func (s Server) uploadFileContextWithBudget(ctx context.Context, secretID int, field SecretField, budget *operationBudget) error {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	filename := field.Filename
	if filename == "" {
		filename = "File.txt"
	} else if match, _ := regexp.MatchString(`[^.]+\.\w+$`, filename); !match {
		filename += ".txt"
	}
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, strings.NewReader(field.ItemValue)); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	path := fmt.Sprintf("%d/fields/%s", secretID, url.PathEscape(field.Slug))
	_, err = s.doWithBudget(ctx, delinea.Request{
		Method: http.MethodPut,
		Path:   s.requestPath("secrets", path),
		Header: http.Header{"Content-Type": {writer.FormDataContentType()}},
		Body:   body,
	}, budget, true)
	return err
}

func (s Server) maxResponseBytes() int64 {
	if s.runtime != nil {
		return s.runtime.responseLimit
	}
	if s.MaxResponseBytes > 0 {
		return min(s.MaxResponseBytes, int64(math.MaxInt64-1))
	}
	return defaultMaxResponseBytes
}

type legacyLogHandler struct {
	logger Logger
	attrs  []slog.Attr
	groups []string
}

func slogFor(logger Logger) *slog.Logger {
	if logger == nil {
		return nil
	}
	return slog.New(&legacyLogHandler{logger: logger})
}

func (*legacyLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *legacyLogHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := slices.Clone(h.attrs)
	record.Attrs(func(attr slog.Attr) bool { attrs = append(attrs, attr); return true })
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s", strings.ToUpper(record.Level.String()), sanitizeLogText(record.Message))
	for _, group := range h.groups {
		fmt.Fprintf(&b, " group=%q", sanitizeLogText(group))
	}
	for _, attr := range attrs {
		fmt.Fprintf(&b, " %q=%q", sanitizeLogText(attr.Key), sanitizeLogText(attr.Value.String()))
	}
	h.logger.Print(b.String())
	return nil
}

func sanitizeLogText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, value)
}

func (h *legacyLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(slices.Clone(h.attrs), attrs...)
	return &clone
}

func (h *legacyLogHandler) WithGroup(name string) slog.Handler {
	clone := *h
	clone.groups = append(slices.Clone(h.groups), name)
	return &clone
}

// Deprecated wire types retained for v3 compatibility.
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
