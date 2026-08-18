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
	"log/slog"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	delinea "github.com/DelineaXPM/delinea-common/api"
)

const (
	defaultAPIPathURI       = "/api/v1"
	defaultTLD              = "com"
	defaultHTTPTimeout      = 60 * time.Second
	defaultMaxResponseBytes = 100 << 20
	defaultMaxRequestBytes  = 100 << 20
	defaultMaxAttachments   = 100
	defaultMaxSearchResults = 1000
	searchPageSize          = 30
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
	MaxRequestBytes        int64
	MaxAttachmentDownloads int
	MaxSearchResults       int

	runtime *serverRuntime
}

// Server provides access to secrets stored in Delinea Secret Server. Runtime
// state is carried in the private portion of the embedded Configuration.
type Server struct {
	Configuration
}

// TokenCache is retained for v3 source and wire compatibility.
//
// Deprecated: token storage is implemented by delinea-common and no longer uses
// this type internally. It is a v4 deletion candidate.
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
	requestLimit   int64
	timeout        time.Duration
	maxAttachments int
	maxSearch      int
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
	if config.MaxRequestBytes < 0 {
		return nil, fmt.Errorf("max request bytes must not be negative")
	}
	if config.MaxAttachmentDownloads < 0 {
		return nil, fmt.Errorf("max attachment downloads must not be negative")
	}
	if config.MaxSearchResults < 0 {
		return nil, fmt.Errorf("max search results must not be negative")
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
		clone.TLSClientConfig = snapshotTLSConfig(config.TLSClientConfig)
		apiConfig.Transport = clone
		config.TLSClientConfig = snapshotTLSConfig(config.TLSClientConfig)
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
	requestLimit := config.MaxRequestBytes
	if requestLimit <= 0 {
		requestLimit = defaultMaxRequestBytes
	}
	maxAttachments := config.MaxAttachmentDownloads
	if maxAttachments == 0 {
		maxAttachments = defaultMaxAttachments
	}
	maxSearch := config.MaxSearchResults
	if maxSearch == 0 {
		maxSearch = defaultMaxSearchResults
	}
	config.runtime = &serverRuntime{
		config: apiConfig, logger: logger, responseLimit: responseLimit, requestLimit: requestLimit,
		timeout: apiConfig.Timeout, maxAttachments: maxAttachments, maxSearch: maxSearch,
	}
	return &Server{Configuration: config}, nil
}

// snapshotTLSConfig copies the mutable standard-library-owned portions of a
// tls.Config. Interface and callback fields remain shared by necessity; callers
// supplying those fields must keep their implementations safe for concurrent use.
func snapshotTLSConfig(source *tls.Config) *tls.Config {
	clone := source.Clone()
	if source.RootCAs != nil {
		clone.RootCAs = source.RootCAs.Clone()
	}
	if source.ClientCAs != nil {
		clone.ClientCAs = source.ClientCAs.Clone()
	}
	clone.NextProtos = slices.Clone(source.NextProtos)
	clone.CipherSuites = slices.Clone(source.CipherSuites)
	clone.CurvePreferences = slices.Clone(source.CurvePreferences)
	clone.EncryptedClientHelloConfigList = bytes.Clone(source.EncryptedClientHelloConfigList)
	clone.Certificates = make([]tls.Certificate, len(source.Certificates))
	for i, certificate := range source.Certificates {
		clone.Certificates[i] = certificate
		clone.Certificates[i].Certificate = cloneByteSlices(certificate.Certificate)
		clone.Certificates[i].SupportedSignatureAlgorithms = slices.Clone(certificate.SupportedSignatureAlgorithms)
		clone.Certificates[i].OCSPStaple = bytes.Clone(certificate.OCSPStaple)
		clone.Certificates[i].SignedCertificateTimestamps = cloneByteSlices(certificate.SignedCertificateTimestamps)
		if certificate.Leaf != nil && len(clone.Certificates[i].Certificate) > 0 {
			// Parse from the copied DER instead of retaining the caller's mutable
			// parsed-certificate pointer. A nil Leaf lets crypto/tls parse lazily.
			clone.Certificates[i].Leaf, _ = x509.ParseCertificate(clone.Certificates[i].Certificate[0])
		}
	}
	clone.EncryptedClientHelloKeys = make([]tls.EncryptedClientHelloKey, len(source.EncryptedClientHelloKeys))
	for i, key := range source.EncryptedClientHelloKeys {
		clone.EncryptedClientHelloKeys[i] = key
		clone.EncryptedClientHelloKeys[i].Config = bytes.Clone(key.Config)
		clone.EncryptedClientHelloKeys[i].PrivateKey = bytes.Clone(key.PrivateKey)
	}
	// NameToCertificate is deprecated server-only state and must not retain
	// pointers into the caller's certificate slice on this client transport.
	//lint:ignore SA1019 clearing deprecated state is the compatibility-safe snapshot
	clone.NameToCertificate = nil
	return clone
}

func cloneByteSlices(values [][]byte) [][]byte {
	clone := make([][]byte, len(values))
	for i, value := range values {
		clone[i] = bytes.Clone(value)
	}
	return clone
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
		if secret, ok := input.(Secret); ok {
			size, err := secretJSONSize(secret, s.maxRequestBytes())
			if err != nil {
				return nil, err
			}
			if size > s.maxRequestBytes() {
				return nil, fmt.Errorf("request body exceeded %d bytes", s.maxRequestBytes())
			}
		}
		data, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > s.maxRequestBytes() {
			return nil, fmt.Errorf("request body exceeded %d bytes", s.maxRequestBytes())
		}
		body = bytes.NewReader(data)
	}
	requestPath := s.requestPath(resource, path)
	if int64(len(requestPath)) > s.maxRequestBytes() {
		return nil, fmt.Errorf("request target exceeded %d bytes", s.maxRequestBytes())
	}
	withholdDiagnostic := resource == "secrets" ||
		(resource == "secret-templates" && strings.HasPrefix(path, "generate-password/")) ||
		input != nil || strings.Contains(path, "?")
	return s.doWithBudget(ctx, delinea.Request{Method: method, Path: requestPath, Body: body}, budget, withholdDiagnostic)
}

func (s Server) searchResourcesContextWithBudget(ctx context.Context, resource, searchText, field string, skip, take int, budget *operationBudget) ([]byte, error) {
	if resource != "secrets" {
		return nil, fmt.Errorf("unknown resource")
	}
	query := url.Values{}
	query.Set("paging.filter.searchText", searchText)
	query.Set("paging.filter.searchField", field)
	query.Set("paging.filter.doNotCalculateTotal", "true")
	query.Set("paging.take", strconv.Itoa(take))
	query.Set("paging.skip", strconv.Itoa(skip))
	if field == "" {
		for _, name := range []string{"Machine", "Notes", "Username"} {
			query.Add("paging.filter.extendedFields", name)
		}
	} else {
		query.Set("paging.filter.isExactMatch", "true")
	}
	base := strings.TrimSuffix(s.requestPath(resource, ""), "/")
	if requestTargetLength(base, query) > s.maxRequestBytes() {
		return nil, fmt.Errorf("request target exceeded %d bytes", s.maxRequestBytes())
	}
	path := base + "?" + query.Encode()
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

func (s Server) uploadFileContextWithBudget(ctx context.Context, secretID int, field SecretField, budget *operationBudget) error {
	path, err := s.pathWithEscapedSegment("secrets", fmt.Sprintf("%d/fields/", secretID), field.Slug)
	if err != nil {
		return err
	}
	filename := field.Filename
	filenameSuffix := ""
	if filename == "" {
		filename = "File.txt"
	} else if match, _ := regexp.MatchString(`[^.]+\.\w+$`, filename); !match {
		filenameSuffix = ".txt"
	}
	size, err := multipartBodySizeParts(filename, filenameSuffix, len(field.ItemValue))
	if err != nil {
		return err
	}
	if size > s.maxRequestBytes() {
		return fmt.Errorf("request body exceeded %d bytes", s.maxRequestBytes())
	}
	// Append only after the preflight proves the resulting multipart request is
	// within the configured bound. Otherwise an extensionless, caller-controlled
	// filename could force a large duplicate allocation merely to reject it.
	filename += filenameSuffix
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
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
	if int64(body.Len()) > s.maxRequestBytes() {
		return fmt.Errorf("request body exceeded %d bytes", s.maxRequestBytes())
	}
	_, err = s.doWithBudget(ctx, delinea.Request{
		Method: http.MethodPut,
		Path:   s.requestPath("secrets", path),
		Header: http.Header{"Content-Type": {writer.FormDataContentType()}},
		Body:   body,
	}, budget, true)
	return err
}

func (s Server) pathWithEscapedSegment(resource, prefix, segment string) (string, error) {
	targetPrefix := s.requestPath(resource, prefix)
	if joinedLength(int64(len(targetPrefix)), pathEscapedLength(segment)) > s.maxRequestBytes() {
		return "", fmt.Errorf("request target exceeded %d bytes", s.maxRequestBytes())
	}
	return prefix + url.PathEscape(segment), nil
}

func requestTargetLength(base string, query url.Values) int64 {
	return joinedLength(int64(len(base)), 1, encodedQueryLength(query))
}

func encodedQueryLength(query url.Values) int64 {
	var length int64
	first := true
	for key, values := range query {
		for _, value := range values {
			if !first {
				length = joinedLength(length, 1)
			}
			first = false
			length = joinedLength(length, queryEscapedLength(key), 1, queryEscapedLength(value))
		}
	}
	return length
}

func queryEscapedLength(value string) int64 {
	var length int64
	for i := 0; i < len(value); i++ {
		if isURLUnreserved(value[i]) || value[i] == ' ' {
			length = joinedLength(length, 1)
		} else {
			length = joinedLength(length, 3)
		}
	}
	return length
}

func pathEscapedLength(value string) int64 {
	var length int64
	for i := 0; i < len(value); i++ {
		c := value[i]
		if isURLUnreserved(c) || strings.ContainsRune("$&+:=@", rune(c)) {
			length = joinedLength(length, 1)
		} else {
			length = joinedLength(length, 3)
		}
	}
	return length
}

func isURLUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c >= '0' && c <= '9' || strings.ContainsRune("-_.~", rune(c))
}

func joinedLength(parts ...int64) int64 {
	var total int64
	for _, part := range parts {
		if part > math.MaxInt64-total {
			return math.MaxInt64
		}
		total += part
	}
	return total
}

func secretJSONSize(secret Secret, limit int64) (int64, error) {
	// Marshal a payload-shaped value with its strings cleared, then add their
	// exact escaped lengths. This bounds allocation before encoding user data.
	if int64(len(secret.Fields)) > limit/128 {
		if limit == math.MaxInt64 {
			return math.MaxInt64, nil
		}
		return limit + 1, nil
	}
	shape := secret
	shape.Name = ""
	shape.Fields = slices.Clone(secret.Fields)
	for i := range shape.Fields {
		shape.Fields[i].FieldName = ""
		shape.Fields[i].Slug = ""
		shape.Fields[i].FieldDescription = ""
		shape.Fields[i].Filename = ""
		shape.Fields[i].ItemValue = ""
	}
	base, err := json.Marshal(shape)
	if err != nil {
		return 0, err
	}
	size := int64(len(base))
	addString := func(value string) bool {
		additional := jsonStringLength(value) - 2 // shape already contains ""
		if additional > math.MaxInt64-size {
			size = math.MaxInt64
			return false
		}
		size += additional
		return size <= limit
	}
	if !addString(secret.Name) {
		return size, nil
	}
	for _, field := range secret.Fields {
		for _, value := range []string{field.FieldName, field.Slug, field.FieldDescription, field.Filename, field.ItemValue} {
			if !addString(value) {
				return size, nil
			}
		}
	}
	return size, nil
}

func jsonStringLength(value string) int64 {
	length := int64(2) // surrounding quotes
	for i := 0; i < len(value); {
		c := value[i]
		if c < utf8.RuneSelf {
			i++
			switch c {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				length += 2
			case '<', '>', '&':
				length += 6
			default:
				if c < 0x20 {
					length += 6
				} else {
					length++
				}
			}
			continue
		}
		r, width := utf8.DecodeRuneInString(value[i:])
		i += width
		if r == utf8.RuneError && width == 1 || r == '\u2028' || r == '\u2029' {
			length += 6
		} else {
			length += int64(width)
		}
	}
	return length
}

type byteCounter int64

func (c *byteCounter) Write(p []byte) (int, error) {
	*c += byteCounter(len(p))
	return len(p), nil
}

func multipartBodySize(filename string, contentLength int) (int64, error) {
	return multipartBodySizeParts(filename, "", contentLength)
}

func multipartBodySizeParts(filename, suffix string, contentLength int) (int64, error) {
	var count byteCounter
	writer := multipart.NewWriter(&count)
	if _, err := writer.CreateFormFile("file", ""); err != nil {
		return 0, err
	}
	if err := writer.Close(); err != nil {
		return 0, err
	}
	variable := joinedLength(multipartFilenameLength(filename), multipartFilenameLength(suffix))
	if variable > math.MaxInt64-int64(count) {
		return math.MaxInt64, nil
	}
	count += byteCounter(variable)
	if int64(contentLength) > math.MaxInt64-int64(count) {
		return math.MaxInt64, nil
	}
	return int64(count) + int64(contentLength), nil
}

func multipartFilenameLength(filename string) int64 {
	var length int64
	for i := 0; i < len(filename); i++ {
		switch filename[i] {
		case '\r', '\n':
			length += 3 // %0D or %0A
		case '\\', '"':
			length += 2
		default:
			length++
		}
	}
	return length
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

func (s Server) maxRequestBytes() int64 {
	if s.runtime != nil {
		return s.runtime.requestLimit
	}
	if s.MaxRequestBytes > 0 {
		return s.MaxRequestBytes
	}
	return defaultMaxRequestBytes
}

func (s Server) maxSearchResults() int {
	if s.runtime != nil {
		return s.runtime.maxSearch
	}
	if s.MaxSearchResults > 0 {
		return s.MaxSearchResults
	}
	return defaultMaxSearchResults
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
		if unsafeRecordRune(r) {
			return '?'
		}
		return r
	}, value)
}

func unsafeRecordRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029'
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

// Response is the former health-check wire model.
//
// Deprecated: retained only for v3 source compatibility. The delinea-common
// engine owns health checking. This type is a v4 deletion candidate.
type Response struct {
	Healthy               bool `json:"healthy"`
	DatabaseHealthy       bool `json:"databaseHealthy"`
	ServiceBusHealthy     bool `json:"serviceBusHealthy"`
	StorageAccountHealthy bool `json:"storageAccountHealthy"`
	ScheduledForDeletion  bool `json:"scheduledForDeletion"`
}

// OAuthTokens is the former authentication response model.
//
// Deprecated: retained only for v3 source compatibility. The delinea-common
// engine owns authentication. This type is a v4 deletion candidate.
type OAuthTokens struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IdToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	SessionExpiresIn int    `json:"session_expires_in"`
	Scope            string `json:"scope"`
}

// Connection is the former Platform vault connection wire model.
//
// Deprecated: retained only for v3 source compatibility. The delinea-common
// engine owns vault discovery. This type is a v4 deletion candidate.
type Connection struct {
	Url            string `json:"url"`
	OAuthProfileId string `json:"oAuthProfileId"`
}

// Vault is the former Platform vault wire model.
//
// Deprecated: retained only for v3 source compatibility. The delinea-common
// engine owns vault discovery. This type is a v4 deletion candidate.
type Vault struct {
	VaultId         string     `json:"vaultId"`
	Name            string     `json:"name"`
	Type            string     `json:"type"`
	IsDefault       bool       `json:"isDefault"`
	IsGlobalDefault bool       `json:"isGlobalDefault"`
	IsActive        bool       `json:"isActive"`
	Connection      Connection `json:"connection"`
}

// VaultsResponseModel is the former Platform vault-list wire model.
//
// Deprecated: retained only for v3 source compatibility. The delinea-common
// engine owns vault discovery. This type is a v4 deletion candidate.
type VaultsResponseModel struct {
	Vaults []Vault `json:"vaults"`
}
