package server

import (
	"bytes"
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

	accessToken, err := s.getAccessToken()

	if err != nil {
		log.Print("[ERROR] error getting accessToken:", err)
		return nil, err
	}

	req, err := http.NewRequest(method, s.urlFor(resource, path), body)

	if err != nil {
		log.Printf("[ERROR] creating req: %s /%s/%s: %s", method, resource, path, err)
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

// searchResources uses the accessToken to search for API resources.
// It assumes an appropriate combination of resource, search text.
// field is optional
func (s Server) searchResources(resource, searchText, field string) ([]byte, error) {
	switch resource {
	case "secrets":
	default:
		message := "unknown resource"

		log.Printf("[ERROR] %s: %s", message, resource)
		return nil, fmt.Errorf(message)
	}

	method := "GET"
	body := bytes.NewBuffer([]byte{})

	accessToken, err := s.getAccessToken()

	if err != nil {
		log.Print("[ERROR] error getting accessToken:", err)
		return nil, err
	}

	req, err := http.NewRequest(method, s.urlForSearch(resource, searchText, field), body)

	if err != nil {
		log.Printf("[ERROR] creating req: %s /%s/%s/%s: %s", method, resource, searchText, field, err)
		return nil, err
	}

	req.Header.Add("Authorization", "Bearer "+accessToken)

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
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	log.Printf("[DEBUG] uploading file with PUT %s", req.URL.String())
	_, _, err = handleResponse((&http.Client{}).Do(req))

	return err
}

func (s *Server) setCacheAccessToken(value string, expiresIn int) error {
	cache := TokenCache{}
	cache.AccessToken = value
	cache.ExpiresIn = (int(time.Now().Unix()) + expiresIn) - int(math.Floor(float64(expiresIn)*0.9))

	data, _ := json.Marshal(cache)
	os.Setenv("SS_AT", string(data))
	return nil
}

func (s *Server) getCacheAccessToken() (string, bool) {
	data, ok := os.LookupEnv("SS_AT")
	if !ok {
		os.Setenv("SS_AT", "")
		return "", ok
	}
	cache := TokenCache{}
	if err := json.Unmarshal([]byte(data), &cache); err != nil {
		return "", false
	}
	if time.Now().Unix() < int64(cache.ExpiresIn) {
		return cache.AccessToken, true
	}
	return "", false
}

// getAccessToken gets an OAuth2 Access Grant and returns the token
// endpoint and get an accessGrant.
func (s *Server) getAccessToken() (string, error) {
	if s.Credentials.Token != "" {
		return s.Credentials.Token, nil
	}
	accessToken, found := s.getCacheAccessToken()
	if found {
		return accessToken, nil
	}

	response, err := s.checkPlatformDetails()
	if err != nil {
		log.Print("Error while checking server details:", err)
		return "", err
	} else if err == nil && response == "" {
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
		data, _, err := handleResponse(http.Post(requestUrl, "application/x-www-form-urlencoded", body))

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
		s.setCacheAccessToken(grant.AccessToken, grant.ExpiresIn)
		return grant.AccessToken, nil
	} else {
		return response, nil
	}
}

func (s *Server) checkPlatformDetails() (string, error) {
	var baseURL string

	if s.ServerURL == "" {
		baseURL = fmt.Sprintf(cloudBaseURLTemplate, s.Tenant, s.TLD)
	} else {
		baseURL = s.ServerURL
	}

	platformHelthCheckUrl := fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "health")
	ssHealthCheckUrl := fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "healthcheck.aspx")

	isHealthy := checkJSONResponse(ssHealthCheckUrl)
	if isHealthy {
		return "", nil
	} else {
		isHealthy := checkJSONResponse(platformHelthCheckUrl)
		if isHealthy {
			requestData := map[string]string{
				"User":    s.Credentials.Username,
				"Version": "1.0",
			}
			jsonData, err := json.Marshal(requestData)
			if err != nil {
				log.Print("Error marshaling JSON:", err)
				return "", err
			}

			req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "identity/Security/StartAuthentication"), bytes.NewBuffer(jsonData))
			if err != nil {
				log.Print("Error creating HTTP request:", err)
				return "", err
			}

			data, _, err := handleResponse((&http.Client{}).Do(req))
			if err != nil {
				log.Print("[ERROR] start authetication response error:", err)
				return "", err
			}

			var startAuthjsonResponse StartAuthResponse
			if err = json.Unmarshal(data, &startAuthjsonResponse); err != nil {
				log.Print("[ERROR] parsing start auth response:", err)
				return "", err
			}

			requestData = map[string]string{
				"Answer":      s.Credentials.Password,
				"MechanismId": findMechanismId(startAuthjsonResponse),
				"Action":      "Answer",
				"SessionId":   startAuthjsonResponse.Result.SessionId,
				"TenantId":    startAuthjsonResponse.Result.TenantId,
			}

			jsonData, err = json.Marshal(requestData)
			if err != nil {
				log.Print("Error marshaling JSON:", err)
				return "", err
			}

			req, err = http.NewRequest("POST", fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "identity/Security/AdvanceAuthentication"), bytes.NewBuffer(jsonData))
			if err != nil {
				log.Print("Error creating HTTP request:", err)
				return "", err
			}

			data, _, err = handleResponse((&http.Client{}).Do(req))
			if err != nil {
				log.Print("[ERROR] advance authetication response error:", err)
				return "", err
			}

			var advanceAuthJsonResponse AdvanceAuthResponse
			if err = json.Unmarshal(data, &advanceAuthJsonResponse); err != nil {
				log.Print("[ERROR] parsing advance auth response:", err)
				return "", err
			}

			req, err = http.NewRequest("GET", fmt.Sprintf("%s/%s", strings.Trim(baseURL, "/"), "vaultbroker/api/vaults"), bytes.NewBuffer([]byte{}))
			if err != nil {
				log.Print("Error creating HTTP request:", err)
				return "", err
			}
			req.Header.Add("Authorization", "Bearer "+advanceAuthJsonResponse.Result.OAuthTokens.AccessToken)

			data, _, err = handleResponse((&http.Client{}).Do(req))
			if err != nil {
				log.Print("[ERROR] get vaults response error:", err)
				return "", err
			}

			var vaultJsonResponse VaultsResponseModel
			if err = json.Unmarshal(data, &vaultJsonResponse); err != nil {
				log.Print("[ERROR] parsing vaults response:", err)
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

			return advanceAuthJsonResponse.Result.OAuthTokens.AccessToken, nil
		}
	}
	return "", fmt.Errorf("invalid URL")
}

func checkJSONResponse(url string) bool {
	response, err := http.Get(url)
	if err != nil {
		log.Println("Error making GET request:", err)
		return false
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("Error reading response body:", err)
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

func findMechanismId(saResponse StartAuthResponse) string {
	for _, challenge := range saResponse.Result.Challenges {
		for _, mechanism := range challenge.Mechanisms {
			if mechanism.PromptSelectMech == "Password" {
				return mechanism.MechanismId
			}
		}
	}
	return ""
}

type Response struct {
	Healthy               bool `json:"healthy"`
	DatabaseHealthy       bool `json:"databaseHealthy"`
	ServiceBusHealthy     bool `json:"serviceBusHealthy"`
	StorageAccountHealthy bool `json:"storageAccountHealthy"`
	ScheduledForDeletion  bool `json:"scheduledForDeletion"`
}

type ClientHints struct {
	PersistDefault      bool   `json:"PersistDefault"`
	AllowPersist        bool   `json:"AllowPersist"`
	AllowForgotPassword bool   `json:"AllowForgotPassword"`
	StartingPoint       string `json:"StartingPoint"`
	RequestedUsername   string `json:"RequestedUsername"`
}

type Mechanism struct {
	AnswerType       string `json:"AnswerType"`
	Name             string `json:"Name"`
	PromptMechChosen string `json:"PromptMechChosen"`
	PromptSelectMech string `json:"PromptSelectMech"`
	MechanismId      string `json:"MechanismId"`
}

type Challenge struct {
	Mechanisms []Mechanism `json:"Mechanisms"`
}

type Result struct {
	ClientHints        ClientHints `json:"ClientHints"`
	Version            string      `json:"Version"`
	SessionId          string      `json:"SessionId"`
	AllowLoginMfaCache bool        `json:"AllowLoginMfaCache"`
	Challenges         []Challenge `json:"Challenges"`
	Summary            string      `json:"Summary"`
	TenantId           string      `json:"TenantId"`
}

type StartAuthResponse struct {
	Success         bool        `json:"success"`
	Result          Result      `json:"Result"`
	Message         interface{} `json:"Message"`
	MessageID       interface{} `json:"MessageID"`
	Exception       interface{} `json:"Exception"`
	ErrorID         interface{} `json:"ErrorID"`
	ErrorCode       interface{} `json:"ErrorCode"`
	IsSoftError     bool        `json:"IsSoftError"`
	InnerExceptions interface{} `json:"InnerExceptions"`
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

type AdvanceAuthResult struct {
	AuthLevel     string      `json:"AuthLevel"`
	DisplayName   string      `json:"DisplayName"`
	OAuthTokens   OAuthTokens `json:"OAuthTokens"`
	UserId        string      `json:"UserId"`
	EmailAddress  string      `json:"EmailAddress"`
	UserDirectory string      `json:"UserDirectory"`
	StartingPoint string      `json:"StartingPoint"`
	PodFqdn       string      `json:"PodFqdn"`
	User          string      `json:"User"`
	CustomerID    string      `json:"CustomerID"`
	SystemID      string      `json:"SystemID"`
	SourceDsType  string      `json:"SourceDsType"`
	Summary       string      `json:"Summary"`
}

type AdvanceAuthResponse struct {
	Success         bool              `json:"success"`
	Result          AdvanceAuthResult `json:"Result"`
	Message         interface{}       `json:"Message"`
	MessageID       interface{}       `json:"MessageID"`
	Exception       interface{}       `json:"Exception"`
	ErrorID         interface{}       `json:"ErrorID"`
	ErrorCode       interface{}       `json:"ErrorCode"`
	IsSoftError     bool              `json:"IsSoftError"`
	InnerExceptions interface{}       `json:"InnerExceptions"`
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
