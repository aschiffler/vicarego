// main.go
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/joho/godotenv"
)

// Constants for the Viessmann API
const (
	authURL          = "https://iam.viessmann.com/idp/v2/authorize"
	tokenURL         = "https://iam.viessmann.com/idp/v2/token"
	installationsURL = "https://api.viessmann.com/iot/v1/equipment/installations?includeGateways=true"
	scope            = "offline_access" // Required to get a refresh token
)

// Config holds the application configuration loaded from environment variables.
type Config struct {
	Username        string
	Password        string
	ClientID        string
	RedirectURI     string
	PollingInterval time.Duration
	FeaturesToPoll  []string
	MqttBrokerURI   string
	MqttClientID    string
	MqttUsername    string
	MqttPassword    string
	MqttTopicPrefix string
}

// Installation represents the data for a single installation.
type Installation struct {
	ID       int `json:"id"`
	Gateways []struct {
		Serial  string `json:"serial"`
		Devices []struct {
			Id string `json:"id"`
		} `json:"devices"`
	} `json:"gateways"`
}

// InstallationsResponse is the top-level structure for the installations API response.
type InstallationsResponse struct {
	Data []Installation `json:"data"`
}

// Feature represents a single data point that can be queried.
type Feature struct {
	Name           string `json:"feature"`
	Uri            string `json:"uri"`
	InstallationID int
	DeviceID       string
}

// FeatureData represents the processed data for a single feature, ready for output.
type FeatureData struct {
	Topic string
	Value string
}

// Token represents the OAuth2 token data.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	TokenType    string    `json:"token_type"`
	Expiry       time.Time // Calculated time when the token expires
}

// IsExpired checks if the access token is expired or close to expiring.
// It checks if the token will expire in the next 60 seconds.
func (t *Token) IsExpired() bool {
	if t == nil {
		return true
	}
	return t.Expiry.Before(time.Now().Add(60 * time.Second))
}

// APIClient manages the API authentication and calls.
type APIClient struct {
	httpClient *http.Client
	config     *Config
	token      *Token
	features   []Feature    // Stores the latest fetched features
	tokenMutex sync.RWMutex // Protects the token during concurrent access/refresh
}

// NewAPIClient creates and initializes a new APIClient.
func NewAPIClient(config *Config) *APIClient {
	return &APIClient{
		config: config,
		// Create a client that does NOT follow redirects automatically.
		// This is crucial for capturing the 'Location' header to get the authorization code.
		httpClient: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// generatePKCE generates a code_verifier and a corresponding S256 code_challenge.
func generatePKCE() (verifier, challenge string, err error) {
	// 1. Generate a high-entropy cryptographic random string as the verifier.
	// A 32-byte random string becomes a 43-character URL-safe base64 string.
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes for verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(randomBytes)

	// 2. Calculate the SHA256 hash of the verifier.
	sha256Hash := sha256.Sum256([]byte(verifier))

	// 3. Base64-URL-encode the hash to get the challenge.
	challenge = base64.RawURLEncoding.EncodeToString(sha256Hash[:])

	return verifier, challenge, nil
}

// getAuthorizationCode performs the first step of the PKCE flow.
func (c *APIClient) getAuthorizationCode(challenge string) (string, error) {
	log.Println("Requesting authorization code...")

	// Build the request URL with necessary query parameters.
	reqURL, err := url.Parse(authURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse auth URL: %w", err)
	}
	params := url.Values{}
	params.Add("client_id", c.config.ClientID)
	params.Add("redirect_uri", c.config.RedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", scope)
	params.Add("code_challenge", challenge)
	params.Add("code_challenge_method", "S256")
	reqURL.RawQuery = params.Encode()

	req, err := http.NewRequest("POST", reqURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create auth code request: %w", err)
	}

	// The API requires Basic Authentication with username and password for this step.
	req.SetBasicAuth(c.config.Username, c.config.Password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute auth code request: %w", err)
	}
	defer resp.Body.Close()

	// We expect a 302 Redirect.
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("expected status 302 Found but got %d. Body: %s", resp.StatusCode, string(body))
	}

	// The authorization code is in the 'Location' header of the redirect response.
	location, err := resp.Location()
	if err != nil {
		return "", fmt.Errorf("failed to get location header from response: %w", err)
	}

	// Extract the 'code' query parameter from the redirect URL.
	authCode := location.Query().Get("code")
	if authCode == "" {
		return "", fmt.Errorf("authorization code not found in redirect URL")
	}

	log.Println("Successfully obtained authorization code.")
	return authCode, nil
}

// getToken exchanges the authorization code for an access token.
func (c *APIClient) getToken(authCode, verifier string) error {
	log.Println("Exchanging authorization code for access token...")

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authCode)
	data.Set("redirect_uri", c.config.RedirectURI)
	data.Set("client_id", c.config.ClientID)
	data.Set("code_verifier", verifier)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Use a standard HTTP client here, not the one that blocks redirects.
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("expected status 200 OK but got %d. Body: %s", resp.StatusCode, string(body))
	}

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	// Calculate the absolute expiry time.
	token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

	c.tokenMutex.Lock()
	c.token = &token
	c.tokenMutex.Unlock()

	log.Println("Successfully obtained access and refresh tokens.")
	return nil
}

// Authenticate performs the full PKCE flow to get the initial tokens.
func (c *APIClient) Authenticate() error {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return fmt.Errorf("failed to generate PKCE codes: %w", err)
	}

	authCode, err := c.getAuthorizationCode(challenge)
	if err != nil {
		return fmt.Errorf("failed to get authorization code: %w", err)
	}

	return c.getToken(authCode, verifier)
}

// refreshToken uses the refresh token to get a new access token.
func (c *APIClient) refreshToken() error {
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()

	// Double-check if a refresh is still needed in case another goroutine just did it.
	if c.token != nil && !c.token.IsExpired() {
		return nil
	}

	log.Println("Access token expired. Refreshing...")
	if c.token == nil || c.token.RefreshToken == "" {
		return fmt.Errorf("cannot refresh token: no refresh token available")
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", c.token.RefreshToken)
	data.Set("client_id", c.config.ClientID)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create refresh token request: %w", err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute refresh token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// If refresh fails, we might need to re-authenticate from scratch.
		c.token = nil // Invalidate the old token.
		return fmt.Errorf("refresh token request failed with status %d. Body: %s", resp.StatusCode, string(body))
	}

	var newToken Token
	if err := json.NewDecoder(resp.Body).Decode(&newToken); err != nil {
		return fmt.Errorf("failed to decode refreshed token response: %w", err)
	}

	// The API might not return a new refresh token. If it doesn't, reuse the old one.
	if newToken.RefreshToken == "" {
		newToken.RefreshToken = c.token.RefreshToken
	}

	newToken.Expiry = time.Now().Add(time.Duration(newToken.ExpiresIn) * time.Second)
	c.token = &newToken

	log.Println("Token refreshed successfully.")
	return nil
}

// GetInstallations fetches the installation data from the API.
// It handles token refreshing automatically.
func (c *APIClient) GetInstallations(ctx context.Context) ([]Installation, error) {
	c.tokenMutex.RLock()
	tokenIsExpired := c.token.IsExpired()
	c.tokenMutex.RUnlock()

	if tokenIsExpired {
		if err := c.refreshToken(); err != nil {
			// If refresh fails, try a full re-authentication.
			log.Println("Token refresh failed, attempting full re-authentication...")
			if authErr := c.Authenticate(); authErr != nil {
				return nil, fmt.Errorf("re-authentication failed after token refresh error: %w", authErr)
			}
		}
	}

	c.tokenMutex.RLock()
	accessToken := c.token.AccessToken
	c.tokenMutex.RUnlock()

	req, err := http.NewRequestWithContext(ctx, "GET", installationsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create installations request: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Accept", "application/json")

	log.Println("Fetching installation data...")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute installations request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read installations response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("installations API returned non-200 status: %d. Body: %s", resp.StatusCode, string(body))
	}
	//log.Printf("Installation response body: %s", string(body))

	var installationsResp InstallationsResponse
	if err := json.Unmarshal(body, &installationsResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal installations response: %w", err)
	}

	return installationsResp.Data, nil
}

// GetFeatures fetches the features for a given installation and gateway.
func (c *APIClient) GetFeatures(ctx context.Context, installationID int, gatewaySerial string, deviceId string) ([]Feature, error) {
	// No need to check for token expiry here, as any API call will do it.
	// We assume GetInstallations was called just before this.
	c.tokenMutex.RLock()
	accessToken := c.token.AccessToken
	c.tokenMutex.RUnlock()

	if accessToken == "" {
		return nil, fmt.Errorf("cannot get features, no access token available")
	}

	featuresURL := fmt.Sprintf("https://api.viessmann.com/iot/v1/equipment/installations/%d/gateways/%s/devices/%s/features", installationID, gatewaySerial, deviceId)

	req, err := http.NewRequestWithContext(ctx, "GET", featuresURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create features request: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute features request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read features response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("features API returned non-200 status: %d. Body: %s", resp.StatusCode, string(body))
	}

	//log.Printf("Features response body: %s", string(body))

	var featuresResponse struct {
		Data []Feature `json:"data"`
	}
	if err := json.Unmarshal(body, &featuresResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal features response: %w", err)
	}

	return featuresResponse.Data, nil
}

// GetFeatureValue fetches the current value of a single feature by its URI.
// It handles token refreshing automatically.
func (c *APIClient) GetFeatureValue(ctx context.Context, feature Feature) (*FeatureData, error) {
	c.tokenMutex.RLock()
	tokenIsExpired := c.token.IsExpired()
	c.tokenMutex.RUnlock()

	if tokenIsExpired {
		if err := c.refreshToken(); err != nil {
			log.Println("Token refresh failed, attempting full re-authentication...")
			if authErr := c.Authenticate(); authErr != nil {
				return nil, fmt.Errorf("re-authentication failed after token refresh error: %w", authErr)
			}
		}
	}

	c.tokenMutex.RLock()
	accessToken := c.token.AccessToken
	c.tokenMutex.RUnlock()

	req, err := http.NewRequestWithContext(ctx, "GET", feature.Uri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create feature value request: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)
	req.Header.Add("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute feature value request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read feature value response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feature value API returned non-200 status: %d. Body: %s", resp.StatusCode, string(body))
	}

	// The API response for a feature value is a JSON object,
	// typically with a structure like: {"data": {"value": ..., "status": "..."}}
	// Based on the new structure, it is: {"data": {"properties": {"value": {"value": ...}}}}
	var response struct {
		Data struct {
			Properties struct {
				Value struct {
					Value json.RawMessage `json:"value"`
				} `json:"value"`
			} `json:"properties"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal feature value response: %w. Body: %s", err, string(body))
	}

	// Convert the raw value to a string. It might be a number, boolean, or string.
	// We unquote string values to get the clean content.
	valueStr := string(response.Data.Properties.Value.Value)
	if unquoted, err := strconv.Unquote(valueStr); err == nil {
		valueStr = unquoted
	}

	// Construct the MQTT topic path.
	mqttTopic := fmt.Sprintf("%s/%d/%s/%s", c.config.MqttTopicPrefix, feature.InstallationID, feature.DeviceID, feature.Name)

	return &FeatureData{Topic: mqttTopic, Value: valueStr}, nil
}

// loadConfig loads configuration from environment variables.
func loadConfig() (*Config, error) {
	pollingIntervalStr := os.Getenv("POLLING_INTERVAL_SECONDS")
	if pollingIntervalStr == "" {
		pollingIntervalStr = "120" // Default to 120 seconds
	}

	pollingIntervalInt, err := strconv.Atoi(pollingIntervalStr)
	if err != nil {
		return nil, fmt.Errorf("invalid POLLING_INTERVAL_SECONDS: %w", err)
	}

	if pollingIntervalInt < 120 {
		log.Printf("Warning: POLLING_INTERVAL_SECONDS is set to %d, which is less than the minimum of 120. Using 120 seconds.", pollingIntervalInt)
		pollingIntervalInt = 120
	}

	// Parse FEATURES_TO_POLL
	featuresToPollStr := os.Getenv("FEATURES_TO_POLL")
	var featuresToPoll []string
	if featuresToPollStr != "" {
		rawFeatures := strings.Split(featuresToPollStr, ",")
		for _, f := range rawFeatures {
			trimmed := strings.TrimSpace(f)
			if trimmed != "" {
				featuresToPoll = append(featuresToPoll, trimmed)
			}
		}
	}

	mqttTopicPrefix := os.Getenv("MQTT_TOPIC_PREFIX")
	if mqttTopicPrefix == "" {
		mqttTopicPrefix = "vicare"
	}

	cfg := &Config{
		Username:        os.Getenv("VIESSMANN_USERNAME"),
		Password:        os.Getenv("VIESSMANN_PASSWORD"),
		ClientID:        os.Getenv("VIESSMANN_CLIENT_ID"),
		RedirectURI:     os.Getenv("VIESSMANN_REDIRECT_URI"),
		PollingInterval: time.Duration(pollingIntervalInt) * time.Second,
		FeaturesToPoll:  featuresToPoll,
		MqttBrokerURI:   os.Getenv("MQTT_BROKER_URI"),
		MqttClientID:    os.Getenv("MQTT_CLIENT_ID"),
		MqttUsername:    os.Getenv("MQTT_USERNAME"),
		MqttPassword:    os.Getenv("MQTT_PASSWORD"),
		MqttTopicPrefix: mqttTopicPrefix,
	}

	if cfg.Username == "" || cfg.Password == "" || cfg.ClientID == "" || cfg.RedirectURI == "" {
		return nil, fmt.Errorf("one or more required environment variables are not set: VIESSMANN_USERNAME, VIESSMANN_PASSWORD, VIESSMANN_CLIENT_ID, VIESSMANN_REDIRECT_URI")
	}

	if len(cfg.FeaturesToPoll) == 0 {
		log.Println("Warning: FEATURES_TO_POLL is not set or is empty. No feature data will be polled.")
	}

	return cfg, nil
}

// discoverFeatures performs a one-time discovery of all available features.
func discoverFeatures(ctx context.Context, client *APIClient) error {
	log.Println("--- Starting initial feature discovery ---")
	installations, err := client.GetInstallations(ctx)
	if err != nil {
		return fmt.Errorf("error getting installations during discovery: %w", err)
	}

	for _, inst := range installations {
		for _, gw := range inst.Gateways {
			for _, dev := range gw.Devices {
				features, err := client.GetFeatures(ctx, inst.ID, gw.Serial, dev.Id)
				if err != nil {
					log.Printf("    Warning: could not get features for device %s: %v", dev.Id, err)
					continue // Try next device
				}
				for _, f := range features {
					f.InstallationID = inst.ID
					f.DeviceID = dev.Id
					client.features = append(client.features, f)
				}
			}
		}
	}
	log.Printf("--- Feature discovery finished. Found %d total features. ---", len(client.features))

	log.Println("--- List of all discovered features ---")
	for _, feature := range client.features {
		log.Println(feature.Name)
	}
	log.Println("---------------------------------------")
	return nil
}

// pollFeatureData is the main work function called periodically to get feature values.
func pollFeatureData(ctx context.Context, client *APIClient, mqttClient mqtt.Client) {
	//log.Println("--- Starting new polling cycle ---")
	// Create a quick lookup map for features to poll
	featuresToPollMap := make(map[string]struct{})
	for _, fName := range client.config.FeaturesToPoll {
		featuresToPollMap[fName] = struct{}{}
	}

	// Iterate through all discovered features and poll the ones we're interested in.
	for _, feature := range client.features {
		if _, ok := featuresToPollMap[feature.Name]; ok {
			log.Printf("Polling feature: %s", feature.Name)
			featureData, err := client.GetFeatureValue(ctx, feature)
			if err != nil {
				log.Printf("  Error getting value for feature %s: %v", feature.Name, err)
				continue
			}
			//log.Printf("  -> Topic: %s, Value: %s", featureData.Topic, featureData.Value)

			// Publish to MQTT if the client is available and connected
			if mqttClient != nil && mqttClient.IsConnected() {
				token := mqttClient.Publish(featureData.Topic, 1, true, featureData.Value)
				// Asynchronously wait for the publish to complete to avoid blocking the polling loop.
				go func(t mqtt.Token, topic string) {
					if t.WaitTimeout(2*time.Second) && t.Error() != nil {
						log.Printf("    Error publishing to MQTT topic %s: %v", topic, t.Error())
					}
				}(token, featureData.Topic)
			}
		}
	}

	//log.Println("--- Polling cycle finished ---")
}

func newMQTTClient(config *Config) mqtt.Client {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(config.MqttBrokerURI)
	opts.SetClientID(config.MqttClientID)
	opts.SetUsername(config.MqttUsername)
	opts.SetPassword(config.MqttPassword)
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.OnConnect = func(c mqtt.Client) {
		log.Println("Connected to MQTT broker.")
	}
	opts.OnConnectionLost = func(c mqtt.Client, err error) {
		log.Printf("MQTT connection lost: %v", err)
	}
	return mqtt.NewClient(opts)
}
func main() {
	log.Println("Starting Viessmann API client...")

	// Load environment variables from .env file.
	// It's okay if the file doesn't exist, we can still rely on shell-exported variables.
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on environment variables.")
	}

	// 1. Load configuration from environment variables
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// 2. Create a new API client
	client := NewAPIClient(config)

	// 3. Perform initial authentication to get the first token
	if err := client.Authenticate(); err != nil {
		log.Fatalf("Initial authentication failed: %v", err)
	}

	// 4. Discover all available features once at startup.
	// Use a longer timeout for this initial, one-time discovery.
	discoveryCtx, discoveryCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	if err := discoverFeatures(discoveryCtx, client); err != nil {
		log.Fatalf("Failed to discover features on startup: %v", err)
	}
	discoveryCancel()

	// 5. Create and connect MQTT client if configured
	var mqttClient mqtt.Client
	if config.MqttBrokerURI != "" {
		mqttClient = newMQTTClient(config)
		log.Printf("Connecting to MQTT broker at %s...", config.MqttBrokerURI)
		if token := mqttClient.Connect(); token.Wait() && token.Error() != nil {
			log.Fatalf("Failed to connect to MQTT broker: %v", token.Error())
		}
		defer mqttClient.Disconnect(250)
	} else {
		log.Println("MQTT_BROKER_URI not configured, will not publish data.")
	}

	// 4. Start the polling loop.
	// The first poll happens immediately, then at each interval.
	//log.Printf("Starting polling loop with an interval of %v.", config.PollingInterval)
	ticker := time.NewTicker(config.PollingInterval)
	defer ticker.Stop()

	// Run first poll immediately
	pollFeatureData(context.Background(), client, mqttClient)
	for range ticker.C {
		// Create a new context for each polling cycle to handle potential timeouts.
		ctx, cancel := context.WithTimeout(context.Background(), config.PollingInterval-5*time.Second)
		pollFeatureData(ctx, client, mqttClient)
		cancel() // Release context resources
	}
}
