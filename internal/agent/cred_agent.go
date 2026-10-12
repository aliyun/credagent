package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/credagent/internal/uds"
	"github.com/aliyun/credagent/pkg/logger"
)

// AuditRequest represents the request sent from Main AI Agent to CredAgent
type AuditRequest struct {
	Type   string `json:"type"`
	Intent string `json:"intent"`
	Action struct {
		CommandSpec          string `json:"command_spec"`
		TargetCredentialFile string `json:"target_credential_file"`
	} `json:"action"`
}

// AuditResponse represents the response from CredAgent to Main AI Agent
type AuditResponse struct {
	Type       string  `json:"type"`
	UUID       string  `json:"uuid,omitempty"`
	Decision   string  `json:"decision,omitempty"` // ALLOW or DENY
	Reason     string  `json:"reason,omitempty"`
	Message    string  `json:"message,omitempty"`
	Confidence float64 `json:"confidence_score,omitempty"`
}

// ProcessingEntry represents a request that is currently being processed
type ProcessingEntry struct {
	ResponseChan chan *AuditResponseResult
	Timestamp    time.Time
	Expiration   time.Duration
}

// AuditResponseResult wraps the response and error together
type AuditResponseResult struct {
	Response *AuditResponse
	Error    error
}

// CacheEntry represents a cached response
type CacheEntry struct {
	Response   *AuditResponse
	Timestamp  time.Time
	Expiration time.Duration
}

// CredAgentClientInterface defines the interface for CredAgentClient
type CredAgentClientInterface interface {
	AuditCommandWithTargetFile(commandSpec, intent, targetFile string) (*AuditResponse, error)
	InternalAuditLogic(intent, commandSpec string) *AuditResponse
	RequestPermissionViaEnclave(socketPath, intent, cmdline, targetFile string) (*AuditResponse, error)
}

// CredAgentClient is responsible for auditing credential access requests
type CredAgentClient struct {
	config        *Config
	cache         map[string]*CacheEntry
	processing    map[string]*ProcessingEntry
	mutex         sync.RWMutex
	processingMux sync.Mutex // Separate mutex for processing map to avoid deadlocks
}

// NewCredAgentClient creates a new instance of CredAgentClient
func NewCredAgentClient(config *Config) *CredAgentClient {
	if config == nil {
		logger.Warn("CredAgent config is nil, creating with default settings. Functionality will be limited.")
		config = &Config{
			Provider:   "openai",
			APIURL:     "",
			APIKey:     "",
			ModelName:  "gpt-4",
			TimeoutSec: 30,
		}
	}

	// Log configuration validation
	if config.APIKey == "" {
		logger.Warn("CredAgent is not configured with required API key. Will use internal logic only.")
	}

	client := &CredAgentClient{
		config:     config,
		cache:      make(map[string]*CacheEntry),
		processing: make(map[string]*ProcessingEntry),
	}

	return client
}

// NewCredAgentClientWithDefaults creates a new instance with minimal configuration
func NewCredAgentClientWithDefaults() *CredAgentClient {
	client := &CredAgentClient{
		config:     nil,
		cache:      make(map[string]*CacheEntry),
		processing: make(map[string]*ProcessingEntry),
	}

	return client
}

// RequestPermit sends a request to get a permit UUID for credential access
func (c *CredAgentClient) RequestPermit(intent, commandSpec, targetFile string) (*AuditResponse, error) {
	// Create a detailed prompt for the AI to evaluate the request
	prompt := fmt.Sprintf(`As a security auditor, evaluate the following credential access request:
Intent: "%s"
Command: "%s"
Target Credential File: "%s"

Analyze the intent and the command to determine if this access request is legitimate and safe. Consider:
1. Does the intent match the action?
2. Are there any potential security risks in executing this command?
3. Could this command potentially lead to credential leakage or misuse?
4. Is the command appropriate for accessing the specified credential file?

Respond in JSON format with the following structure:
{
  "decision": "ALLOW or DENY",
  "reason": "Brief explanation of your decision",
  "message": "Detailed explanation of your security analysis",
  "confidence_score": "A number between 0.0 and 1.0 representing your confidence in this assessment"
}`, intent, commandSpec, targetFile)

	return c.callAIWithFallback(prompt, intent, commandSpec)
}

// AuditCommand performs real-time risk assessment of a command
func (c *CredAgentClient) AuditCommand(commandSpec, intent string) (*AuditResponse, error) {
	// First, try our internal audit logic as a quick check
	internalResponse := c.InternalAuditLogic(intent, commandSpec)

	// If the internal logic already denies the request, return early
	if internalResponse.Decision == "DENY" {
		return internalResponse, nil
	}

	// Create a detailed prompt for the AI to evaluate the command
	// The target file is currently not passed to this function, so we use a default placeholder
	// In a complete implementation, this would come from the context of the request
	targetFile := "PROTECTED_CREDENTIAL_FILE"

	prompt := fmt.Sprintf(`As a security auditor, evaluate the following command for potential security risks:
Intent: "%s"
Command: "%s"
Protected File: "%s"

This is a credential access request where the command is requesting access to a protected credential file. This could be legitimate usage where the user needs to access the credentials for authentication purposes, or it could be a malicious attempt to extract credentials.

Your task is to determine if this is a legitimate access or a risky access based on the following CRITERIA. CRITICAL: Only DENY if there is CLEAR AND CONCRETE EVIDENCE that the command violates the criteria. Do NOT deny based on speculation or hypothetical concerns:

1. Intent Reasonableness: Is the intent reasonable? For example, intents like accessing a database, performing cloud operations, or authenticating to a service suggest legitimate use of credentials for authentication. Intents like backing up the protected file, reading the protected file content, or extracting the file suggest lack of reasonable intent and should be rejected. If the intent is reasonable and the command appears to support that intent, this factor supports an ALLOW decision.

2. Intent-Command Matching: Does the intent match the command? For example, if the intent is to access a PostgreSQL database but the command is "cat PROTECTED_CREDENTIAL_FILE", the command and intent do not match and the request should be rejected. However, if the intent is to query a database and the command is "psql -c 'SELECT ...'", this matches the intent even if credentials are involved.

3. Risky Command Construction: Does the command explicitly show risky behavior like printing file contents to stdout, redirecting to other files, piping to network tools, or transmitting data externally? Look specifically for operators like "|", ">", ">>", or commands like "curl", "wget", "scp" that would transmit data. SPECIAL ATTENTION: Commands that directly output file content to the terminal (like "cat", "head", "tail", "less", "more") are inherently risky when dealing with credential files because they expose the sensitive content on the screen. This violates the security principle that credential content should not be displayed directly to users. If the command simply accesses a credential file for authentication purposes (e.g., psql accessing pgpass), this is NOT risky.

CRITICAL RULES:
- Default to ALLOW if the command appears legitimate and serves the stated intent
- Only DENY if you can point to SPECIFIC parts of the command that demonstrate a violation
- Do not deny based on potential alternative uses or hypothetical risks
- If the command is a standard way to perform the stated intent (e.g., psql for database queries), this supports an ALLOW decision
- HOWEVER: Commands that directly output file content to the terminal (like "cat", "head", "tail", "less", "more") are inherently risky when accessing credential files, regardless of intent

Provide your assessment in JSON format:
{
  "decision": "ALLOW or DENY",
  "reason": "Brief explanation of your decision focusing on the specific evidence for your determination",
  "confidence_score": "A number between 0.0 and 1.0 representing your confidence in this assessment"
}`, intent, commandSpec, targetFile)

	return c.callAIWithFallback(prompt, intent, commandSpec)
}

// AuditCommandWithTargetFile performs real-time risk assessment of a command with a specific target file
func (c *CredAgentClient) AuditCommandWithTargetFile(commandSpec, intent, targetFile string) (*AuditResponse, error) {
	// First, try our internal audit logic as a quick check
	internalResponse := c.InternalAuditLogic(intent, commandSpec)

	// If the internal logic already denies the request, return early
	if internalResponse.Decision == "DENY" {
		return internalResponse, nil
	}

	prompt := fmt.Sprintf(`As a security auditor, evaluate if this command poses a risk of credential exposure. 

CONTEXT:
- This command has already passed baseline authorization (the program is whitelisted to access protected files)
- The protected file is: %s
- However, even authorized commands may perform risky operations

INTENT: %s
COMMAND: %s

ANALYSIS:
1. COMMAND RISK: Evaluate the specific command for data exfiltration or unintended file transmission:
   - Does the command upload, copy, or transfer data containing or alongside the credential file?
   - Examples of HIGH RISK: cloud storage uploads (aliyun oss cp local_dir/ oss://bucket), backup commands, network transfers
   - Examples of SAFE: direct authentication operations (aliyun ecs DescribeInstances)

2. INTENT-COMMAND ALIGNMENT: Compare intent vs. actual command:
   - If intent describes "uploading", "copying", "transferring" files that include credentials: RISKY
   - If intent matches safe operation (querying, reading, authenticating): LIKELY SAFE

3. TARGET FILE CONTEXT: Consider if the protected file could be exposed:
   - Protected files are often in directories like ~/.aliyun, ~/.aws, etc.
   - Operations on parent directories may include protected files unexpectedly
   - Commands targeting credential-containing directories are HIGH RISK

DECISION MATRIX:
- HIGH RISK: Command could expose credentials despite authorization (upload, copy, transfer operations)
- LOW RISK: Command only uses credentials for intended purpose (authentication, queries)
- UNCERTAIN: Default to ALLOW (but note uncertainty)

CRITICAL: Even authorized programs like "aliyun" can pose risks if they perform data transfer operations that include protected files.

Respond in JSON format:
{
  "decision": "ALLOW or DENY",
  "reason": "Analysis of both command semantics and intent alignment, with specific reference to potential credential exposure",
  "confidence_score": "0.0 to 1.0 based on clarity of risk"
}`, targetFile, intent, commandSpec)

	return c.callAIWithFallback(prompt, intent, commandSpec)
}

// callAIWithFallback attempts to call the AI model, falling back to internal logic if needed
func (c *CredAgentClient) callAIWithFallback(prompt, intent, commandSpec string) (*AuditResponse, error) {
	// Check if the AI is properly configured
	if c.config == nil || c.config.APIKey == "" || c.config.APIURL == "" || c.config.ModelName == "" {
		logger.Error("CredAgent is not properly configured with required API settings. AI access denied.")
		// Return a response that denies access
		return &AuditResponse{
			Type:       "AUDIT_RESPONSE",
			Decision:   "DENY",
			Reason:     "CredAgent is not properly configured with required API settings",
			Message:    "The CredAgent system requires a valid API key, URL, and model name to operate. Please check configuration.",
			Confidence: 1.0,
		}, nil
	}

	// Try to call the actual AI model
	response, err := c.callAIModel(prompt)
	if err != nil {
		logger.Error("Failed to call AI model: %v. AI access denied.", err)
		// Return a response that denies access
		return &AuditResponse{
			Type:       "AUDIT_RESPONSE",
			Decision:   "DENY",
			Reason:     "Failed to communicate with AI model",
			Message:    fmt.Sprintf("Error communicating with AI model: %v", err),
			Confidence: 0.9,
		}, nil
	}

	return response, nil
}

// calculateRequestHash computes a hash of the request parameters to use as cache key
func (c *CredAgentClient) calculateRequestHash(prompt string) string {
	hash := sha256.Sum256([]byte(prompt))
	return fmt.Sprintf("%x", hash[:])
}

// getFromCache retrieves a cached response if it exists and hasn't expired
func (c *CredAgentClient) getFromCache(hash string) (*AuditResponse, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.cache[hash]
	if !exists {
		return nil, false
	}

	// Check if the entry has expired
	if time.Since(entry.Timestamp) > entry.Expiration {
		// Remove expired entry
		delete(c.cache, hash)
		return nil, false
	}

	return entry.Response, true
}

// putInCache stores a response in the cache
func (c *CredAgentClient) putInCache(hash string, response *AuditResponse) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Set expiration time (e.g., 5 minutes)
	expiration := 5 * time.Minute
	c.cache[hash] = &CacheEntry{
		Response:   response,
		Timestamp:  time.Now(),
		Expiration: expiration,
	}
}

// callAIModel makes an HTTP request to the configured AI model API
func (c *CredAgentClient) callAIModel(prompt string) (*AuditResponse, error) {
	if c.config == nil {
		return nil, fmt.Errorf("config is nil")
	}

	// Calculate request hash for caching
	requestHash := c.calculateRequestHash(prompt)

	// Check if we have a cached response for this request
	if cachedResponse, found := c.getFromCache(requestHash); found {
		logger.Debug("Returning cached response for request hash: %s", requestHash)
		return cachedResponse, nil
	}

	// Check if another goroutine is already processing this request
	c.processingMux.Lock()
	if processingEntry, exists := c.processing[requestHash]; exists {
		// Another goroutine is already processing this request
		// Wait for the result from the channel
		c.processingMux.Unlock()

		// Wait for the result with timeout
		timeout := 30 // Default timeout if config is somehow nil
		if c.config != nil {
			timeout = c.config.TimeoutSec
		}
		select {
		case result := <-processingEntry.ResponseChan:
			return result.Response, result.Error
		case <-time.After(time.Duration(timeout) * time.Second):
			// Timeout occurred, return an error
			return nil, fmt.Errorf("timeout waiting for concurrent AI request")
		}
	} else {
		// No other goroutine is processing this request, so we'll start processing it
		// Create a channel to send the result to other waiting goroutines
		responseChan := make(chan *AuditResponseResult, 1)

		timeout := 30 // Default timeout if config is somehow nil
		if c.config != nil {
			timeout = c.config.TimeoutSec
		}

		c.processing[requestHash] = &ProcessingEntry{
			ResponseChan: responseChan,
			Timestamp:    time.Now(),
			Expiration:   time.Duration(timeout) * time.Second,
		}
		c.processingMux.Unlock()

		// Execute the actual AI request in a separate function to allow deferring cleanup
		result := c.executeAIRequest(prompt, requestHash)

		// Send the result to the channel to notify other waiting goroutines
		responseChan <- result

		// Cleanup the processing entry after sending the result
		c.processingMux.Lock()
		delete(c.processing, requestHash)
		c.processingMux.Unlock()

		return result.Response, result.Error
	}
}

// executeAIRequest performs the actual AI request
func (c *CredAgentClient) executeAIRequest(prompt, requestHash string) *AuditResponseResult {
	// Record start time for logging duration
	startTime := time.Now()

	// Create the request payload for the LLM API
	logger.Debug("Http Request for AI model with Prompt: %s", prompt)
	payload := map[string]interface{}{
		"model": c.config.ModelName,
		"messages": []map[string]interface{}{
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.1, // Low temperature for more consistent security evaluations
		"max_tokens":  1000,
	}

	// Marshal the payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return &AuditResponseResult{Response: nil, Error: fmt.Errorf("failed to marshal request payload: %w", err)}
	}

	// Construct the full API endpoint URL based on API type
	apiEndpoint := c.config.APIURL
	switch c.config.APIType {
	case "openai-chat", "":
		// Default behavior for standard OpenAI chat completions API
		if !strings.HasSuffix(apiEndpoint, "/chat/completions") {
			if !strings.HasSuffix(apiEndpoint, "/") {
				apiEndpoint += "/"
			}
			apiEndpoint += "chat/completions"
		}
	case "openai-completions":
		// For older OpenAI completions API
		if !strings.HasSuffix(apiEndpoint, "/completions") {
			if !strings.HasSuffix(apiEndpoint, "/") {
				apiEndpoint += "/"
			}
			apiEndpoint += "completions"
		}
	default:
		// For other API types or if not specified, default to chat completions
		if !strings.HasSuffix(apiEndpoint, "/chat/completions") {
			if !strings.HasSuffix(apiEndpoint, "/") {
				apiEndpoint += "/"
			}
			apiEndpoint += "chat/completions"
		}
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(context.Background(), "POST", apiEndpoint, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return &AuditResponseResult{Response: nil, Error: fmt.Errorf("failed to create HTTP request: %w", err)}
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.config.APIKey)
	req.Header.Set("User-Agent", "CredAgent/1.0")
	req.Header.Set("Accept", "application/json")

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: time.Duration(c.config.TimeoutSec) * time.Second,
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		return &AuditResponseResult{Response: nil, Error: fmt.Errorf("failed to execute HTTP request: %w", err)}
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &AuditResponseResult{Response: nil, Error: fmt.Errorf("failed to read response body: %w", err)}
	}

	// Check if the request was successful
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Error("AI model API returned error status %d: %s", resp.StatusCode, string(body))
		return &AuditResponseResult{Response: nil, Error: fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))}
	}

	// Parse the response - most LLM APIs return a JSON response with choices
	var apiResponse map[string]interface{}
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return &AuditResponseResult{Response: nil, Error: fmt.Errorf("failed to unmarshal API response: %w", err)}
	}

	// Extract the content from the response (this varies by API, assuming OpenAI format)
	var content string
	if choices, ok := apiResponse["choices"].([]interface{}); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]interface{}); ok {
			if message, ok := choice["message"].(map[string]interface{}); ok {
				if contentVal, ok := message["content"].(string); ok {
					content = contentVal
				}
			}
		}
	} else if contentVal, ok := apiResponse["content"].(string); ok {
		// Some APIs might return content directly
		content = contentVal
	} else {
		return &AuditResponseResult{Response: nil, Error: fmt.Errorf("could not extract content from API response")}
	}

	// Calculate the duration from start time
	duration := time.Since(startTime)

	// Log the AI's response with duration
	logger.Info("AI model responded with: %s (duration: %v)", content, duration)

	// Parse the AI's JSON response
	aiResponse, err := parseAIResponse(content)
	if err != nil {
		return &AuditResponseResult{Response: nil, Error: fmt.Errorf("failed to parse AI response: %w", err)}
	}

	// Cache the response for future identical requests
	c.putInCache(requestHash, aiResponse)

	return &AuditResponseResult{Response: aiResponse, Error: nil}
}

// InternalAuditLogic exposes the internal audit logic for fallback scenarios
func (c *CredAgentClient) InternalAuditLogic(intent, commandSpec string) *AuditResponse {
	return c.internalAuditLogic(intent, commandSpec)
}

// internalAuditLogic contains the internal reasoning logic for the AI security auditor
// This would normally be handled by the AI model, but we implement basic logic here
func (c *CredAgentClient) internalAuditLogic(intent, commandSpec string) *AuditResponse {
	response := &AuditResponse{
		Type: "AUDIT_RESPONSE",
	}

	// Perform consistency check
	intentActionConsistent := checkIntentActionConsistency(intent, commandSpec)
	if !intentActionConsistent {
		response.Decision = "DENY"
		response.Reason = "Intent and action are inconsistent"
		response.Message = "The stated intent does not match the action being performed."
		response.Confidence = 0.9
		logger.Info("Internal audit logic DENY: Intent and action are inconsistent. Intent: '%s', Command: '%s'", intent, commandSpec)
		return response
	}

	// Check for data exfiltration vectors
	hasExfiltrationVectors := hasDataExfiltrationVectors(commandSpec)
	if hasExfiltrationVectors {
		response.Decision = "DENY"
		response.Reason = "Detected potential data exfiltration vectors in command"
		response.Message = "Command contains patterns that may lead to credential leakage."
		response.Confidence = 0.85
		logger.Info("Internal audit logic DENY: Detected potential data exfiltration vectors in command. Command: '%s'", commandSpec)
		return response
	}

	// Check for known good patterns
	isKnownGoodPattern := isKnownGoodPattern(commandSpec)
	if isKnownGoodPattern {
		response.Decision = "ALLOW"
		response.Reason = "Command matches known safe pattern"
		response.Message = "Command appears to be a safe, standard operation."
		response.Confidence = 0.95
		logger.Info("Internal audit logic ALLOW: Command matches known safe pattern. Command: '%s'", commandSpec)
		return response
	}

	// Default to allow for simple cases, but with lower confidence
	response.Decision = "ALLOW"
	response.Reason = "Command passed basic security checks"
	response.Message = "Command appears safe based on preliminary checks."
	response.Confidence = 0.7
	logger.Info("Internal audit logic ALLOW: Command passed basic security checks. Command: '%s'", commandSpec)

	return response
}

// parseAIResponse parses the AI response and converts it to an AuditResponse
func parseAIResponse(aiResponse string) (*AuditResponse, error) {
	// Clean up the response string to handle potential formatting issues
	cleanResponse := strings.TrimSpace(aiResponse)

	// Look for JSON-like structure in the response
	startIdx := strings.Index(cleanResponse, "{")
	endIdx := strings.LastIndex(cleanResponse, "}")

	if startIdx != -1 && endIdx != -1 && endIdx > startIdx {
		// Extract the JSON part
		jsonPart := cleanResponse[startIdx : endIdx+1]

		// Attempt to unmarshal the JSON directly
		var response AuditResponse
		response.Type = "AUDIT_RESPONSE"

		var rawResponse map[string]interface{}
		if err := json.Unmarshal([]byte(jsonPart), &rawResponse); err != nil {
			// If JSON unmarshaling fails, fall back to manual parsing
			return parseAIResponseManually(aiResponse)
		}

		// Extract fields from the raw map
		if decision, ok := rawResponse["decision"].(string); ok {
			response.Decision = strings.ToUpper(decision)
		}

		if reason, ok := rawResponse["reason"].(string); ok {
			response.Reason = reason
		}

		if message, ok := rawResponse["message"].(string); ok {
			response.Message = message
		}

		if confidence, ok := rawResponse["confidence_score"].(float64); ok {
			response.Confidence = confidence
		} else if confidenceStr, ok := rawResponse["confidence_score"].(string); ok {
			// Handle case where confidence_score might be a string
			if conf, err := strconv.ParseFloat(confidenceStr, 64); err == nil {
				response.Confidence = conf
			}
		}

		// Set default reason and message if not provided
		if response.Reason == "" {
			if response.Decision == "DENY" {
				response.Reason = "Request denied by AI security auditor"
			} else {
				response.Reason = "Request approved by AI security auditor"
			}
		}

		if response.Message == "" {
			if response.Decision == "DENY" {
				response.Message = "The AI security auditor determined that this request poses a security risk and should be denied."
			} else {
				response.Message = "The AI security auditor determined that this request appears to be legitimate and safe to proceed."
			}
		}

		return &response, nil
	}

	// If no JSON structure is found, fall back to manual parsing
	return parseAIResponseManually(aiResponse)
}

// parseAIResponseManually is a fallback parser for AI responses
func parseAIResponseManually(aiResponse string) (*AuditResponse, error) {
	// This is a simplified parser - in practice, you'd want a more robust JSON parser
	response := &AuditResponse{Type: "AUDIT_RESPONSE"}

	// Look for decision in the response
	if strings.Contains(strings.ToLower(aiResponse), `"decision":"deny"`) ||
		strings.Contains(strings.ToLower(aiResponse), `"decision": "deny"`) ||
		(strings.Contains(strings.ToLower(aiResponse), "decision") && strings.Contains(strings.ToLower(aiResponse), "deny")) {
		response.Decision = "DENY"
	} else if strings.Contains(strings.ToLower(aiResponse), `"decision":"allow"`) ||
		strings.Contains(strings.ToLower(aiResponse), `"decision": "allow"`) ||
		(strings.Contains(strings.ToLower(aiResponse), "decision") && strings.Contains(strings.ToLower(aiResponse), "allow")) {
		response.Decision = "ALLOW"
	} else {
		// Default to ALLOW if decision is ambiguous
		response.Decision = "ALLOW"
	}

	// Extract reason if present
	if idx := strings.Index(aiResponse, `"reason":"`); idx != -1 {
		start := idx + len(`"reason":"`)
		if end := strings.Index(aiResponse[start:], `",`); end != -1 {
			response.Reason = aiResponse[start : start+end]
		} else if end := strings.Index(aiResponse[start:], `"}`); end != -1 {
			response.Reason = aiResponse[start : start+end]
		}
	}

	// Extract message if present
	if idx := strings.Index(aiResponse, `"message":"`); idx != -1 {
		start := idx + len(`"message":"`)
		if end := strings.Index(aiResponse[start:], `",`); end != -1 {
			response.Message = aiResponse[start : start+end]
		} else if end := strings.Index(aiResponse[start:], `"}`); end != -1 {
			response.Message = aiResponse[start : start+end]
		}
	}

	// Extract confidence score if present
	if idx := strings.Index(aiResponse, `"confidence_score":`); idx != -1 {
		start := idx + len(`"confidence_score":`)
		end := -1
		for i, ch := range aiResponse[start:] {
			if ch == ',' || ch == '}' || ch == ']' || ch == ' ' {
				end = i
				break
			}
		}
		if end != -1 {
			confStr := strings.TrimSpace(aiResponse[start : start+end])
			if conf, err := strconv.ParseFloat(confStr, 64); err == nil {
				response.Confidence = conf
			} else {
				// This is a simplified extraction - in practice, you'd want to properly parse the float
				response.Confidence = 0.8 // Default value
			}
		}
	}

	// If no specific reason was extracted, create a default one
	if response.Reason == "" {
		if response.Decision == "DENY" {
			response.Reason = "Request denied by AI security auditor"
		} else {
			response.Reason = "Request approved by AI security auditor"
		}
	}

	// If no specific message was extracted, create a default one
	if response.Message == "" {
		if response.Decision == "DENY" {
			response.Message = "The AI security auditor determined that this request poses a security risk and should be denied."
		} else {
			response.Message = "The AI security auditor determined that this request appears to be legitimate and safe to proceed."
		}
	}

	return response, nil
}

// Helper function to check intent-action consistency
func checkIntentActionConsistency(intent, commandSpec string) bool {
	// Basic check: if intent says "query" but command does "delete", it's inconsistent
	intentLower := strings.ToLower(strings.TrimSpace(intent))
	commandLower := strings.ToLower(strings.TrimSpace(commandSpec))

	if containsAny(intentLower, []string{"query", "read", "get", "show", "display", "fetch"}) {
		if containsAny(commandLower, []string{"rm ", "rm -", "delete", "remove", "destroy", "erase"}) {
			return false // Intent is to read but action is to delete
		}
	}

	// Check if intent suggests data modification but command is only reading
	if containsAny(intentLower, []string{"modify", "update", "change", "edit", "write", "save"}) {
		if containsAny(commandLower, []string{"cat ", "head ", "tail ", "grep ", "less ", "more "}) {
			return false // Intent is to modify but action is only reading
		}
	}

	return true
}

// Helper function to check for data exfiltration vectors
func hasDataExfiltrationVectors(commandSpec string) bool {
	specLower := strings.ToLower(strings.TrimSpace(commandSpec))

	// Check for redirection/piping
	if containsAny(specLower, []string{"|", ">", ">>", "tee "}) {
		return true
	}

	// Check for command substitution
	if containsAny(specLower, []string{"$(", "`"}) {
		return true
	}

	// Check for network tools that might exfiltrate data
	// Skip this check if the command starts with "aliyun" since aliyun is for legitimate cloud operations
	if !strings.HasPrefix(specLower, "aliyun") {
		if containsAny(specLower, []string{"curl", "wget", "nc ", "ncat", "netcat", "scp ", "rsync", "ftp ", "sftp "}) {
			return true
		}
	}

	// Check for subshell execution
	if containsAny(specLower, []string{"bash -c", "sh -c", "python -c", "perl -e", "node -e"}) {
		return true
	}

	// Check for vim or other editors that might execute commands
	if containsAny(specLower, []string{"vim ", "vi ", "nano ", "emacs "}) {
		return true
	}

	// Check for compression/tar commands that might package credentials
	if containsAny(specLower, []string{"tar ", "zip ", "gzip ", "bzip2 ", "7z "}) {
		return true
	}

	// Check for commands that directly output file content to terminal (high risk for credential files)
	if containsAny(specLower, []string{"cat ", "head ", "tail ", "less ", "more ", "strings ", "od ", "hexdump ", "xxd "}) {
		return true
	}

	return false
}

// Helper function to check for known good patterns
func isKnownGoodPattern(commandSpec string) bool {
	specLower := strings.ToLower(strings.TrimSpace(commandSpec))

	// Safe patterns that are typically used for legitimate queries
	// Note: Commands that directly output file content (like "cat ", "head ", "tail ") are NOT considered safe
	// when dealing with credential files, so they are excluded from this list
	safePatterns := []string{
		"psql -c 'select",
		"mysql -e \"select",
		"aliyun oss ls",
		"aliyun ecs ",
		"aliyun ",
		"kubectl get",
		"kubectl describe",
		"git clone",
		"git pull",
		"grep ",
		"find ",
		"ls ",
		"ps ",
		"top ",
		"df ",
		"du ",
	}

	for _, pattern := range safePatterns {
		if strings.Contains(specLower, pattern) {
			return true
		}
	}

	return false
}

// RequestPermissionViaEnclave requests permission to access a credential file via the EnclaveDaemon
func (c *CredAgentClient) RequestPermissionViaEnclave(socketPath, intent, cmdline, targetFile string) (*AuditResponse, error) {
	// Create a UDS client to communicate with the EnclaveDaemon
	client, err := uds.NewClient(socketPath)
	if err != nil {
		logger.Error("Failed to create UDS client: %v", err)
		return nil, fmt.Errorf("failed to connect to EnclaveDaemon: %w", err)
	}
	defer client.Close()

	// Call the RequestPermission method on the EnclaveDaemon
	resp, err := client.RequestPermission(context.Background(), intent, cmdline, targetFile)
	if err != nil {
		logger.Error("Failed to request permission from EnclaveDaemon: %v", err)
		return nil, fmt.Errorf("failed to request permission from EnclaveDaemon: %w", err)
	}

	// Convert the gRPC response to an AuditResponse
	auditResp := &AuditResponse{
		Type:     "AUDIT_RESPONSE",
		UUID:     resp.GetUuid(), // This will be the permit ticket UUID if successful
		Decision: resp.GetDecision(),
		Message:  resp.GetMessage(),
	}

	if resp.GetSuccess() {
		auditResp.Reason = "Permission granted by EnclaveDaemon"
		auditResp.Confidence = 1.0
	} else {
		auditResp.Reason = fmt.Sprintf("Permission denied by EnclaveDaemon: %s", resp.GetMessage())
		auditResp.Confidence = 0.0
	}

	return auditResp, nil
}

// Helper functions
func containsAny(haystack string, needles []string) bool {
	haystackLower := strings.ToLower(haystack)
	for _, needle := range needles {
		if strings.Contains(haystackLower, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
