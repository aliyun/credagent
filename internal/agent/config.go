package agent

// Config represents the configuration for CredAgent
type Config struct {
	Provider   string `json:"provider"`    // AI Provider type (e.g., "openai", "anthropic", "ollama", etc.)
	APIURL     string `json:"api_url"`     // API URL for the provider
	APIKey     string `json:"api_key"`     // API key for the provider
	APIType    string `json:"api"`         // API type for the provider (e.g., "openai-completions", "openai-chat", etc.)
	ModelName  string `json:"model_name"`  // Model name to use
	TimeoutSec int    `json:"timeout_sec"` // Request timeout in seconds
}
