package agent

import (
	"encoding/json"
	"os"
)

// loadTestConfig loads the test configuration from config.test.json
func loadTestConfig() (*Config, error) {
	data, err := os.ReadFile("config.test.json")
	if err != nil {
		// If config.test.json doesn't exist in current directory, try relative path
		data, err = os.ReadFile("./internal/agent/config.test.json")
		if err != nil {
			// Return default config if file not found
			return &Config{
				Provider:   "openai",
				APIURL:     "http://test.example.com",
				APIKey:     "test-key",
				APIType:    "openai-completions",
				ModelName:  "test-model",
				TimeoutSec: 30,
			}, nil
		}
	}

	var config struct {
		CredAgent struct {
			APIURL     string `json:"api_url"`
			APIKey     string `json:"api_key"`
			API        string `json:"api"`
			ModelName  string `json:"model_name"`
			TimeoutSec int    `json:"timeout_seconds"`
		} `json:"credagent"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &Config{
		Provider:   "openai",
		APIURL:     config.CredAgent.APIURL,
		APIKey:     config.CredAgent.APIKey,
		APIType:    config.CredAgent.API,
		ModelName:  config.CredAgent.ModelName,
		TimeoutSec: config.CredAgent.TimeoutSec,
	}, nil
}
