package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CredAgentConfig holds the configuration for the CredAgent
type CredAgentConfig struct {
	Provider   string `json:"provider"`        // AI Provider type (e.g., "openai", "anthropic", "ollama", etc.)
	APIURL     string `json:"api_url"`         // API URL for the provider
	APIKey     string `json:"api_key"`         // API key for the provider
	APIType    string `json:"api"`             // API type for the provider (e.g., "openai-completions", "openai-chat", etc.)
	ModelName  string `json:"model_name"`      // Model name to use
	TimeoutSec int    `json:"timeout_seconds"` // Request timeout in seconds
}

// EnclaveConfig holds the configuration for the Enclave
type EnclaveConfig struct {
	MasterKeyFile string `json:"master_key_file"`
	SocketFile    string `json:"socket_file"` // Legacy field for backward compatibility
	SocketDir     string `json:"socket_dir"`  // Directory for socket files
	BaselineFile  string `json:"baseline_file"`
}

// MonitorConfig holds the configuration for the Monitor
type MonitorConfig struct {
	MountPoint string `json:"mount_point"`
	TargetPath string `json:"target_path"`
}

// BinaryCheckConfig controls binary trust verification (path safety, ownership).
type BinaryCheckConfig struct {
	Enabled         bool     `json:"enabled"`
	TrustedPrograms []string `json:"trusted_programs"`
}

// AncestorCheckConfig controls ancestor process chain verification
type AncestorCheckConfig struct {
	Enabled  bool `json:"enabled"`
	MaxDepth int  `json:"max_depth"`
}

// ProcessStatusCheckConfig controls TracerPid/Seccomp detection
type ProcessStatusCheckConfig struct {
	Enabled bool `json:"enabled"`
}

// LibraryInjectionCheckConfig controls suspicious .so detection
type LibraryInjectionCheckConfig struct {
	Enabled         bool     `json:"enabled"`
	TrustedLibPaths []string `json:"trusted_lib_paths"`
}

// EnvVarCheckConfig controls LD_PRELOAD/LD_LIBRARY_PATH/LD_AUDIT detection
type EnvVarCheckConfig struct {
	Enabled    bool                `json:"enabled"`
	TrustedEnv map[string][]string `json:"trusted_env"`
}

// InterpreterCheckItemConfig controls per-interpreter security checks
type InterpreterCheckItemConfig struct {
	Enabled        bool                `json:"enabled"`
	TrustedEnv     map[string][]string `json:"trusted_env"`
	TrustedScripts []string            `json:"trusted_scripts,omitempty"`
	ExePaths       []string            `json:"exe_paths,omitempty"`
}

// InterpreterCheckConfig holds per-interpreter configurations
type InterpreterCheckConfig struct {
	Python *InterpreterCheckItemConfig `json:"python,omitempty"`
	Node   *InterpreterCheckItemConfig `json:"node,omitempty"`
	Perl   *InterpreterCheckItemConfig `json:"perl,omitempty"`
	Ruby   *InterpreterCheckItemConfig `json:"ruby,omitempty"`
	Java   *InterpreterCheckItemConfig `json:"java,omitempty"`

	PHP *InterpreterCheckItemConfig `json:"php,omitempty"`
}

// FdShareCheckConfig controls cross-process fd share detection and blacklisting
type FdShareCheckConfig struct {
	Enabled bool `json:"enabled"`
}

// AntiattackOptions holds anti-intrusion security check configuration
type AntiattackOptions struct {
	BinaryCheck              *BinaryCheckConfig           `json:"binary_check"`
	AncestorCheck            *AncestorCheckConfig         `json:"ancestor_check"`
	ProcessStatusCheck       *ProcessStatusCheckConfig    `json:"process_status_check"`
	LibraryInjectionCheck    *LibraryInjectionCheckConfig `json:"library_injection_check"`
	EnvVarCheck              *EnvVarCheckConfig           `json:"env_var_check"`
	InterpreterCheck         *InterpreterCheckConfig      `json:"interpreter_check"`
	FdShareCheck             *FdShareCheckConfig          `json:"fd_share_check"`
	TrustedHarness           []string                     `json:"trusted_harness"`
	ProcessCleanupTimeoutSec int                          `json:"process_cleanup_timeout_sec"`
}

// SecuritySummary returns a human-readable one-line summary of the security policy.
func (o *AntiattackOptions) SecuritySummary() string {
	if o == nil {
		return "all anti-attack checks disabled (no security config)"
	}

	var enabled, disabled []string

	type boolCheck struct {
		name string
		on   bool
	}
	checks := []boolCheck{
		{"binary_check", o.BinaryCheck != nil && o.BinaryCheck.Enabled},
		{"ancestor_check", o.AncestorCheck != nil && o.AncestorCheck.Enabled},
		{"process_status_check", o.ProcessStatusCheck != nil && o.ProcessStatusCheck.Enabled},
		{"library_injection_check", o.LibraryInjectionCheck != nil && o.LibraryInjectionCheck.Enabled},
		{"env_var_check", o.EnvVarCheck != nil && o.EnvVarCheck.Enabled},
		{"interpreter_check", o.InterpreterCheck != nil},
		{"fd_share_check", o.FdShareCheck != nil && o.FdShareCheck.Enabled},
	}

	for _, c := range checks {
		if c.on {
			enabled = append(enabled, c.name)
		} else {
			disabled = append(disabled, c.name)
		}
	}

	summary := fmt.Sprintf("enabled=[%s]", strings.Join(enabled, ", "))
	if len(disabled) > 0 {
		summary += fmt.Sprintf(", disabled=[%s]", strings.Join(disabled, ", "))
	}
	if len(o.TrustedHarness) > 0 {
		summary += fmt.Sprintf(", trusted_harness=%v", o.TrustedHarness)
	}
	return summary
}

// SecuritySource describes where antiattack/security options were loaded from.
type SecuritySource int

const (
	SecurityFromConfig SecuritySource = iota // from config.json
	SecurityFromFile                         // from security.json
	SecurityDefault                          // no explicit config, using defaults
)

// Config represents the complete configuration
type Config struct {
	CredAgent            *CredAgentConfig   `json:"credagent"`
	Enclave              *EnclaveConfig     `json:"enclave"`
	Monitor              *MonitorConfig     `json:"monitor"`
	LogLevel             string             `json:"log_level"`
	CmdlineTrustedSource []string           `json:"cmdline_trusted_source"`
	AntiattackOptions    *AntiattackOptions `json:"antiattack_options"`

	SecuritySource SecuritySource `json:"-"`
}

// SecurityConfig holds fields that can live in a separate security.json file.
type SecurityConfig struct {
	CmdlineTrustedSource []string           `json:"cmdline_trusted_source"`
	AntiattackOptions    *AntiattackOptions `json:"antiattack_options"`
}

// LoadConfig loads configuration from a JSON file.
// It also looks for a security.json in the same directory and merges
// CmdlineTrustedSource and AntiattackOptions from it. Fields already
// present in the main config.json take precedence (for backward compatibility).
func LoadConfig(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if config.AntiattackOptions != nil {
		config.SecuritySource = SecurityFromConfig
	}

	securityPath := filepath.Join(filepath.Dir(configPath), "security.json")
	if secData, err := os.ReadFile(securityPath); err == nil {
		var sec SecurityConfig
		if err := json.Unmarshal(secData, &sec); err == nil {
			if config.CmdlineTrustedSource == nil && sec.CmdlineTrustedSource != nil {
				config.CmdlineTrustedSource = sec.CmdlineTrustedSource
			}
			if config.AntiattackOptions == nil && sec.AntiattackOptions != nil {
				config.AntiattackOptions = sec.AntiattackOptions
				config.SecuritySource = SecurityFromFile
			}
		}
	}

	if config.AntiattackOptions == nil {
		config.SecuritySource = SecurityDefault
	}

	return &config, nil
}
