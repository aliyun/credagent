package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/alibaba/CredAgent/internal/agent"
	"github.com/alibaba/CredAgent/internal/config"
	"github.com/alibaba/CredAgent/pkg/version"
	"github.com/spf13/cobra"
)

func main() {
	var (
		intent     string
		cmdline    string
		targetFile string
		socketDir  string
		configFile string
		logLevel   string
	)

	// Initialize default values
	socketDir = "/run/credagent"
	configFile = "/usr/local/etc/credagent/engine/config.json"
	logLevel = "info"

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of credreq",
		Long:  `Print the version number of CredAgent credreq CLI tool.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("credreq version %s\n", version.Version)
		},
	}

	rootCmd := &cobra.Command{
		Use:   "credreq",
		Short: "CredAgent CLI for requesting credential access permissions",
		Long:  `CredAgent CLI tool for requesting temporary permissions to access protected credentials via the enclave.`,
	}

	reqCmd := &cobra.Command{
		Use:   "req [flags]",
		Short: "Request permission to access a credential file",
		Long:  `Requests temporary permission to access a protected credential file based on intent, command line, and target file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load config if provided and file exists
			if configFile != "" {
				if _, err := os.Stat(configFile); err == nil {
					// File exists, load it
					cfg, err := config.LoadConfig(configFile)
					if err != nil {
						return fmt.Errorf("failed to load config: %w", err)
					}

					// Override log level from config only if not explicitly set via command line
					if cmd.Flags().Changed("log-level") {
						logLevel = cfg.LogLevel
					}

					// Override socket dir from config only if not explicitly set via command line
					if !cmd.Flags().Changed("socket-dir") {
						if cfg.Enclave != nil && cfg.Enclave.SocketDir != "" {
							socketDir = cfg.Enclave.SocketDir
						} else {
							// Default to the standard location if not specified
							socketDir = "/run/credagent"
						}
					}
				}
			}

			// Validate required arguments
			if intent == "" || cmdline == "" || targetFile == "" {
				return fmt.Errorf("intent, cmdline, and targetFile are required")
			}

			fmt.Printf("Starting CredAgent CLI\n")
			fmt.Printf("Intent: %s\n", intent)
			fmt.Printf("Command line: %s\n", cmdline)
			fmt.Printf("Target file: %s\n", targetFile)

			// Determine the socket file path for enclave service
			var enclaveSocketFile string
			cfg, _ := config.LoadConfig(configFile)
			if cfg != nil && cfg.Enclave != nil && cfg.Enclave.SocketFile != "" {
				enclaveSocketFile = cfg.Enclave.SocketFile
			} else {
				// Use default naming convention: <socket-dir>/enclave.sock
				enclaveSocketFile = filepath.Join(socketDir, "enclave.sock")
			}

			fmt.Printf("Using socket file: %s\n", enclaveSocketFile)

			// Create a CredAgent client with default configuration
			// Note: Some configuration values might come from environment variables or defaults
			agentConfig := &agent.Config{
				Provider:   os.Getenv("CRED_AGENT_PROVIDER"),   // Allow setting via env var
				APIURL:     os.Getenv("CRED_AGENT_API_URL"),    // Allow setting via env var
				APIKey:     os.Getenv("CRED_AGENT_API_KEY"),    // Allow setting via env var
				APIType:    os.Getenv("CRED_AGENT_API_TYPE"),   // Allow setting via env var
				ModelName:  os.Getenv("CRED_AGENT_MODEL_NAME"), // Allow setting via env var
				TimeoutSec: 30,                                 // Default timeout of 30 seconds
			}
			credAgentClient := agent.NewCredAgentClient(agentConfig)

			// Call the CredAgent to request permission via EnclaveDaemon
			// This sends the intent, cmdline and targetFile to the EnclaveDaemon for processing
			auditResponse, err := credAgentClient.RequestPermissionViaEnclave(enclaveSocketFile, intent, cmdline, targetFile)
			if err != nil {
				// If the EnclaveDaemon is unavailable, use the internal audit logic as fallback
				fmt.Fprintf(os.Stderr, "EnclaveDaemon unavailable: %v, using internal audit logic as fallback\n", err)

				// Use the internal audit logic directly
				response := credAgentClient.InternalAuditLogic(intent, cmdline)

				// Output the result based on the decision
				if response.Decision == "ALLOW" {
					fmt.Printf("%s\n", response.Message)
				} else {
					fmt.Printf("Access denied: %s\n", response.Reason)
					os.Exit(1)
				}
			} else {
				// Output the result based on the decision
				if auditResponse.Decision == "ALLOW" {
					fmt.Printf("Access granted. Permit ticket UUID: %s\n", auditResponse.UUID)
					fmt.Printf("Message: %s\n", auditResponse.Message)
				} else {
					fmt.Printf("Access denied: %s\n", auditResponse.Reason)
					os.Exit(1)
				}
			}

			return nil
		},
	}

	reqCmd.Flags().StringVar(&intent, "intent", "", "Original intent for accessing the credential (required)")
	reqCmd.Flags().StringVar(&cmdline, "cmdline", "", "Detailed command line for the operation (required)")
	reqCmd.Flags().StringVar(&targetFile, "targetFile", "", "Target file that needs access (required)")
	reqCmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	reqCmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/engine/config.json", "Path to the configuration file (JSON format)")
	reqCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warning, error)")

	reqCmd.MarkFlagRequired("intent")
	reqCmd.MarkFlagRequired("cmdline")
	reqCmd.MarkFlagRequired("targetFile")

	rootCmd.AddCommand(reqCmd, versionCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
