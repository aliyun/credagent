package main

import (
	"context"
	"fmt"
	"os"

	"github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	restoreFile   string
	restoreSecret string
)

func createRestoreCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore [flags] <id>",
		Short: "Restore (update) the content of a protected credential",
		Long:  `Replaces the content of a protected credential with new data. Requires password authentication. The baseline metadata and access rules remain unchanged.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runRestore,
	}

	cmd.Flags().StringVarP(&restoreFile, "file", "f", "", "Read new content from the specified file")
	cmd.Flags().StringVarP(&restoreSecret, "secret", "s", "", "New content provided directly (WARNING: visible in process list and shell history)")
	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <id>\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\n%s\n", cmd.Long)
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		cmd.Flags().VisitAll(func(flag *pflag.Flag) {
			fmt.Fprintf(os.Stderr, "  -%s, --%s %s\n", flag.Shorthand, flag.Name, flag.Usage)
			if flag.DefValue != "" {
				fmt.Fprintf(os.Stderr, "        (default \"%s\")\n", flag.DefValue)
			}
		})
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -f /tmp/config.json abc123\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s -s 'new-secret-value' abc123\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s -s \"$(credctl dump abc123 | sed 's/old/new/g')\" abc123\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\nSecurity note: --secret/-s value is visible in the process list and shell history.\n")
		fmt.Fprintf(os.Stderr, "  Prefer --file/-f for sensitive content.\n")
		fmt.Fprintf(os.Stderr, "\nNote: The 'id' is the SHA identifier shown in the 'list' command output.\n")
	})

	return cmd
}

func runRestore(cmd *cobra.Command, args []string) error {
	if configFile != "" {
		if _, err := os.Stat(configFile); err == nil {
			cfg, err := config.LoadConfig(configFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			if !cmd.Flags().Changed("socket-dir") {
				if cfg.Enclave != nil && cfg.Enclave.SocketDir != "" {
					socketDir = cfg.Enclave.SocketDir
				} else {
					socketDir = "/run/credagent"
				}
			}
		}
	}

	return restoreCredentialContent(cmd, args[0])
}

func restoreCredentialContent(cmd *cobra.Command, id string) error {
	hasFile := cmd.Flags().Changed("file")
	hasSecret := cmd.Flags().Changed("secret")

	if !hasFile && !hasSecret {
		return fmt.Errorf("either --file/-f or --secret/-s is required")
	}
	if hasFile && hasSecret {
		return fmt.Errorf("--file/-f and --secret/-s are mutually exclusive")
	}

	var newContent []byte
	if hasFile {
		data, err := os.ReadFile(restoreFile)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", restoreFile, err)
		}
		newContent = data
	} else {
		newContent = []byte(restoreSecret)
	}

	password, err := getPasswordFromPrompt("Enter password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	conn, err := createEnclaveClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := enclave.NewEnclaveGuardServiceClient(conn)

	resp, err := client.RestoreFileContent(context.Background(), &enclave.RestoreFileContentRequest{
		Sha:      id,
		Password: string(password),
		Content:  newContent,
	})
	if err != nil {
		return fmt.Errorf("failed to restore credential: %w", err)
	}

	if !resp.GetSuccess() {
		return fmt.Errorf("failed to restore credential: %s", resp.GetMessage())
	}

	fmt.Printf("Successfully restored credential content (new size: %d bytes)\n", resp.GetNewSize())
	return nil
}
