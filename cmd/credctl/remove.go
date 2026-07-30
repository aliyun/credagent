package main

import (
	"context"
	"fmt"
	"os"

	"github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/config"
	"github.com/spf13/cobra"
)

// createRemoveCmd creates the remove command
func createRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove [flags] <target_filepath>",
		Short: "Remove a protected credential file from the enclave (without restoring)",
		Long:  `Removes a protected credential file from the enclave without restoring it to the filesystem.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runRemove,
	}

	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")

	return cmd
}

// runRemove executes the remove command
func runRemove(cmd *cobra.Command, args []string) error {
	// Load config if provided and file exists
	if configFile != "" {
		if _, err := os.Stat(configFile); err == nil {
			cfg, err := config.LoadConfig(configFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Override socket dir from config only if not explicitly set via command line
			if !cmd.Flags().Changed("socket-dir") {
				if cfg.Enclave != nil && cfg.Enclave.SocketDir != "" {
					socketDir = cfg.Enclave.SocketDir
				} else {
					socketDir = "/run/credagent"
				}
			}
		}
	}

	return removeProtectedFile(args[0])
}

// removeProtectedFile removes a protected credential file from the enclave without restoring it
func removeProtectedFile(sha string) error {
	// Prompt user for password
	password, err := getPasswordFromPrompt("Enter admin password to remove the protected credential: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Create gRPC connection to EnclaveDaemon via Unix Domain Socket
	conn, err := createEnclaveClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := enclave.NewEnclaveGuardServiceClient(conn)

	// Create RemoveFileRequest with SHA and password
	req := &enclave.RemoveFileRequest{
		Sha:      sha,
		Password: string(password),
	}

	// Call RemoveFile
	resp, err := client.RemoveFile(context.Background(), req)
	if err != nil || !resp.GetSuccess() {
		if resp != nil {
			return fmt.Errorf("failed to remove protected credential: %w (server message: %s)", err, resp.GetMessage())
		}
		return fmt.Errorf("failed to remove protected credential: %w", err)
	}

	fmt.Printf("Successfully removed %s from the enclave (file not restored to filesystem).\n", sha)
	return nil
}
