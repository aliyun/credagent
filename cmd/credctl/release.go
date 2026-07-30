package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// createReleaseCmd creates the release command
func createReleaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "release [flags] <id>",
		Short: "Release a credential file by restoring it from the enclave",
		Long:  `Releases a credential file by retrieving it from the enclave and restoring it to the filesystem.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runRelease,
	}

	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")

	// Set custom help text for release command
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <id>\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\n%s\n", cmd.Long)
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		cmd.Flags().VisitAll(func(flag *pflag.Flag) {
			fmt.Fprintf(os.Stderr, "  -%s, --%s %s\n", flag.Shorthand, flag.Name, flag.Usage)
			if flag.Value.Type() == "string" {
				fmt.Fprintf(os.Stderr, "        (default \"%s\")\n", flag.DefValue)
			} else {
				fmt.Fprintf(os.Stderr, "        (default %s)\n", flag.DefValue)
			}
		})
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s abc123\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\nNote: The 'id' is the SHA identifier shown in the 'list' command output.\n")
	})

	return cmd
}

// runRelease executes the release command
func runRelease(cmd *cobra.Command, args []string) error {
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

	return releaseCredentialByID(args[0])
}

// releaseCredentialByID releases a credential file by restoring it from the enclave using its SHA identifier
func releaseCredentialByID(id string) error {
	// Get current user's UID
	currentUID := os.Geteuid()

	// Prompt user for password
	password, err := getPasswordFromPrompt("Enter your password to release the credential: ")
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

	// Create ReleaseFileRequest with SHA identifier and password
	req := &enclave.ReleaseFileRequest{
		FileId:   id, // Use the SHA identifier
		Uid:      int32(currentUID),
		Password: string(password),
	}

	// Call ReleaseFile to get file data and permissions
	resp, err := client.ReleaseFile(context.Background(), req)
	if err != nil {
		return fmt.Errorf("failed to release credential: %w", err)
	}

	if !resp.GetSuccess() {
		return fmt.Errorf("failed to release credential: %s", resp.GetMessage())
	}

	// Extract file information from response
	filePath := resp.GetFilePath()
	fileContent := resp.GetFileContent()
	ownerUID := resp.GetOwnerUid()
	ownerGID := resp.GetOwnerGid()
	permission := resp.GetPermission()

	// Ensure parent directory exists before writing the file
	parentDir := filepath.Dir(filePath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create parent directory for %s: %v\n", filePath, err)
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	// Write the file with the original permissions
	if err := os.WriteFile(filePath, fileContent, os.FileMode(permission)); err != nil {
		// If file write fails, print error and return without removing baseline
		fmt.Printf("Operation failed: unable to write file content to %s: %v\n", filePath, err)
		fmt.Printf("File location: %s\n", filePath)
		fmt.Printf("Baseline entry remains in enclave as file restoration failed\n")
		return nil // Return nil to indicate that the baseline was not removed
	}

	// Attempt to change ownership to original owner
	ownershipChanged := true
	if err := os.Chown(filePath, int(ownerUID), int(ownerGID)); err != nil {
		// If changing ownership fails, continue but note the issue
		fmt.Printf("Warning: Failed to change ownership of %s to %d:%d: %v\n", filePath, ownerUID, ownerGID, err)
		ownershipChanged = false
	}

	// Attempt to set correct permissions
	permissionChanged := true
	if err := os.Chmod(filePath, os.FileMode(permission)); err != nil {
		// If changing permissions fails, continue but note the issue
		fmt.Printf("Warning: Failed to set permissions on %s to %#o: %v\n", filePath, permission, err)
		permissionChanged = false
	}

	// Now that file has been written (successfully or with partial success), call RemoveFile to delete the baseline entry
	// Use the SHA identifier from the response to remove the baseline
	removeReq := &enclave.RemoveFileRequest{
		Sha:      resp.GetFileId(), // Use the SHA identifier from the response
		Password: string(password),
	}

	removeResp, err := client.RemoveFile(context.Background(), removeReq)
	if err != nil {
		return fmt.Errorf("failed to remove baseline entry after release: %w", err)
	}

	if !removeResp.GetSuccess() {
		return fmt.Errorf("failed to remove baseline entry after release: %s", removeResp.GetMessage())
	}

	// Print the result based on what operations succeeded
	if ownershipChanged && permissionChanged {
		fmt.Printf("Successfully released credential to %s\n", filePath)
		fmt.Printf("- File content restored with original permissions\n")
		fmt.Printf("- Original owner UID: %d, GID: %d\n", ownerUID, ownerGID)
		fmt.Printf("- Original permission: %#o\n", permission)
		fmt.Printf("- Baseline removed from enclave\n")
	} else {
		fmt.Printf("File content written successfully to %s\n", filePath)
		fmt.Printf("- File location: %s\n", filePath)

		if !ownershipChanged && !permissionChanged {
			fmt.Printf("- Warning: File owner/group and permissions were not restored due to insufficient privileges\n")
		} else if !ownershipChanged {
			fmt.Printf("- Warning: File owner/group was not restored due to insufficient privileges\n")
		} else if !permissionChanged {
			fmt.Printf("- Warning: File permissions were not restored due to insufficient privileges\n")
		}

		fmt.Printf("- Baseline removed from enclave\n")
	}

	return nil
}
