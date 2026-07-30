package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/config"
	"github.com/spf13/cobra"
)

// createAttachCmd creates the attach command
func createAttachCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attach [flags] <id>",
		Short: "Attach one or more allowed programs to an existing protected credential file",
		Long:  `Attaches one or more allowed programs (with SHA256) to an existing protected credential file. Programs that already exist in the baseline are skipped.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runAttach,
	}

	cmd.Flags().StringSliceVarP(&updateProgramPermit, "program-permit", "p", []string{}, "The path to program to attach (can be specified multiple times)")
	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")

	cmd.MarkFlagRequired("program-permit")

	// Set custom help text for attach command
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <baseline_id>\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\n%s\n", cmd.Long)
		fmt.Fprintf(os.Stderr, "\nRequired Flags:\n")
		fmt.Fprintf(os.Stderr, "  -p, --program-permit strings       The path to program to attach (can be specified multiple times)\n")
		fmt.Fprintf(os.Stderr, "\nOptional Flags:\n")
		fmt.Fprintf(os.Stderr, "  -d, --socket-dir string            Directory for Unix Domain Socket files (default \"/run/credagent\")\n")
		fmt.Fprintf(os.Stderr, "  -c, --config string                Path to the configuration file (JSON format)\n")
		fmt.Fprintf(os.Stderr, "                                     (default \"/usr/local/etc/credagent/credctl/config.json\")\n")
		fmt.Fprintf(os.Stderr, "\nBehavior:\n")
		fmt.Fprintf(os.Stderr, "  Programs already present in the baseline are silently skipped and reported.\n")
		fmt.Fprintf(os.Stderr, "  SHA256 is always computed and stored for each newly attached program.\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s abc123 --program-permit /usr/bin/psql\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s abc123 -p /usr/bin/psql -p /usr/bin/pg_dump\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\nNote: The baseline_id is the SHA identifier shown in the 'list' command output.\n")
	})

	return cmd
}

// runAttach executes the attach command
func runAttach(cmd *cobra.Command, args []string) error {
	// Load config if provided and file exists
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

	return attachPrograms(args[0])
}

// attachPrograms attaches one or more allowed binary programs to an existing protected credential file.
// baselineID is the SHA identifier of the protected file.
func attachPrograms(baselineID string) error {
	password, err := getPasswordFromPrompt("Enter admin password to attach programs: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Convert to absolute paths and compute SHA256 for each binary
	var absAllowedBinaries []string
	var sha256List []string
	for _, binary := range updateProgramPermit {
		absBinary, err := filepath.Abs(binary)
		if err != nil {
			return fmt.Errorf("failed to convert program path to absolute: %w", err)
		}
		hash, err := calculateSHA256(absBinary)
		if err != nil {
			return fmt.Errorf("failed to calculate SHA256 for %s: %w", absBinary, err)
		}
		absAllowedBinaries = append(absAllowedBinaries, absBinary)
		sha256List = append(sha256List, hash)
	}

	conn, err := createEnclaveClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := enclave.NewEnclaveGuardServiceClient(conn)

	req := &enclave.AttachProgramsRequest{
		Sha:                   baselineID,
		Password:              string(password),
		AllowedBinaries:       absAllowedBinaries,
		AllowedBinariesSha256: sha256List,
	}

	resp, err := client.AttachPrograms(context.Background(), req)
	if err != nil {
		return fmt.Errorf("failed to attach programs: %w", err)
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("failed to attach programs: %s", resp.GetMessage())
	}

	fmt.Printf("Successfully updated credential %s\n", baselineID)
	if len(resp.GetAdded()) > 0 {
		fmt.Printf("Added (%d):   %v\n", len(resp.GetAdded()), resp.GetAdded())
	}
	if len(resp.GetSkipped()) > 0 {
		fmt.Printf("Skipped (%d): %v (already exist)\n", len(resp.GetSkipped()), resp.GetSkipped())
		fmt.Println("  Hint: use 'credctl refresh' to update SHA256 for already-authorized programs.")
	}

	return nil
}
