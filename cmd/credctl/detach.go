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

// createDetachCmd creates the detach command
func createDetachCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "detach [flags] <id>",
		Short: "Detach one or more allowed programs from an existing protected credential file",
		Long:  `Removes one or more allowed programs from an existing protected credential file. Programs that are not found in the baseline are reported but do not cause failure.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runDetach,
	}

	cmd.Flags().StringSliceVarP(&updateProgramPermit, "program-permit", "p", []string{}, "The path to pragram to detach (can be specified multiple times)")
	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")

	cmd.MarkFlagRequired("program-permit")

	// Set custom help text for detach command
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <baseline_id>\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\n%s\n", cmd.Long)
		fmt.Fprintf(os.Stderr, "\nRequired Flags:\n")
		fmt.Fprintf(os.Stderr, "  -p, --program-permit strings       The path to program to detach (can be specified multiple times)\n")
		fmt.Fprintf(os.Stderr, "\nOptional Flags:\n")
		fmt.Fprintf(os.Stderr, "  -d, --socket-dir string            Directory for Unix Domain Socket files (default \"/run/credagent\")\n")
		fmt.Fprintf(os.Stderr, "  -c, --config string                Path to the configuration file (JSON format)\n")
		fmt.Fprintf(os.Stderr, "                                     (default \"/usr/local/etc/credagent/credctl/config.json\")\n")
		fmt.Fprintf(os.Stderr, "\nBehavior:\n")
		fmt.Fprintf(os.Stderr, "  Programs not found in the baseline are reported as not_found but do not fail the operation.\n")
		fmt.Fprintf(os.Stderr, "  The corresponding SHA256 entry is removed together with the program path (paired deletion).\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s abc123 --program-permit /usr/bin/psql\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s abc123 -p /usr/bin/psql -p /usr/bin/pg_dump\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\nNote: The baseline_id is the SHA identifier shown in the 'list' command output.\n")
	})

	return cmd
}

// runDetach executes the detach command
func runDetach(cmd *cobra.Command, args []string) error {
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

	return detachPrograms(args[0])
}

// detachPrograms removes one or more allowed binary programs from an existing protected credential file.
// baselineID is the SHA identifier of the protected file.
func detachPrograms(baselineID string) error {
	var absAllowedBinaries []string
	for _, binary := range updateProgramPermit {
		absBinary, err := filepath.Abs(binary)
		if err != nil {
			return fmt.Errorf("failed to resolve path %s: %w", binary, err)
		}
		absAllowedBinaries = append(absAllowedBinaries, absBinary)
	}

	password, err := getPasswordFromPrompt("Enter admin password to detach programs: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	conn, err := createEnclaveClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := enclave.NewEnclaveGuardServiceClient(conn)

	req := &enclave.DetachProgramsRequest{
		Sha:             baselineID,
		Password:        string(password),
		AllowedBinaries: absAllowedBinaries,
	}

	resp, err := client.DetachPrograms(context.Background(), req)
	if err != nil {
		return fmt.Errorf("failed to detach programs: %w", err)
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("failed to detach programs: %s", resp.GetMessage())
	}

	fmt.Printf("Successfully updated credential %s\n", baselineID)
	if len(resp.GetRemoved()) > 0 {
		fmt.Printf("Removed (%d):   %v\n", len(resp.GetRemoved()), resp.GetRemoved())
	}
	if len(resp.GetNotFound()) > 0 {
		fmt.Printf("Not found (%d): %v (not in allowed list)\n", len(resp.GetNotFound()), resp.GetNotFound())
	}

	return nil
}
