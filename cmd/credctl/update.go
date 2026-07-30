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

// createUpdateCmd creates the update command
func createUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [flags] <id>",
		Short: "Update security configuration options for a protected credential file",
		Long:  `Updates the security configuration options for an existing protected credential file in the enclave.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runUpdate,
	}

	cmd.Flags().StringVarP(&updateStrategy, "strategy", "s", "", "Strategy for credential protection (ONE_TIME_USE|PID_BIND|SPEC_VERIFICATION|BASIC)")
	cmd.Flags().StringSliceVarP(&updateProgramPermit, "program-permit", "p", []string{}, "The path to program that is allowed to access this credential (can be specified multiple times)")
	cmd.Flags().StringVarP(&updateMeasureBinaryStr, "measure", "m", "", "Whether to verify SHA256 of allowed binaries at runtime (true/false)")
	cmd.Flags().Int64VarP(&updateOpenFrequency, "open-frequency", "o", 0, "Maximum number of times the credential can be opened (0 means unlimited)")
	cmd.Flags().StringVarP(&updateWritableStr, "writable", "w", "", "Whether the credential file can be modified (true/false)")
	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")

	// Set custom help text for update command
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <baseline_id>\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\n%s\n", cmd.Long)
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		fmt.Fprintf(os.Stderr, "  -s, --strategy string              Update verification strategy (ONE_TIME_USE|PID_BIND|SPEC_VERIFICATION|BASIC)\n")
		fmt.Fprintf(os.Stderr, "  -p, --program-permit strings       Update allowed program paths (SHA256 is always computed for each program)\n")
		fmt.Fprintf(os.Stderr, "  -m, --measure bool                 Whether to verify SHA256 of allowed binaries at runtime (true/false, independent of --program-permit)\n")
		fmt.Fprintf(os.Stderr, "  -o, --open-frequency int           Maximum number of times the credential can be opened (0 means unlimited)\n")
		fmt.Fprintf(os.Stderr, "  -w, --writable bool                Update whether the file can be modified (true/false)\n")
		fmt.Fprintf(os.Stderr, "  -d, --socket-dir string            Directory for Unix Domain Socket files\n")
		fmt.Fprintf(os.Stderr, "                                     (default \"/run/credagent\")\n")
		fmt.Fprintf(os.Stderr, "  -c, --config string                Path to the configuration file (JSON format)\n")
		fmt.Fprintf(os.Stderr, "                                     (default \"/usr/local/etc/credagent/credctl/config.json\")\n")
		fmt.Fprintf(os.Stderr, "\nNote: --program-permit and --measure are independent. SHA256 is always recorded for all allowed binaries.\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s abc123 --strategy ONE_TIME_USE\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s abc123 --program-permit /usr/bin/psql\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s abc123 --measure false\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s abc123 --program-permit /usr/bin/psql --measure true\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s abc123 --open-frequency 10\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s abc123 --writable true\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\nNote: The baseline_id is the SHA identifier shown in the 'list' command output.\n")
	})

	return cmd
}

// runUpdate executes the update command
func runUpdate(cmd *cobra.Command, args []string) error {
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

	// Check if any update parameter was specified
	hasUpdateParam := cmd.Flags().Changed("strategy") || cmd.Flags().Changed("program-permit") ||
		cmd.Flags().Changed("measure") || cmd.Flags().Changed("open-frequency") || cmd.Flags().Changed("writable")
	if !hasUpdateParam {
		fmt.Println("No update parameters specified. Please specify at least one parameter to update:")
		fmt.Println()
		fmt.Println("  --strategy,-s         Update verification strategy (ONE_TIME_USE|PID_BIND|SPEC_VERIFICATION|BASIC)")
		fmt.Println("  --program-permit,-p   Update allowed program paths (SHA256 is always computed for each program)")
		fmt.Println("  --measure,-m          Whether to verify SHA256 of allowed binaries at runtime (true/false)")
		fmt.Println("  --open-frequency,-o   Update open frequency (0 or negative means unlimited)")
		fmt.Println("  --writable,-w         Update whether the file can be modified (true/false)")
		return nil
	}

	// Validate --measure value if provided
	measureChanged := cmd.Flags().Changed("measure")
	if measureChanged && updateMeasureBinaryStr != "true" && updateMeasureBinaryStr != "false" {
		return fmt.Errorf("--measure must be 'true' or 'false' (got '%s')", updateMeasureBinaryStr)
	}

	strategyChanged := cmd.Flags().Changed("strategy")
	programPermitChanged := cmd.Flags().Changed("program-permit")
	openFrequencyChanged := cmd.Flags().Changed("open-frequency")
	writableChanged := cmd.Flags().Changed("writable")

	return updateCredential(args[0], strategyChanged, programPermitChanged, measureChanged, openFrequencyChanged, writableChanged)
}

// updateCredential updates security configuration options for a protected credential file.
// baselineID is the SHA identifier of the protected file (from the 'list' command output).
func updateCredential(baselineID string, strategyChanged, programPermitChanged, measureChanged, openFrequencyChanged, writableChanged bool) error {
	password, err := getPasswordFromPrompt("Enter admin password to update the credential: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	conn, err := createEnclaveClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := enclave.NewEnclaveGuardServiceClient(conn)

	req := &enclave.UpdateFileAccessRule{
		Sha:      baselineID,
		Password: string(password),
	}

	if strategyChanged {
		req.Strategy = updateStrategy
	}

	if programPermitChanged {
		var absAllowedBinaries []string
		for _, binary := range updateProgramPermit {
			absBinary, err := filepath.Abs(binary)
			if err != nil {
				return fmt.Errorf("failed to convert allowed program to absolute path: %w", err)
			}
			absAllowedBinaries = append(absAllowedBinaries, absBinary)
		}
		var sha256List []string
		for _, binary := range absAllowedBinaries {
			hash, err := calculateSHA256(binary)
			if err != nil {
				return fmt.Errorf("failed to calculate SHA256 for %s: %w", binary, err)
			}
			sha256List = append(sha256List, hash)
		}
		req.AllowedBinaries = absAllowedBinaries
		req.AllowedBinariesSha256 = sha256List
		req.UpdateAllowedBinaries = true
	}

	if measureChanged {
		req.Measure = updateMeasureBinaryStr == "true"
		req.UpdateMeasure = true
	}

	if openFrequencyChanged {
		req.MaxOpenCount = updateOpenFrequency
		req.UpdateMaxOpenCount = true
	}

	if writableChanged {
		req.Writable = updateWritableStr == "true"
		req.UpdateWritable = true
	}

	updateResp, err := client.UpdateFileInfo(context.Background(), req)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}
	if !updateResp.GetSuccess() {
		return fmt.Errorf("failed to update credential: %s", updateResp.GetMessage())
	}

	fmt.Printf("Successfully updated credential %s\n", baselineID)

	updatedBaseline := updateResp.GetUpdatedBaseline()
	if strategyChanged {
		fmt.Printf("Updated strategy: %s\n", updatedBaseline.GetVerificationStrategy())
	}
	if programPermitChanged {
		fmt.Printf("Updated allowed binaries: %v\n", updatedBaseline.GetAllowedBinaries())
	}
	if measureChanged {
		fmt.Printf("Updated measure: %v\n", updatedBaseline.GetMeasure())
	}
	if openFrequencyChanged {
		fmt.Printf("Updated max open count: %d\n", updatedBaseline.GetMaxOpenCount())
	}
	if writableChanged {
		fmt.Printf("Updated writable: %v\n", updatedBaseline.GetWritable())
	}

	return nil
}
