package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// createInspectCmd creates the inspect command
func createInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect [flags] <id>",
		Short: "Inspect details of a specific protected credential file",
		Long:  `Displays detailed information about a specific protected credential file identified by its SHA ID.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runInspect,
	}

	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")
	cmd.Flags().BoolP("json", "j", false, "Output results in JSON format")

	// Set custom help text for inspect command
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
		fmt.Fprintf(os.Stderr, "  %s abc123 --json\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\nNote: The 'id' is the SHA identifier shown in the 'list' command output.\n")
	})

	return cmd
}

// runInspect executes the inspect command
func runInspect(cmd *cobra.Command, args []string) error {
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

	jsonFormat, _ := cmd.Flags().GetBool("json")
	return inspectProtectedFile(args[0], jsonFormat)
}

// inspectProtectedFile inspects a specific protected credential file by its SHA ID
func inspectProtectedFile(sha string, jsonFormat bool) error {
	// Create gRPC connection to EnclaveDaemon via Unix Domain Socket
	conn, err := createEnclaveClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := enclave.NewEnclaveGuardServiceClient(conn)

	// Create GetProtectedFileInfoRequest with SHA identifier
	req := &enclave.GetProtectedFileInfoRequest{
		Sha: sha,
	}

	// Call GetProtectedFileInfo
	resp, err := client.GetProtectedFileInfo(context.Background(), req)
	if err != nil {
		return fmt.Errorf("failed to inspect protected file: %w", err)
	}

	if !resp.GetSuccess() {
		return fmt.Errorf("protected file not found: %s", resp.GetMessage())
	}

	baseline := resp.GetBaseline()
	if baseline == nil {
		return fmt.Errorf("no baseline data returned for ID: %s", sha)
	}

	// Build ProtectedFile struct (same as list command)
	perms := baseline.GetPermissions()
	permStr := fmt.Sprintf("%#o (uid:%d,gid:%d)", perms.GetMode(), perms.GetUid(), perms.GetGid())

	// For the ProtectedFile struct, we still need to create a string representation for AllowedProgram
	// since the struct field is defined as string in the shared struct
	allowedBins := ""
	if len(baseline.GetAllowedBinaries()) > 0 {
		allowedBins = baseline.GetAllowedBinaries()[0]
		if len(baseline.GetAllowedBinaries()) > 1 {
			allowedBins += fmt.Sprintf(" (+%d more)", len(baseline.GetAllowedBinaries())-1)
		}
	}

	maxOpenCount := baseline.GetMaxOpenCount()
	maxOpenStr := "unlimited"
	if maxOpenCount > 0 {
		maxOpenStr = fmt.Sprintf("%d", maxOpenCount)
	}

	protectedFile := ProtectedFile{
		ID:                    baseline.GetSha(),
		TargetPath:            baseline.GetTargetPath(),
		Strategy:              baseline.GetVerificationStrategy(),
		Permissions:           permStr,
		OwnerUID:              perms.GetUid(),
		OwnerGID:              perms.GetGid(),
		Mode:                  perms.GetMode(),
		AllowedProgram:        allowedBins,
		AllowedBinariesSha256: baseline.GetAllowedBinariesSha256(),
		MaxOpenCount:          maxOpenStr,
		Writable:              baseline.GetWritable(),
		Measure:               baseline.GetMeasure(),
	}

	if jsonFormat {
		// Output as JSON with full permitted_program array
		jsonOutput := map[string]any{
			"id":                protectedFile.ID,
			"target_path":       protectedFile.TargetPath,
			"strategy":          protectedFile.Strategy,
			"permissions":       protectedFile.Permissions,
			"owner_uid":         protectedFile.OwnerUID,
			"owner_gid":         protectedFile.OwnerGID,
			"mode":              protectedFile.Mode,
			"permitted_program": baseline.GetAllowedBinaries(),
			"program_sha256":    protectedFile.AllowedBinariesSha256,
			"open_frequency":    protectedFile.MaxOpenCount,
			"writable":          protectedFile.Writable,
			"measure":           protectedFile.Measure,
		}
		jsonBytes, err := json.MarshalIndent(jsonOutput, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON output: %w", err)
		}
		fmt.Println(string(jsonBytes))
	} else {
		// Output in plain text format with field names matching JSON keys
		fmt.Println("Protected Credential File Details:")
		fmt.Println("-----------------------------------")
		fmt.Printf("id: %s\n", protectedFile.ID)
		fmt.Printf("target_path: %s\n", protectedFile.TargetPath)
		fmt.Printf("strategy: %s\n", protectedFile.Strategy)
		fmt.Printf("permissions: %s\n", protectedFile.Permissions)
		fmt.Printf("owner_uid: %d\n", protectedFile.OwnerUID)
		fmt.Printf("owner_gid: %d\n", protectedFile.OwnerGID)
		fmt.Printf("mode: %#o\n", protectedFile.Mode)

		// Display all allowed binaries (not truncated like in the ProtectedFile struct)
		if len(baseline.GetAllowedBinaries()) > 0 {
			fmt.Printf("permitted_program: %v\n", baseline.GetAllowedBinaries())
		} else {
			fmt.Printf("permitted_program: N/A\n")
		}

		// Display all SHA256 hashes for inspect (not truncated)
		if len(protectedFile.AllowedBinariesSha256) > 0 {
			fmt.Printf("program_sha256: %v\n", protectedFile.AllowedBinariesSha256)
		} else {
			fmt.Printf("program_sha256: N/A\n")
		}

		fmt.Printf("open_frequency: %s\n", protectedFile.MaxOpenCount)
		fmt.Printf("writable: %v\n", protectedFile.Writable)
		fmt.Printf("measure: %v\n", protectedFile.Measure)
	}

	return nil
}
