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
	"google.golang.org/protobuf/types/known/emptypb"
)

// ProtectedFile represents a protected credential file for JSON output
type ProtectedFile struct {
	ID                    string   `json:"id"`
	TargetPath            string   `json:"target_path"`
	Strategy              string   `json:"strategy"`
	Permissions           string   `json:"permissions"`
	OwnerUID              uint32   `json:"owner_uid"`
	OwnerGID              uint32   `json:"owner_gid"`
	Mode                  uint32   `json:"mode"`
	AllowedProgram        string   `json:"permitted_program"`
	AllowedBinariesSha256 []string `json:"program_sha256"`
	MaxOpenCount          string   `json:"open_frequency"`
	Writable              bool     `json:"writable"`
	Measure               bool     `json:"measure"`
}

// createListCmd creates the list command
func createListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all protected credential files in the enclave",
		Long:  `Lists all protected credential files currently stored in the enclave.`,
		Args:  cobra.NoArgs,
		RunE:  runList,
	}

	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")
	cmd.Flags().BoolP("json", "j", false, "Output results in JSON format")

	// Set custom help text for list command
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", cmd.CommandPath())
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
		fmt.Fprintf(os.Stderr, "  %s\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s --socket-dir /custom/dir\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\nNote: The --config flag can be used to load settings from a JSON file.\n")
	})

	return cmd
}

// runList executes the list command
func runList(cmd *cobra.Command, args []string) error {
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
	return listProtectedFiles(jsonFormat)
}

// listProtectedFiles lists all protected credential files in the enclave
func listProtectedFiles(jsonFormat bool) error {
	// Create gRPC connection to EnclaveDaemon via Unix Domain Socket
	conn, err := createEnclaveClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := enclave.NewEnclaveGuardServiceClient(conn)

	// Create Empty request
	req := &emptypb.Empty{}

	// Call ListProtectedFiles
	resp, err := client.ListProtectedFiles(context.Background(), req)
	if err != nil || !resp.GetSuccess() {
		if resp != nil {
			return fmt.Errorf("failed to list protected files: %w (server message: %s)", err, resp.GetMessage())
		}
		return fmt.Errorf("failed to list protected files: %w", err)
	}

	if jsonFormat {
		// Format as JSON
		protectedFiles := make([]ProtectedFile, 0, len(resp.GetBaselines()))

		for _, baseline := range resp.GetBaselines() {
			perms := baseline.GetPermissions()
			permStr := fmt.Sprintf("%#o (uid:%d,gid:%d)", perms.GetMode(), perms.GetUid(), perms.GetGid())

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

			protectedFiles = append(protectedFiles, protectedFile)
		}

		jsonOutput, err := json.MarshalIndent(protectedFiles, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON output: %w", err)
		}

		fmt.Println(string(jsonOutput))
	} else {
		// Print the list of protected files in table format
		fmt.Println("Protected Files in Enclave:")
		fmt.Printf("Total Count: %d\n", len(resp.GetBaselines()))
		fmt.Println("------------------------------------------------------------------------------------------------------")
		fmt.Printf("%-12s %-32s %-20s %-18s %-14s %-8s %-8s %-s\n",
			"id", "Target Path", "Permissions", "Strategy", "Open Frequency", "Writable", "Measure", "Permitted Program")
		fmt.Println("------------------------------------------------------------------------------------------------------")

		for _, baseline := range resp.GetBaselines() {
			perms := baseline.GetPermissions()
			permStr := fmt.Sprintf("%#o (uid:%d,gid:%d)", perms.GetMode(), perms.GetUid(), perms.GetGid())

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

			fmt.Printf("%-12s %-32s %-20s %-18s %-14s %-8v %-8v %-s\n",
				baseline.GetSha(),
				baseline.GetTargetPath(),
				permStr,
				baseline.GetVerificationStrategy(),
				maxOpenStr,
				baseline.GetWritable(),
				baseline.GetMeasure(),
				allowedBins)
		}
		fmt.Println("------------------------------------------------------------------------------------------------------")
		fmt.Println("Use 'credctl inspect <id>' to view full details of a specific credential.")
	}

	return nil
}
