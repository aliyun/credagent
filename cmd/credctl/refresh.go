package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/config"
	"github.com/spf13/cobra"
)

// createRefreshCmd creates the refresh command
func createRefreshCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "refresh [flags] <id>",
		Short: "Refresh SHA256 values for already-authorized programs in a protected credential file",
		Long:  `Recomputes and updates the SHA256 hash for one or more programs already present in a protected credential file's allowed list. Programs not in the allowed list are reported and skipped — use 'attach' to add new programs.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runRefresh,
	}

	cmd.Flags().StringSliceVarP(&updateProgramPermit, "program-permit", "p", []string{}, "The path to program to refresh SHA256 for (can be specified multiple times)")
	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")

	// Set custom help text for refresh command
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <baseline_id>\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\n%s\n", cmd.Long)
		fmt.Fprintf(os.Stderr, "\nOptional Flags:\n")
		fmt.Fprintf(os.Stderr, "  -p, --program-permit strings       The path to program to refresh SHA256 for (can be specified multiple times)\n")
		fmt.Fprintf(os.Stderr, "                                     If not specified, ALL authorized programs will be refreshed.\n")
		fmt.Fprintf(os.Stderr, "  -d, --socket-dir string            Directory for Unix Domain Socket files (default \"/run/credagent\")\n")
		fmt.Fprintf(os.Stderr, "  -c, --config string                Path to the configuration file (JSON format)\n")
		fmt.Fprintf(os.Stderr, "                                     (default \"/usr/local/etc/credagent/credctl/config.json\")\n")
		fmt.Fprintf(os.Stderr, "\nBehavior:\n")
		fmt.Fprintf(os.Stderr, "  SHA256 is recomputed from the current binary on disk and stored at the paired index.\n")
		fmt.Fprintf(os.Stderr, "  Programs not in the baseline's allowed list are skipped and reported.\n")
		fmt.Fprintf(os.Stderr, "  Use 'credctl attach' to add a new program to the allowed list.\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s abc123 --program-permit /usr/bin/psql\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s abc123 -p /usr/bin/psql -p /usr/bin/pg_dump\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s abc123                                       (refresh ALL authorized programs)\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\nNote: The baseline_id is the SHA identifier shown in the 'list' command output.\n")
	})

	return cmd
}

// runRefresh executes the refresh command
func runRefresh(cmd *cobra.Command, args []string) error {
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

	return refreshPrograms(args[0], cmd.Flags().Changed("program-permit"))
}

// abbreviateSha256 returns the first 5 and last 5 characters of a SHA256 hash separated by ***.
func abbreviateSha256(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:5] + "***" + hash[len(hash)-5:]
}

// refreshPrograms recomputes and updates SHA256 values for already-authorized programs.
// Programs not in the allowed list are skipped and reported; they are not added.
// baselineID is the SHA identifier of the protected file.
func refreshPrograms(baselineID string, programFlagSpecified bool) error {
	conn, err := createEnclaveClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := enclave.NewEnclaveGuardServiceClient(conn)

	// Fetch baseline info to get old SHA256 values for display and (optionally) the full program list.
	infoResp, err := client.GetProtectedFileInfo(context.Background(), &enclave.GetProtectedFileInfoRequest{
		Sha: baselineID,
	})
	if err != nil {
		return fmt.Errorf("failed to get baseline info: %w", err)
	}
	if !infoResp.GetSuccess() {
		return fmt.Errorf("failed to get baseline info: %s", infoResp.GetMessage())
	}
	bl := infoResp.GetBaseline()
	if bl == nil {
		return fmt.Errorf("baseline not found for ID: %s", baselineID)
	}

	// Build old SHA256 map from baseline for display purposes.
	oldSha256Map := make(map[string]string)
	programs := bl.GetAllowedBinaries()
	sha256s := bl.GetAllowedBinariesSha256()
	for i, prog := range programs {
		if i < len(sha256s) {
			oldSha256Map[prog] = sha256s[i]
		}
	}

	// If no -p specified, refresh all authorized programs.
	if !programFlagSpecified || len(updateProgramPermit) == 0 {
		fmt.Println("\033[33m⚠  未指定 -p 参数，将刷新该凭证全部已授权程序的 SHA256 值\033[0m")
		fmt.Println()

		updateProgramPermit = bl.GetAllowedBinaries()
		if len(updateProgramPermit) == 0 {
			fmt.Println("该凭证没有已授权的程序。")
			return nil
		}
	}

	// Convert to absolute paths, verify each binary exists, and compute new SHA256 values.
	var absAllowedBinaries []string
	var sha256List []string
	var failedBinaries []string
	for _, binary := range updateProgramPermit {
		absBinary, err := filepath.Abs(binary)
		if err != nil {
			failedBinaries = append(failedBinaries, binary)
			continue
		}
		hash, err := calculateSHA256(absBinary)
		if err != nil {
			failedBinaries = append(failedBinaries, absBinary)
			continue
		}
		absAllowedBinaries = append(absAllowedBinaries, absBinary)
		sha256List = append(sha256List, hash)
	}

	if len(absAllowedBinaries) == 0 && len(failedBinaries) > 0 {
		return fmt.Errorf("failed to compute SHA256 for all specified programs")
	}

	password, err := getPasswordFromPrompt("Enter admin password to refresh programs: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	req := &enclave.RefreshProgramsRequest{
		Sha:                   baselineID,
		Password:              string(password),
		AllowedBinaries:       absAllowedBinaries,
		AllowedBinariesSha256: sha256List,
	}

	resp, err := client.RefreshPrograms(context.Background(), req)
	if err != nil {
		return fmt.Errorf("failed to refresh programs: %w", err)
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("failed to refresh programs: %s", resp.GetMessage())
	}

	// Build new SHA256 map for display.
	newSha256Map := make(map[string]string)
	for i, bin := range absAllowedBinaries {
		if i < len(sha256List) {
			newSha256Map[bin] = sha256List[i]
		}
	}

	// Build sets for quick lookup.
	refreshedSet := make(map[string]bool)
	for _, p := range resp.GetRefreshed() {
		refreshedSet[p] = true
	}

	// Display results.
	fmt.Println()
	for _, bin := range absAllowedBinaries {
		oldHash := oldSha256Map[bin]
		newHash := newSha256Map[bin]
		if refreshedSet[bin] {
			fmt.Printf("  [刷新]   %s  %s -> %s\n", bin, abbreviateSha256(oldHash), abbreviateSha256(newHash))
		} else {
			fmt.Printf("  [未刷新] %s\n", bin)
		}
	}

	// Show programs that failed to compute SHA256 (e.g., binary not found on disk).
	for _, bin := range failedBinaries {
		fmt.Printf("  [未刷新] %s (无法读取程序文件)\n", bin)
	}

	// Show programs not authorized (only when -p specified with non-authorized programs).
	for _, bin := range resp.GetNotAuthorized() {
		fmt.Printf("  [未刷新] %s (未授权，请使用 credctl attach 添加)\n", bin)
	}

	fmt.Println()
	fmt.Printf("刷新完成: %d 已刷新, %d 未刷新\n", len(resp.GetRefreshed()), len(resp.GetNotAuthorized())+len(failedBinaries))

	return nil
}
