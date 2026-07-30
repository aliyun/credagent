package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/config"
	"github.com/spf13/cobra"
)

// createProtectCmd creates the protect command
func createProtectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "protect [flags] <target_filepath>",
		Short: "Protect a credential file by moving it to the enclave",
		Long:  `Protects a credential file by uploading it to the enclave and securely removing the original.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runProtect,
	}

	cmd.Flags().StringVarP(&strategy, "strategy", "s", "BASIC", "Strategy for credential protection (ONE_TIME_USE|PID_BIND|SPEC_VERIFICATION|BASIC, default BASIC)")
	cmd.Flags().StringSliceVarP(&programPermit, "program-permit", "p", []string{}, "The path to program that is allowed to access this credential (can be specified multiple times)")
	cmd.Flags().StringVarP(&measureBinaryStr, "measure", "m", "true", "Whether to measure and store the SHA256 hash of the allowed binaries (true/false, default true)")
	cmd.Flags().Int64VarP(&openFrequency, "open-frequency", "o", 0, "Maximum number of times the credential can be opened (0 means unlimited)")
	cmd.Flags().StringVarP(&writableStr, "writable", "w", "false", "Whether the credential file can be modified (default false)")
	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")

	cmd.MarkFlagRequired("program-permit")

	// Set custom help text for protect command
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <target_filepath>\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\n%s\n", cmd.Long)
		fmt.Fprintf(os.Stderr, "\nAvailable Strategies:\n")
		fmt.Fprintf(os.Stderr, "  ONE_TIME_USE    - Credential is deleted after first access\n")
		fmt.Fprintf(os.Stderr, "  PID_BIND        - Credential is bound to the original process ID\n")
		fmt.Fprintf(os.Stderr, "  SPEC_VERIFICATION - Credential is accessed through command spec verification\n")
		fmt.Fprintf(os.Stderr, "  BASIC           - Basic verification without additional checks (default)\n")
		fmt.Fprintf(os.Stderr, "\nRequired Flags:\n")
		fmt.Fprintf(os.Stderr, "  -p, --program-permit strings       The path to program that is allowed to access this credential (can be specified multiple times)\n")
		fmt.Fprintf(os.Stderr, "\nOptional Flags:\n")
		fmt.Fprintf(os.Stderr, "  -s, --strategy string              Strategy for credential protection (ONE_TIME_USE|PID_BIND|SPEC_VERIFICATION|BASIC, default BASIC)\n")
		fmt.Fprintf(os.Stderr, "  -m, --measure string               Whether to measure SHA256 hash of allowed binaries (true/false, default true)\n")
		fmt.Fprintf(os.Stderr, "  -o, --open-frequency int           Maximum number of times the credential can be opened (0 means unlimited)\n")
		fmt.Fprintf(os.Stderr, "  -w, --writable string              Allow the credential file to be modified (true/false, default false)\n")
		fmt.Fprintf(os.Stderr, "  -d, --socket-dir string            Directory for Unix Domain Socket files (default \"/run/credagent\")\n")
		fmt.Fprintf(os.Stderr, "  -c, --config string                Path to the configuration file (JSON format)\n")
		fmt.Fprintf(os.Stderr, "                                     (default \"/usr/local/etc/credagent/credctl/config.json\")\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --strategy ONE_TIME_USE --program-permit /usr/bin/psql /etc/psql/passwd\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s --strategy BASIC --program-permit /usr/bin/psql /etc/psql/passwd\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s --strategy BASIC --program-permit /usr/bin/cat -m false /etc/myfile.txt\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\nNote: The --config flag can be used to load settings from a JSON file.\n")
	})

	return cmd
}

// runProtect executes the protect command
func runProtect(cmd *cobra.Command, args []string) error {
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

	return protectCredential(args[0])
}

// protectCredential protects a credential file by moving it to the enclave
func protectCredential(targetPath string) error {
	// Convert targetPath to absolute path
	absTargetPath, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("failed to convert target path to absolute path: %w", err)
	}

	// Convert program permits to absolute paths
	var absAllowedBinaries []string
	for _, binary := range programPermit {
		absBinary, err := filepath.Abs(binary)
		if err != nil {
			return fmt.Errorf("failed to convert allowed binary to absolute path: %w", err)
		}
		absAllowedBinaries = append(absAllowedBinaries, absBinary)
	}

	// Load config if provided to get the correct mount point
	if configFile != "" {
		if _, err := os.Stat(configFile); err == nil {
			cfg, err := config.LoadConfig(configFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			// Check if Monitor config exists and has MountPoint
			if cfg.Monitor == nil || cfg.Monitor.MountPoint == "" {
				return fmt.Errorf("configuration error: 'monitor.mount_point' is required in config file '%s'. Please specify the FUSE mount point in your configuration", configFile)
			}
			DefaultFuseMountPoint = cfg.Monitor.MountPoint
		}
	}

	// Read plaintext from target file
	data, err := os.ReadFile(absTargetPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", absTargetPath, err)
	}

	// Get file permissions
	fileInfo, err := os.Stat(absTargetPath)
	if err != nil {
		return fmt.Errorf("failed to get file info for %s: %w", absTargetPath, err)
	}
	permissions := &enclave.FilePerms{
		Uid:  uint32(fileInfo.Sys().(*syscall.Stat_t).Uid),
		Gid:  uint32(fileInfo.Sys().(*syscall.Stat_t).Gid),
		Mode: uint32(fileInfo.Mode().Perm()),
	}

	// Parse measureBinaryStr to boolean (default is "true")
	measureBinary := measureBinaryStr == "true"

	// Always calculate SHA256 hashes for all allowed binaries
	var allowedBinariesSha256 []string
	for _, binary := range absAllowedBinaries {
		hash, err := calculateSHA256(binary)
		if err != nil {
			return fmt.Errorf("failed to calculate SHA256 for %s: %w", binary, err)
		}
		allowedBinariesSha256 = append(allowedBinariesSha256, hash)
	}

	// Parse writableStr to boolean
	writable := writableStr == "true"

	// Create OnboardFileRequest
	req := &enclave.OnboardFileRequest{
		TargetPath:            absTargetPath,
		PlaintextData:         data,
		Permissions:           permissions,
		AllowedBinaries:       absAllowedBinaries,
		AllowedBinariesSha256: allowedBinariesSha256,
		VerificationStrategy:  strategy,
		MaxOpenCount:          openFrequency,
		Writable:              writable,
		Measure:               measureBinary,
	}

	// Create gRPC connection to EnclaveDaemon via Unix Domain Socket
	conn, err := createEnclaveClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := enclave.NewEnclaveGuardServiceClient(conn)

	// Call OnboardFile
	resp, err := client.OnboardFile(context.Background(), req)
	if err != nil || !resp.GetSuccess() {
		if resp != nil {
			return fmt.Errorf("failed to onboard credential: %w (server message: %s)", err, resp.GetMessage())
		}
		return fmt.Errorf("failed to onboard credential: %w", err)
	}

	// Get the SHA identifier from the response - this is the authoritative source
	shaIdentifier := resp.GetSha()
	if shaIdentifier == "" {
		return fmt.Errorf("server did not return SHA identifier for onboarded file")
	}

	// Secure shredding: overwrite with zeros and remove
	file, err := os.OpenFile(targetPath, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open %s for shredding: %w", targetPath, err)
	}
	defer file.Close()

	// Overwrite with zeros
	zeros := make([]byte, len(data))
	_, err = file.WriteAt(zeros, 0)
	if err != nil {
		return fmt.Errorf("failed to overwrite %s: %w", targetPath, err)
	}

	// Sync to disk
	err = file.Sync()
	if err != nil {
		return fmt.Errorf("failed to sync %s: %w", targetPath, err)
	}

	// Atomically replace the original file with a symlink to the FUSE mount point.
	// Using Rename instead of Remove+Symlink eliminates the TOCTOU race window
	// where an attacker could create a malicious file at targetPath between the two calls.
	fusePath := fmt.Sprintf("%s/%s", DefaultFuseMountPoint, shaIdentifier)
	tmpLink := targetPath + ".credagent.tmp"
	os.Remove(tmpLink) // best-effort cleanup of stale temp link
	if err := os.Symlink(fusePath, tmpLink); err != nil {
		os.Remove(targetPath) // fall back: at least remove the zeroed file
		return fmt.Errorf("failed to create temporary symlink: %w", err)
	}
	if err := os.Rename(tmpLink, targetPath); err != nil {
		os.Remove(tmpLink)
		return fmt.Errorf("failed to atomically replace %s with symlink: %w", targetPath, err)
	}

	fmt.Printf("Successfully onboarded %s, securely shredded, and created symlink to %s.\n", targetPath, fusePath)
	return nil
}
