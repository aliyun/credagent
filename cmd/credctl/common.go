package main

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alibaba/CredAgent/internal/config"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Default FUSE mount point - this should match the mount point used by CredMonitor
var DefaultFuseMountPoint = "/mnt/shielded"

// Common flags used by multiple commands
var (
	// Common flags
	socketDir  string
	configFile string

	// Protect command flags
	strategy         string
	programPermit    []string
	measureBinaryStr string // String type to support "--measure true" format
	openFrequency    int64
	writableStr      string // String type to support "--writable true" format

	// Update command flags
	updateStrategy         string
	updateProgramPermit    []string
	updateMeasureBinaryStr string // String type to support "--measure true" format
	updateOpenFrequency    int64
	updateWritableStr      string // String type to support "--writable true" format

	// List command flags
	jsonFormatStr string // String type to support "--json true" format
)

// getPasswordFromPrompt prompts the user for a password without echoing it to the terminal.
// The prompt is written directly to /dev/tty (like sudo/ssh) so it is visible
// regardless of stdout/stderr redirection.
func getPasswordFromPrompt(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_WRONLY, 0)
	if err != nil {
		// Fallback: if /dev/tty is unavailable, write to stderr
		fmt.Fprint(os.Stderr, prompt)
	} else {
		fmt.Fprint(tty, prompt)
		tty.Close()
	}
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	// Print newline to tty after hidden password input
	if tty, err2 := os.OpenFile("/dev/tty", os.O_WRONLY, 0); err2 == nil {
		fmt.Fprintln(tty)
		tty.Close()
	} else {
		fmt.Fprintln(os.Stderr)
	}
	return password, err
}

// calculateSHA256 calculates the SHA256 hash of a file
func calculateSHA256(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), nil
}

// getShaFromTargetPath extracts the SHA from the target path by looking up in the baseline
func getShaFromTargetPath(targetPath string) string {
	// For now, we'll just return the target path basename as the SHA identifier
	// In a real implementation, we'd look up the SHA from the baseline store
	return filepath.Base(targetPath)
}

// writeBackFile writes the file content back to the filesystem with specified permissions
func writeBackFile(filePath string, fileContent []byte, ownerUID uint32, ownerGID uint32, permission uint32) error {
	// Ensure parent directory exists before writing the file
	parentDir := filepath.Dir(filePath)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	// Write the file with the original permissions
	if err := os.WriteFile(filePath, fileContent, os.FileMode(permission)); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}

	// Try to change ownership to original owner
	ownershipChanged := true
	if err := os.Chown(filePath, int(ownerUID), int(ownerGID)); err != nil {
		ownershipChanged = false
	}

	// Try to change permissions to original
	permissionChanged := true
	if err := os.Chmod(filePath, os.FileMode(permission)); err != nil {
		permissionChanged = false
	}

	// Print warnings if we couldn't restore ownership or permissions
	if !ownershipChanged {
		fmt.Printf("WARNING: Could not restore owner/group for %s\n", filePath)
	}
	if !permissionChanged {
		fmt.Printf("WARNING: Could not restore permissions for %s\n", filePath)
	}

	return nil
}

// getEnclaveSocketFile returns the socket file path for the enclave service
func getEnclaveSocketFile() string {
	cfg, _ := config.LoadConfig(configFile)
	if cfg != nil && cfg.Enclave != nil && cfg.Enclave.SocketFile != "" {
		return cfg.Enclave.SocketFile
	}
	// Use default naming convention: <socket-dir>/enclave.sock
	return filepath.Join(socketDir, "enclave.sock")
}

// createEnclaveClient creates a gRPC client connection to the EnclaveDaemon
func createEnclaveClient() (*grpc.ClientConn, error) {
	enclaveSocketFile := getEnclaveSocketFile()
	tlsCreds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
	conn, err := grpc.Dial("unix:"+enclaveSocketFile, grpc.WithTransportCredentials(tlsCreds))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to EnclaveDaemon: %w", err)
	}
	return conn, nil
}

// loadConfigIfChanged loads config and updates socketDir if not explicitly set via command line
func loadConfigIfChanged(cmd interface {
	Flags() interface{ Changed(string) bool }
}, socketDirFlagName string) error {
	if configFile == "" {
		return nil
	}

	if _, err := os.Stat(configFile); err != nil {
		// Config file doesn't exist, use defaults
		return nil
	}

	cfg, err := config.LoadConfig(configFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Update socketDir from config only if not explicitly set via command line
	if !cmd.Flags().(interface{ Changed(string) bool }).Changed(socketDirFlagName) {
		if cfg.Enclave != nil && cfg.Enclave.SocketDir != "" {
			socketDir = cfg.Enclave.SocketDir
		} else {
			socketDir = "/run/credagent"
		}
	}

	return nil
}
