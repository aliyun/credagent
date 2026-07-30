package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alibaba/CredAgent/api/gen/enclave"
	"github.com/alibaba/CredAgent/internal/agent"
	"github.com/alibaba/CredAgent/internal/baseline"
	"github.com/alibaba/CredAgent/internal/cache"
	"github.com/alibaba/CredAgent/internal/cmdline"
	"github.com/alibaba/CredAgent/internal/config"
	"github.com/alibaba/CredAgent/internal/fusehook"
	"github.com/alibaba/CredAgent/internal/guard"
	"github.com/alibaba/CredAgent/internal/interpreter"
	"github.com/alibaba/CredAgent/internal/ledger"
	"github.com/alibaba/CredAgent/internal/osutil"
	"github.com/alibaba/CredAgent/internal/uds"
	"github.com/alibaba/CredAgent/pkg/crypto"
	"github.com/alibaba/CredAgent/pkg/logger"
	"github.com/alibaba/CredAgent/pkg/version"
	gofusefs "github.com/hanwen/go-fuse/v2/fs"
	gofuse "github.com/hanwen/go-fuse/v2/fuse"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	keyFile       string
	socketDir     string // Directory for socket files
	baselineFile  string
	configFile    string
	adminPassword string
	logLevel      string
	mountPoint    string // FUSE mount point (merged from credmon)
	useBufNet     bool   // For testing purposes
	autoInit      bool   // --auto-init: bootstrap master key + admin password on first start
)

func init() {
	// Set default log level to info
	logLevel = "info"
	interpreter.Register()
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of credagent",
	Long:  `Print the version number of CredAgent enclave daemon.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("credagent version %s\n", version.Version)
	},
}

// getPasswordWithConfirmation prompts the user for a password twice to confirm it
// Since Go doesn't have built-in password hiding, we'll implement a basic version using os.Stdin
func getPasswordWithConfirmation(scanner *bufio.Scanner) (string, error) {
	for {
		// For password input without echo, we'll use a cross-platform solution
		// Since golang doesn't have built-in password hiding, we'll implement a simple solution
		fmt.Print("Please enter your admin password: ")

		// On Unix-like systems, we can use terminal package to read password without echoing
		password1, err := readPassword()
		if err != nil {
			return "", fmt.Errorf("error reading password: %w", err)
		}

		if len(password1) == 0 {
			return "", fmt.Errorf("password cannot be empty")
		}

		fmt.Print("\nPlease confirm your admin password: ")
		password2, err := readPassword()
		if err != nil {
			return "", fmt.Errorf("error reading password: %w", err)
		}

		fmt.Print("\n") // Add newline after password input

		if password1 != password2 {
			fmt.Println("Passwords do not match. Please try again.")
			continue
		}

		return password1, nil
	}
}

// readPassword reads a password from stdin without echoing
func readPassword() (string, error) {
	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}

	// Print a newline after the hidden input
	fmt.Print("\n")

	return string(bytePassword), nil
}

// ensureRequiredDirectories ensures that all required directories exist
// Creates them with appropriate permissions if they don't exist
func ensureRequiredDirectories(socketDir, keyFile, baselineFile string) error {
	// Ensure socket directory exists with proper permissions for other users to access
	// The directory needs to be traversable by other users (x bit) so they can reach the socket
	if socketDir != "" {
		if err := os.MkdirAll(socketDir, 0751); err != nil {
			return fmt.Errorf("failed to create socket directory: %w", err)
		}
		// Set permissions on the socket directory to ensure others can traverse it
		if err := os.Chmod(socketDir, 0751); err != nil {
			return fmt.Errorf("failed to set socket directory permissions: %w", err)
		}
		logger.Info("Socket directory ensured: %s", socketDir)
	}

	// Ensure key file directory exists with secure permissions
	// Only owner can write, group and others can only read and traverse
	if keyFile != "" {
		keyDir := filepath.Dir(keyFile)
		if err := os.MkdirAll(keyDir, 0750); err != nil {
			return fmt.Errorf("failed to create key file directory: %w", err)
		}
		logger.Info("Key file directory ensured: %s", keyDir)
	}

	// Ensure baseline file directory exists with secure permissions
	// Only owner can write, group and others can only read and traverse
	if baselineFile != "" {
		baselineDir := filepath.Dir(baselineFile)
		if err := os.MkdirAll(baselineDir, 0750); err != nil {
			return fmt.Errorf("failed to create baseline file directory: %w", err)
		}
		logger.Info("Baseline file directory ensured: %s", baselineDir)
	}

	return nil
}

// isSocketInUse checks if a Unix domain socket file is currently in use by attempting to connect to it
func isSocketInUse(socketPath string) bool {
	// Check if the socket file exists
	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return false
	}

	// Try to connect to the socket with a short timeout
	conn, err := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
	if err != nil {
		// If connection fails, the socket might not be in use or might not accept connections
		return false
	}

	// If connection succeeds, close it and return true
	conn.Close()
	return true
}

// isAddrInUseError checks whether the error indicates that the address is already in use (EADDRINUSE).
func isAddrInUseError(err error) bool {
	if opErr, ok := err.(*net.OpError); ok {
		if syscallErr, ok := opErr.Err.(*os.SyscallError); ok {
			return syscallErr.Err == syscall.EADDRINUSE
		}
		return opErr.Err == syscall.EADDRINUSE
	}
	return false
}

func main() {
	rootCmd := &cobra.Command{
		Use:           "credagent",
		Short:         "CredAgent enclave daemon",
		Long:          `CredAgent enclave daemon for managing credential protection.`,
		SilenceUsage:  true, // Don't print usage when error occurs
		SilenceErrors: true, // Don't print errors to stderr (we'll handle logging ourselves)
	}

	// Add the init command
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the enclave by creating a master key file and admin password",
		Long:  `Wizard-style initialization for creating master key file and admin password.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			scanner := bufio.NewScanner(os.Stdin)

			// Step 1: Create master key file
			cfg, err := config.LoadConfig(configFile)
			if err != nil {
				logger.Error("Failed to load config file: %s — %v", configFile, err)
				return fmt.Errorf("failed to load config: %w", err)
			}

			if cfg.Enclave == nil {
				return fmt.Errorf("config file missing required section: \"enclave\"")
			}

			// Override key file with config value if not explicitly set via command line
			if !cmd.Flags().Changed("key-file") && cfg.Enclave.MasterKeyFile != "" {
				keyFile = cfg.Enclave.MasterKeyFile
			}

			// Check if key file already exists
			_, keyExists := os.Stat(keyFile)
			if keyExists == nil {
				fmt.Printf("We detected that a master key file already exists at: %s\n", keyFile)
				fmt.Print("Would you like to overwrite it? (Y/N): ")
				scanner.Scan()
				response := strings.ToLower(strings.TrimSpace(scanner.Text()))
				if response == "y" || response == "yes" {
					// Ensure directory for key file exists with secure permissions
					// Only owner can write, group and others can only read and traverse
					keyDir := filepath.Dir(keyFile)
					if err := os.MkdirAll(keyDir, 0750); err != nil {
						return fmt.Errorf("failed to create key file directory: %w", err)
					}

					// Generate a random 32-byte key
					key := make([]byte, 32)
					if _, err := rand.Read(key); err != nil {
						return fmt.Errorf("failed to generate random key: %w", err)
					}

					// Encode the key as base64 for storage
					encodedKey := base64.StdEncoding.EncodeToString(key)

					// Write the key to file
					if err := os.WriteFile(keyFile, []byte(encodedKey), 0600); err != nil {
						return fmt.Errorf("failed to write key to file: %w", err)
					}

					logger.Info("Successfully created master key file: %s", keyFile)
					fmt.Printf("Master key file created successfully at: %s\n", keyFile)
				} else {
					fmt.Println("Master key creation skipped.")
				}
			} else {
				fmt.Printf("We did not detect an existing master key file.\n")
				fmt.Print("Would you like to create one? (Y/N): ")
				scanner.Scan()
				response := strings.ToLower(strings.TrimSpace(scanner.Text()))
				if response == "y" || response == "yes" {
					// Ensure directory for key file exists with secure permissions
					// Only owner can write, group and others can only read and traverse
					keyDir := filepath.Dir(keyFile)
					if err := os.MkdirAll(keyDir, 0750); err != nil {
						return fmt.Errorf("failed to create key file directory: %w", err)
					}

					// Generate a random 32-byte key
					key := make([]byte, 32)
					if _, err := rand.Read(key); err != nil {
						return fmt.Errorf("failed to generate random key: %w", err)
					}

					// Encode the key as base64 for storage
					encodedKey := base64.StdEncoding.EncodeToString(key)

					// Write the key to file
					if err := os.WriteFile(keyFile, []byte(encodedKey), 0600); err != nil {
						return fmt.Errorf("failed to write key to file: %w", err)
					}

					logger.Info("Successfully created master key file: %s", keyFile)
					fmt.Printf("Master key file created successfully at: %s\n", keyFile)
				} else {
					fmt.Println("Master key creation skipped.")
				}
			}

			// Step 2: Create admin password
			passwordFile := filepath.Join(filepath.Dir(keyFile), "admin_password.json")
			adminStore, err := guard.NewAdminPasswordStore(passwordFile)
			if err != nil {
				return fmt.Errorf("failed to create admin password store: %w", err)
			}

			isPasswordSet := adminStore.IsPasswordSet()

			if isPasswordSet {
				// If password is already set, ask user if they want to overwrite it
				fmt.Printf("\nYou have already configured an admin password.\n")
				fmt.Print("Would you like to set/overwrite the password? (Y/N): ")
				scanner.Scan()
				response := strings.ToLower(strings.TrimSpace(scanner.Text()))
				if response == "y" || response == "yes" {
					// Get password with confirmation (hidden input)
					password, err := getPasswordWithConfirmation(scanner)
					if err != nil {
						return err
					}

					// Set the admin password
					if err := adminStore.SetPassword(password); err != nil {
						return fmt.Errorf("failed to set admin password: %w", err)
					}

					fmt.Println("\nAdmin password has been set successfully.")
				} else {
					fmt.Println("Admin password setting skipped.")
				}
			} else {
				// If no password is set, require user to set one
				fmt.Printf("\nAdmin password is required but not yet configured.\n")

				// Get password with confirmation (hidden input)
				password, err := getPasswordWithConfirmation(scanner)
				if err != nil {
					return err
				}

				// Set the admin password
				if err := adminStore.SetPassword(password); err != nil {
					return fmt.Errorf("failed to set admin password: %w", err)
				}

				fmt.Println("\nAdmin password has been set successfully.")
			}

			// End: Completion message
			fmt.Println("\nInitialization completed!")
			fmt.Println("You can now run the program using: enclave run &")

			return nil
		},
	}

	// Add flags to init command
	initCmd.Flags().StringVarP(&keyFile, "key-file", "k", "/usr/local/etc/credagent/master.key", "Path to the file to create containing the 32-byte AES-256 master key")
	initCmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/engine/config.json", "Path to the configuration file (JSON format)")

	// Add the main run command
	runCmd := &cobra.Command{
		Use:           "run",
		Short:         "Run the CredAgent enclave daemon",
		Long:          `Starts the CredAgent enclave daemon for managing credential protection.`,
		SilenceUsage:  true, // Don't print usage when error occurs
		SilenceErrors: true, // Don't print errors to stderr (we'll handle logging ourselves)
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load configuration from file (required)
			cfg, err := config.LoadConfig(configFile)
			if err != nil {
				logger.Error("Failed to load config file: %s — %v", configFile, err)
				return fmt.Errorf("failed to load config: %w", err)
			}

			if cfg.Enclave == nil {
				return fmt.Errorf("config file missing required section: \"enclave\"")
			}
			if cfg.CredAgent == nil {
				return fmt.Errorf("config file missing required section: \"credagent\"")
			}

			// Override command line values with config values only if they weren't explicitly set via command line
			if !cmd.Flags().Changed("key-file") && cfg.Enclave.MasterKeyFile != "" {
				keyFile = cfg.Enclave.MasterKeyFile
			}

			if !cmd.Flags().Changed("socket-dir") && cfg.Enclave.SocketDir != "" {
				socketDir = cfg.Enclave.SocketDir
			}

			if !cmd.Flags().Changed("baseline-file") && cfg.Enclave.BaselineFile != "" {
				baselineFile = cfg.Enclave.BaselineFile
			}

			if !cmd.Flags().Changed("mount") && cfg.Monitor != nil && cfg.Monitor.MountPoint != "" {
				mountPoint = cfg.Monitor.MountPoint
			}

			// Ensure all required directories exist before proceeding
			// This includes socket directory, key file directory, and baseline file directory
			if err := ensureRequiredDirectories(socketDir, keyFile, baselineFile); err != nil {
				return fmt.Errorf("failed to ensure required directories: %w", err)
			}

			// Override log level from config if it wasn't explicitly set via command line
			if !cmd.Flags().Changed("log-level") && cfg.LogLevel != "" {
				logLevel = cfg.LogLevel
			}

			// Set log level based on the logLevel variable
			switch logLevel {
			case "debug":
				logger.SetLevel(logger.DEBUG)
			case "info":
				logger.SetLevel(logger.INFO)
			case "warning":
				logger.SetLevel(logger.WARNING)
			case "error":
				logger.SetLevel(logger.ERROR)
			default:
				logger.SetLevel(logger.INFO) // Default to info
			}

			// Harden process: disable core dumps and mark process as non-dumpable
			// to prevent master key from leaking via crash dumps or /proc/<pid>/mem.
			if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
				logger.Warn("Failed to disable core dumps: %v", err)
			}
			if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
				logger.Warn("Failed to set PR_SET_DUMPABLE=0: %v", err)
			}

			// Log initialization information
			logger.Info("Starting CredAgent Enclave Daemon version %s", version.Version)
			logger.Info("Socket directory: %s", socketDir)
			logger.Info("Master key file: %s", keyFile)
			logger.Info("Baseline file: %s", baselineFile)
			logger.Info("Log level: %s", logLevel)
			logger.Info("CredAgent provider: %s", cfg.CredAgent.Provider)
			logger.Info("CredAgent API URL: %s", cfg.CredAgent.APIURL)
			logger.Info("CredAgent model: %s", cfg.CredAgent.ModelName)

			// Check if master key file exists
			if keyFile == "" {
				return fmt.Errorf("master key file path is not set. Please check your configuration file and ensure 'master_key_file' is properly specified")
			}
			if _, err := os.Stat(keyFile); os.IsNotExist(err) {
				if !autoInit {
					errMsg := fmt.Sprintf("master key file does not exist: %s. Please run 'credagent init' to initialize the enclave", keyFile)
					logger.Error("%s", errMsg)
					// For this unrecoverable error, we'll still return an error but log it appropriately
					// The service manager (systemd) will handle restart policy based on exit codes
					return fmt.Errorf("%s", errMsg) // Return error without usage
				}
				// Cloud-image/unattended bootstrap: generate a fresh master key,
				// backing up any pre-existing baseline (unrecoverable under the new key).
				if err := autoInitMasterKey(keyFile, baselineFile); err != nil {
					return fmt.Errorf("auto-init master key: %w", err)
				}
			}

			// Read master key from file
			masterKeyBytes, err := os.ReadFile(keyFile)
			if err != nil {
				return fmt.Errorf("failed to read master key file: %w", err)
			}

			// Handle different key formats - support both raw 32-byte keys and base64-encoded keys
			var masterKey []byte
			if len(masterKeyBytes) == 32 {
				// Raw 32-byte key
				masterKey = masterKeyBytes
			} else {
				// Try to decode as base64 (common format for encoded keys)
				// Remove any trailing newline/whitespace first
				keyStr := strings.TrimSpace(string(masterKeyBytes))

				decodedKey, err := base64.StdEncoding.DecodeString(keyStr)
				if err != nil {
					// If base64 decoding fails, try with the original bytes but trim whitespace
					trimmedKey := keyStr
					if len(trimmedKey) == 32 {
						masterKey = []byte(trimmedKey)
					} else {
						return fmt.Errorf("master key must be exactly 32 bytes for AES-256, got %d bytes (tried raw, base64-decoded, and trimmed formats)", len(masterKeyBytes))
					}
				} else {
					if len(decodedKey) != 32 {
						return fmt.Errorf("decoded master key must be exactly 32 bytes for AES-256, got %d bytes", len(decodedKey))
					}
					masterKey = decodedKey
				}
			}
			crypto.ZeroBytes(masterKeyBytes)
			if err := syscall.Mlock(masterKey); err != nil {
				logger.Warn("Failed to mlock master key: %v (key may be swapped to disk)", err)
			}
			logger.Info("Loaded master key.")

			// Initialize core components
			ledgerStore := ledger.NewInMemoryLedger()

			// Use persistent baseline store if baseline file is specified
			baselineStore, err := baseline.NewBaselineStoreFromPath(baselineFile, masterKey)
			if err != nil {
				return fmt.Errorf("failed to initialize baseline store: %w", err)
			}

			// Log baseline store information
			if baselineStore != nil {
				numBaselines := baselineStore.Count()
				logger.Info("Baseline store initialized with file: %s, loaded %d entries", baselineFile, numBaselines)
			} else {
				logger.Info("In-memory baseline store initialized")
			}

			// Initialize CredAgent client with configuration from file
			agentConfig := &agent.Config{
				Provider:   cfg.CredAgent.Provider,
				APIURL:     cfg.CredAgent.APIURL,
				APIKey:     cfg.CredAgent.APIKey,
				APIType:    cfg.CredAgent.APIType,
				ModelName:  cfg.CredAgent.ModelName,
				TimeoutSec: cfg.CredAgent.TimeoutSec,
			}
			credAgentClient := agent.NewCredAgentClient(agentConfig)

			// Initialize admin password store
			passwordFile := filepath.Join(filepath.Dir(keyFile), "admin_password.json")

			if _, err := os.Stat(passwordFile); os.IsNotExist(err) {
				logger.Warn("Admin password file does not exist: %s. Some administrative functions may be limited.", passwordFile)
			}

			adminStore, err := guard.NewAdminPasswordStore(passwordFile)
			if err != nil {
				return fmt.Errorf("failed to create admin password store: %w", err)
			}

			// Cloud-image/unattended bootstrap: if no admin password is configured,
			// generate an unrecoverable random one so the daemon starts with admin
			// auth enforced. The operator must reset it via 'credagent init'.
			if autoInit && !adminStore.IsPasswordSet() {
				pw, err := generateRandomPassword(8)
				if err != nil {
					return fmt.Errorf("generate admin password: %w", err)
				}
				if err := adminStore.SetPassword(pw); err != nil {
					return fmt.Errorf("set auto-generated admin password: %w", err)
				}
				logger.Warn("Admin password was missing; generated a random 8-char password (unrecoverable). Reset it via 'credagent init'.")
			}

			cmdlineSources := cfg.CmdlineTrustedSource
			var riskCheckConfig *osutil.RiskCheckConfig
			if cfg.AntiattackOptions != nil {
				riskCheckConfig = buildRiskCheckConfig(cfg.AntiattackOptions)
			}

			switch cfg.SecuritySource {
			case config.SecurityFromConfig:
				logger.Info("Security policy loaded from config.json: %s", cfg.AntiattackOptions.SecuritySummary())
			case config.SecurityFromFile:
				logger.Info("Security policy loaded from security.json: %s", cfg.AntiattackOptions.SecuritySummary())
			case config.SecurityDefault:
				logger.Warn("No security.json found and no antiattack_options in config.json: %s",
					(*config.AntiattackOptions)(nil).SecuritySummary())
			}
			cmdlineMgr := cmdline.NewManager(cmdlineSources)
			osutil.SetCmdlineProvider(cmdlineMgr)
			osutil.SetSystemPATH(os.Getenv("PATH"))
			osutil.SetProcessProvider(cache.NewProcessProvider())

			policyEngine := guard.NewPolicyEngine(ledgerStore, baselineStore, credAgentClient, masterKey, adminStore, riskCheckConfig)

			// Initialize fd_share_check (defaults to disabled)
			fdShareCheckEnabled := false
			if cfg.AntiattackOptions != nil && cfg.AntiattackOptions.FdShareCheck != nil {
				fdShareCheckEnabled = cfg.AntiattackOptions.FdShareCheck.Enabled
			}
			cache.InitFdShareCheck(fdShareCheckEnabled)

			// Initialize process state cleanup
			processCleanupTimeout := 30 * time.Second
			if cfg.AntiattackOptions != nil && cfg.AntiattackOptions.ProcessCleanupTimeoutSec > 0 {
				processCleanupTimeout = time.Duration(cfg.AntiattackOptions.ProcessCleanupTimeoutSec) * time.Second
			}
			stopProcessCleanup := cache.StartCleanup(processCleanupTimeout)

			// --- FUSE filesystem (merged from credmon) ---
			if mountPoint == "" {
				mountPoint = "/mnt/credagent/shielded"
			}
			if err := os.MkdirAll(mountPoint, 0755); err != nil {
				return fmt.Errorf("failed to create mount point directory: %w", err)
			}

			if isMountPoint(mountPoint) {
				if runtime.GOOS == "darwin" {
					return fmt.Errorf("mount point %s is already mounted (stale FUSE mount from a previous crash?). "+
						"Please run: umount %s", mountPoint, mountPoint)
				}
				return fmt.Errorf("mount point %s is already mounted (stale FUSE mount from a previous crash?). "+
					"Please run: fusermount -uz %s", mountPoint, mountPoint)
			}

			root := fusehook.NewShieldedNode(policyEngine, baselineStore)
			nfs := gofusefs.NewNodeFS(root, &gofusefs.Options{})
			fuseServer, err := gofuse.NewServer(nfs, mountPoint, &gofuse.MountOptions{
				FsName:     "CredShield",
				Debug:      false,
				AllowOther: true,
				Options:    []string{"default_permissions"},
			})
			if err != nil {
				return fmt.Errorf("failed to create FUSE server: %w", err)
			}
			logger.Info("FUSE filesystem mounted at: %s", mountPoint)

			// Start FUSE server in background
			fuseDone := make(chan struct{})
			go func() {
				fuseServer.Serve()
				close(fuseDone)
			}()

			// --- enclave.sock gRPC server (control plane for credctl/credreq) ---
			var socketDirPath string
			if socketDir != "" {
				socketDirPath = socketDir
			} else if cfg.Enclave.SocketDir != "" {
				socketDirPath = cfg.Enclave.SocketDir
			} else {
				socketDirPath = "/run/credagent"
			}

			enclaveSocketFile := filepath.Join(socketDirPath, "enclave.sock")

			enclaveListener, err := net.Listen("unix", enclaveSocketFile)
			if err != nil {
				if isAddrInUseError(err) {
					if isSocketInUse(enclaveSocketFile) {
						return fmt.Errorf("another instance of credagent appears to be running - socket file is in use: %s", enclaveSocketFile)
					}
					logger.Info("Removing stale socket file: %s", enclaveSocketFile)
					if rmErr := os.Remove(enclaveSocketFile); rmErr != nil {
						return fmt.Errorf("failed to remove stale socket file %s: %w", enclaveSocketFile, rmErr)
					}
					enclaveListener, err = net.Listen("unix", enclaveSocketFile)
					if err != nil {
						return fmt.Errorf("failed to create enclave UDS listener: %w", err)
					}
				} else {
					return fmt.Errorf("failed to create enclave UDS listener: %w", err)
				}
			}

			if err := os.Chmod(enclaveSocketFile, 0666); err != nil {
				return fmt.Errorf("failed to set enclave socket permissions: %w", err)
			}

			tlsCert, err := uds.GenerateSelfSignedCert()
			if err != nil {
				return fmt.Errorf("failed to generate TLS certificate: %w", err)
			}
			enclaveCreds := credentials.NewServerTLSFromCert(&tlsCert)
			enclaveGrpcServer := grpc.NewServer(
				grpc.Creds(enclaveCreds),
				grpc.UnaryInterceptor(uds.UDSPeerAuthInterceptor),
			)

			enclave.RegisterEnclaveGuardServiceServer(enclaveGrpcServer, policyEngine)

			// --- Signal handling: unified shutdown for FUSE + gRPC ---
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

			go func() {
				sig := <-sigChan
				logger.Info("Received signal: %v, shutting down gracefully...", sig)

				shutdownDone := make(chan struct{})
				go func() {
					logger.Info("Stopping process state cleanup goroutine...")
					stopProcessCleanup()

					logger.Info("Closing cmdline data sources (eBPF/auditd)...")
					cmdlineMgr.Close()
					logger.Info("Cmdline data sources closed")

					activeHandles := cache.GlobalActiveHandleCount()
					logger.Info("FUSE: preparing to unmount, %d active file handle(s) waiting for kernel release", activeHandles)

					unmountDone := make(chan error, 1)
					go func() { unmountDone <- fuseServer.Unmount() }()

					select {
					case err := <-unmountDone:
						if err != nil {
							logger.Warn("FUSE: unmount failed: %v", err)
						} else {
							logger.Info("FUSE: unmount completed, filesystem detached")
						}
					case <-time.After(3 * time.Second):
						logger.Warn("FUSE: regular unmount blocked (likely CWD or pending kernel refs), falling back to lazy unmount")
						forceUnmountFuse(mountPoint)
					}

					logger.Info("gRPC: stopping EnclaveService, waiting for in-flight requests to finish...")
					enclaveGrpcServer.GracefulStop()
					logger.Info("gRPC: EnclaveService stopped")

					if err := os.Remove(enclaveSocketFile); err != nil && !os.IsNotExist(err) {
						logger.Warn("Failed to remove socket file: %v", err)
					} else {
						logger.Info("Removed socket file: %s", enclaveSocketFile)
					}

					close(shutdownDone)
				}()

				select {
				case <-shutdownDone:
					logger.Info("Graceful shutdown completed, exiting")
				case <-time.After(10 * time.Second):
					logger.Warn("Graceful shutdown timed out after 10s (likely blocked on FUSE unmount or gRPC drain), forcing exit")
					enclaveGrpcServer.Stop()
				}

				os.Exit(0)
			}()

			// Start gRPC server
			logger.Info("Starting EnclaveService on UDS: %s", enclaveSocketFile)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := enclaveGrpcServer.Serve(enclaveListener); err != nil {
					logger.Error("Failed to serve enclave service: %v", err)
				}
			}()

			logger.Info("CredAgent is ready and serving requests")

			wg.Wait()
			return nil
		},
	}

	// Add flags to run command (inheriting from root command)
	runCmd.Flags().StringVarP(&keyFile, "key-file", "k", "", "Path to the file containing the 32-byte AES-256 master key")
	runCmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	runCmd.Flags().StringVarP(&baselineFile, "baseline-file", "b", "", "Path to the encrypted baseline store file")
	runCmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/engine/config.json", "Path to the configuration file (JSON format)")
	runCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warning, error)")
	runCmd.Flags().StringVar(&mountPoint, "mount", "/mnt/credagent/shielded", "FUSE mount point for credential protection")
	runCmd.Flags().BoolVar(&useBufNet, "use-bufnet", false, "Use bufnet for testing (internal flag)")
	runCmd.Flags().BoolVar(&autoInit, "auto-init", false, "Auto-initialize master key and admin password on first start if missing (cloud-image/unattended use)")

	rootCmd.Flags().StringVarP(&keyFile, "key-file", "k", "", "Path to the file containing the 32-byte AES-256 master key")
	rootCmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	rootCmd.Flags().StringVarP(&baselineFile, "baseline-file", "b", "", "Path to the encrypted baseline store file")
	rootCmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/engine/config.json", "Path to the configuration file (JSON format)")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Log level (debug, info, warning, error)")
	rootCmd.Flags().BoolVar(&useBufNet, "use-bufnet", false, "Use bufnet for testing (internal flag)")

	// Add commands to root command
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(versionCmd)

	// The cobra library automatically handles printing flags with PrintDefaults()
	// when we don't override the help function. We'll ensure flags are properly registered.

	// If no subcommand is provided, default to run
	if len(os.Args) == 1 {
		// No arguments provided, show help
		rootCmd.Help()
		os.Exit(0)
	} else if len(os.Args) == 2 && (os.Args[1] == "start" || os.Args[1] == "run") {
		// Execute run command directly
		runCmd.SetArgs(os.Args[2:])
		if err := runCmd.Execute(); err != nil {
			logger.Error("Error: %v", err)
			os.Exit(1)
		}
	} else {
		// Execute the root command normally (handles subcommands like init)
		if err := rootCmd.Execute(); err != nil {
			logger.Error("Error: %v", err)
			os.Exit(1)
		}
	}
}

// buildRiskCheckConfig converts parsed config.AntiattackOptions into an osutil.RiskCheckConfig.
func buildRiskCheckConfig(opts *config.AntiattackOptions) *osutil.RiskCheckConfig {
	cfg := osutil.DefaultRiskCheckConfig()

	if opts.ProcessStatusCheck != nil {
		cfg.ProcessStatusCheck.Enabled = opts.ProcessStatusCheck.Enabled
	}

	if opts.LibraryInjectionCheck != nil {
		cfg.LibraryInjectionCheck.Enabled = opts.LibraryInjectionCheck.Enabled
		cfg.LibraryInjectionCheck.TrustedLibPaths = opts.LibraryInjectionCheck.TrustedLibPaths
	}

	if opts.EnvVarCheck != nil {
		cfg.EnvVarCheck.Enabled = opts.EnvVarCheck.Enabled
		cfg.EnvVarCheck.TrustedEnv = opts.EnvVarCheck.TrustedEnv
	}

	if opts.BinaryCheck != nil {
		cfg.BinaryCheck.Enabled = opts.BinaryCheck.Enabled
		cfg.BinaryCheck.TrustedPrograms = opts.BinaryCheck.TrustedPrograms
	}

	if opts.AncestorCheck != nil {
		cfg.AncestorCheck.Enabled = opts.AncestorCheck.Enabled
		if opts.AncestorCheck.MaxDepth > 0 {
			cfg.MaxAncestorDepth = opts.AncestorCheck.MaxDepth
		}
	}

	if opts.InterpreterCheck != nil {
		interpMap := make(map[string]osutil.InterpreterCheckOpts)
		addInterpreterOpts(interpMap, "python", opts.InterpreterCheck.Python)
		addInterpreterOpts(interpMap, "node", opts.InterpreterCheck.Node)
		addInterpreterOpts(interpMap, "perl", opts.InterpreterCheck.Perl)
		addInterpreterOpts(interpMap, "ruby", opts.InterpreterCheck.Ruby)
		addInterpreterOpts(interpMap, "java", opts.InterpreterCheck.Java)

		addInterpreterOpts(interpMap, "php", opts.InterpreterCheck.PHP)
		cfg.InterpreterCheck = interpMap

		trustedPaths := make(map[string][]string)
		for family, opts := range interpMap {
			if len(opts.ExePaths) > 0 {
				trustedPaths[family] = append(trustedPaths[family], opts.ExePaths...)
			}
		}
		interpreter.SetConfig(&interpreter.Config{TrustedPaths: trustedPaths})
	}

	if len(opts.TrustedHarness) > 0 {
		cfg.TrustedHarness = opts.TrustedHarness
	}

	return cfg
}

func addInterpreterOpts(m map[string]osutil.InterpreterCheckOpts, family string, item *config.InterpreterCheckItemConfig) {
	if item == nil {
		return
	}
	m[family] = osutil.InterpreterCheckOpts{
		Enabled:        item.Enabled,
		TrustedEnv:     item.TrustedEnv,
		TrustedScripts: item.TrustedScripts,
		ExePaths:       item.ExePaths,
	}
}

// passwordCharset is the alphabet for auto-generated admin passwords: digits,
// upper/lower letters, and a fixed symbol set.
const passwordCharset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@#$%^&*-_=+"

// generateRandomPassword returns an n-character password drawn uniformly (via
// rejection sampling to avoid modulo bias) from passwordCharset using crypto/rand.
func generateRandomPassword(n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("password length must be positive, got %d", n)
	}
	// Largest multiple of len(charset) that fits in a byte, for bias-free sampling.
	max := 255 - (256 % len(passwordCharset))
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		for {
			b := make([]byte, 1)
			if _, err := rand.Read(b); err != nil {
				return "", fmt.Errorf("failed to read random bytes: %w", err)
			}
			// Reject values that would introduce modulo bias.
			if int(b[0]) > max {
				continue
			}
			buf[i] = passwordCharset[int(b[0])%len(passwordCharset)]
			break
		}
	}
	return string(buf), nil
}

// autoInitMasterKey bootstraps a missing master key: if baselineFile exists it
// is renamed aside (a new key cannot decrypt a baseline encrypted under a prior
// key), then a fresh 32-byte AES-256 key is generated and written (base64, 0600)
// to keyFile. The key-file directory must already exist (ensureRequiredDirectories).
func autoInitMasterKey(keyFile, baselineFile string) error {
	// Back up any existing baseline: it is useless under a new key, and leaving
	// it in place would make NewBaselineStoreFromPath try to decrypt it and fail.
	if baselineFile != "" {
		if _, err := os.Stat(baselineFile); err == nil {
			backup, err := uniqueBackupPath(baselineFile)
			if err != nil {
				return fmt.Errorf("failed to compute backup path for baseline: %w", err)
			}
			if err := os.Rename(baselineFile, backup); err != nil {
				return fmt.Errorf("failed to back up existing baseline %s: %w", baselineFile, err)
			}
			logger.Warn("Backed up existing baseline to %s (new master key cannot decrypt it)", backup)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat baseline file %s: %w", baselineFile, err)
		}
	}

	keyDir := filepath.Dir(keyFile)
	if err := os.MkdirAll(keyDir, 0750); err != nil {
		return fmt.Errorf("failed to create key file directory: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate random master key: %w", err)
	}
	encodedKey := base64.StdEncoding.EncodeToString(key)
	crypto.ZeroBytes(key)
	if err := os.WriteFile(keyFile, []byte(encodedKey), 0600); err != nil {
		return fmt.Errorf("failed to write master key file %s: %w", keyFile, err)
	}
	logger.Info("Auto-initialized master key at %s", keyFile)
	return nil
}

// uniqueBackupPath returns path + ".bak.<timestamp>", appending a numeric
// suffix until a non-existent path is found.
func uniqueBackupPath(path string) (string, error) {
	base := path + ".bak." + time.Now().Format("20060102-150405")
	candidate := base
	for i := 1; ; i++ {
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate, nil
		} else if err != nil {
			return "", err
		}
		candidate = fmt.Sprintf("%s.%d", base, i)
	}
}

func isMountPoint(path string) bool {
	var pathStat, parentStat unix.Stat_t
	if err := unix.Stat(path, &pathStat); err != nil {
		return false
	}
	if err := unix.Stat(filepath.Dir(path), &parentStat); err != nil {
		return false
	}
	return pathStat.Dev != parentStat.Dev
}

func forceUnmountFuse(path string) {
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("umount", path).CombinedOutput(); err != nil {
			logger.Warn("FUSE: umount fallback failed: %v, output: %s", err, string(out))
		} else {
			logger.Info("FUSE: umount completed")
		}
	} else {
		if out, err := exec.Command("fusermount", "-uz", path).CombinedOutput(); err != nil {
			logger.Warn("FUSE: lazy unmount failed: %v, output: %s", err, string(out))
		} else {
			logger.Info("FUSE: lazy unmount completed, filesystem will detach when all refs are released")
		}
	}
}
