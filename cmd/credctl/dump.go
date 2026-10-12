package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aliyun/credagent/api/gen/enclave"
	"github.com/aliyun/credagent/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var dumpWriteFile string

func createDumpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dump [flags] <id>",
		Short: "Dump the content of a protected credential to stdout or a file",
		Long:  `Retrieves the plaintext content of a protected credential without modifying the baseline. Requires password authentication.`,
		Args:  cobra.ExactArgs(1),
		RunE:  runDump,
	}

	cmd.Flags().StringVarP(&dumpWriteFile, "write", "w", "", "Write content to the specified file instead of stdout")
	cmd.Flags().StringVarP(&socketDir, "socket-dir", "d", "/run/credagent", "Directory for Unix Domain Socket files")
	cmd.Flags().StringVarP(&configFile, "config", "c", "/usr/local/etc/credagent/credctl/config.json", "Path to the configuration file (JSON format)")

	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <id>\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\n%s\n", cmd.Long)
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		cmd.Flags().VisitAll(func(flag *pflag.Flag) {
			fmt.Fprintf(os.Stderr, "  -%s, --%s %s\n", flag.Shorthand, flag.Name, flag.Usage)
			if flag.DefValue != "" {
				fmt.Fprintf(os.Stderr, "        (default \"%s\")\n", flag.DefValue)
			}
		})
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s abc123\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s -w /tmp/config.json abc123\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "  %s abc123 > /tmp/config.json\n", cmd.CommandPath())
		fmt.Fprintf(os.Stderr, "\nNote: The 'id' is the SHA identifier shown in the 'list' command output.\n")
	})

	return cmd
}

func runDump(cmd *cobra.Command, args []string) error {
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

	return dumpCredentialContent(args[0])
}

func dumpCredentialContent(id string) error {
	password, err := getPasswordFromPrompt("Enter password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	conn, err := createEnclaveClient()
	if err != nil {
		return err
	}
	defer conn.Close()

	client := enclave.NewEnclaveGuardServiceClient(conn)

	resp, err := client.DumpFileContent(context.Background(), &enclave.DumpFileContentRequest{
		Sha:      id,
		Password: string(password),
	})
	if err != nil {
		return fmt.Errorf("failed to dump credential: %w", err)
	}

	if !resp.GetSuccess() {
		return fmt.Errorf("failed to dump credential: %s", resp.GetMessage())
	}

	if dumpWriteFile != "" {
		if err := os.WriteFile(dumpWriteFile, resp.GetContent(), 0600); err != nil {
			return fmt.Errorf("failed to write to %s: %w", dumpWriteFile, err)
		}
		fmt.Fprintf(os.Stderr, "Content written to %s (%d bytes)\n", dumpWriteFile, len(resp.GetContent()))
	} else {
		os.Stdout.Write(resp.GetContent())
	}

	return nil
}
