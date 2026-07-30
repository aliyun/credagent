package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "credctl",
		Short: "CredAgent credctl CLI tool",
		Long:  `CredAgent credctl CLI tool for onboarding and releasing credentials to/from the enclave.`,
	}

	// Initialize default socket dir
	socketDir = "/run/credagent"

	// Create subcommands
	protectCmd := createProtectCmd()
	releaseCmd := createReleaseCmd()
	listCmd := createListCmd()
	inspectCmd := createInspectCmd()
	removeCmd := createRemoveCmd()
	updateCmd := createUpdateCmd()
	attachCmd := createAttachCmd()
	detachCmd := createDetachCmd()
	refreshCmd := createRefreshCmd()
	dumpCmd := createDumpCmd()
	restoreCmd := createRestoreCmd()
	versionCmd := createVersionCmd()

	rootCmd.AddCommand(protectCmd, releaseCmd, listCmd, inspectCmd, removeCmd, updateCmd, attachCmd, detachCmd, refreshCmd, dumpCmd, restoreCmd, versionCmd)

	// Set custom help text for the root command
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(os.Stderr, "Usage: %s [command] [flags]\n", cmd.Use)
		fmt.Fprintf(os.Stderr, "\nAvailable Commands:\n")
		for _, c := range cmd.Commands() {
			fmt.Fprintf(os.Stderr, "  %s\n", c.Use)
			fmt.Fprintf(os.Stderr, "    %s\n\n", c.Short)
		}
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		cmd.Flags().PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nUse \"%s [command] --help\" for more information about a command.\n", cmd.Use)
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
