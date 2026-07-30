package main

import (
	"fmt"

	"github.com/alibaba/CredAgent/pkg/version"
	"github.com/spf13/cobra"
)

// createVersionCmd creates the version command
func createVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of credctl",
		Long:  `Print the version number of CredAgent credctl CLI tool.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("credctl version %s\n", version.Version)
		},
	}

	return cmd
}
