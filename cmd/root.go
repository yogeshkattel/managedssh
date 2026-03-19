package cmd

import (
	"github.com/managedssh/managedssh/internal/tui"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "managedssh",
	Short: "A beautiful SSH connection manager",
	Long:  "ManagedSSH — manage, organize, and connect to your SSH hosts from a slick terminal UI.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.Start()
	},
}

func Execute() error {
	return rootCmd.Execute()
}
