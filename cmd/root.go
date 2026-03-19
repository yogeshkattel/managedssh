package cmd

import (
	"fmt"

	"github.com/managedssh/managedssh/internal/tui"
	"github.com/managedssh/managedssh/internal/vault"
	"github.com/spf13/cobra"
)

var Version = "1.0.0"

var profile string

var rootCmd = &cobra.Command{
	Use:   "managedssh",
	Short: "A beautiful SSH connection manager",
	Long:  "ManagedSSH — manage, organize, and connect to your SSH hosts from a slick terminal UI.",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if profile != "" {
			if err := vault.ValidateProfileName(profile); err != nil {
				return err
			}
			vault.SetProfile(profile)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.Start()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ManagedSSH v%s\n", Version)
	},
}

var profilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "List available profiles",
	RunE: func(cmd *cobra.Command, args []string) error {
		profiles, err := vault.ListProfiles()
		if err != nil {
			return err
		}
		if len(profiles) == 0 {
			fmt.Println("No profiles found. Run managedssh to create one.")
			return nil
		}
		fmt.Println("Available profiles:")
		for _, p := range profiles {
			fmt.Printf("  - %s\n", p)
		}
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&profile, "profile", "p", "", "profile to use (default: auto-detect)")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(profilesCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
