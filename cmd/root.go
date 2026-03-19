package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/managedssh/managedssh/internal/analytics"
	"github.com/managedssh/managedssh/internal/audit"
	"github.com/managedssh/managedssh/internal/compliance"
	"github.com/managedssh/managedssh/internal/health"
	"github.com/managedssh/managedssh/internal/host"
	"github.com/managedssh/managedssh/internal/keymgr"
	"github.com/managedssh/managedssh/internal/rbac"
	"github.com/managedssh/managedssh/internal/session"
	"github.com/managedssh/managedssh/internal/tui"
	"github.com/managedssh/managedssh/internal/vault"
	"github.com/spf13/cobra"
)

var Version = "2.0.0"

var profile string

func currentRBAC() (*rbac.Config, error) {
	dir, err := vault.Dir()
	if err != nil {
		return nil, err
	}
	return rbac.Load(dir)
}

func requirePermission(perm rbac.Permission) error {
	cfg, err := currentRBAC()
	if err != nil {
		return err
	}
	return cfg.Check(perm)
}

var rootCmd = &cobra.Command{
	Use:   "managedssh",
	Short: "Enterprise SSH connection manager",
	Long:  "ManagedSSH — enterprise-grade SSH host management with RBAC, audit logging, session recording, and health monitoring.",
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

// ------------------------------------------------------------------
// version
// ------------------------------------------------------------------

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ManagedSSH v%s\n", Version)
	},
}

// ------------------------------------------------------------------
// profiles
// ------------------------------------------------------------------

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

// ------------------------------------------------------------------
// role — RBAC management
// ------------------------------------------------------------------

var roleCmd = &cobra.Command{
	Use:   "role",
	Short: "Manage RBAC role for the current profile",
}

var roleGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show current role",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := vault.Dir()
		if err != nil {
			return err
		}
		cfg, err := rbac.Load(dir)
		if err != nil {
			return err
		}
		fmt.Printf("Current role: %s\n", rbac.RoleLabel(cfg.Role))
		return nil
	},
}

var roleSetCmd = &cobra.Command{
	Use:   "set [admin|operator|viewer]",
	Short: "Set the RBAC role for this profile",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requirePermission(rbac.PermManageRoles); err != nil {
			return err
		}
		roleName := strings.ToLower(args[0])
		if !rbac.IsValidRole(roleName) {
			return fmt.Errorf("invalid role %q — must be one of: admin, operator, viewer", args[0])
		}
		dir, err := vault.Dir()
		if err != nil {
			return err
		}
		cfg, err := rbac.Load(dir)
		if err != nil {
			return err
		}
		if err := cfg.SetRole(rbac.Role(roleName)); err != nil {
			return err
		}
		fmt.Printf("Role set to: %s\n", rbac.RoleLabel(rbac.Role(roleName)))
		return nil
	},
}

// ------------------------------------------------------------------
// health — host health checking
// ------------------------------------------------------------------

var healthCmd = &cobra.Command{
	Use:   "health",
	Short: "Check connectivity of all hosts",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requirePermission(rbac.PermHealthCheck); err != nil {
			return err
		}
		dir, err := vault.Dir()
		if err != nil {
			return err
		}
		store, err := host.NewStore(dir)
		if err != nil {
			return err
		}
		if len(store.Hosts) == 0 {
			fmt.Println("No hosts configured.")
			return nil
		}

		hosts := make([]health.Host, len(store.Hosts))
		for i, h := range store.Hosts {
			hosts[i] = health.Host{ID: h.ID, Hostname: h.Hostname, Port: h.Port}
		}

		fmt.Printf("Checking %d hosts...\n\n", len(hosts))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		results := health.CheckAll(ctx, hosts, 5*time.Second, 10)

		alive, dead := 0, 0
		for _, r := range results {
			alias := ""
			for _, h := range store.Hosts {
				if h.ID == r.HostID {
					alias = h.Alias
					break
				}
			}
			status := "✓ UP"
			latency := r.Latency.Round(time.Millisecond).String()
			if !r.Alive {
				status = "✗ DOWN"
				latency = r.Error
				dead++
			} else {
				alive++
			}
			fmt.Printf("  %-6s %-20s %-30s %s\n", status, alias, r.Hostname, latency)
		}
		fmt.Printf("\n%d reachable, %d unreachable out of %d hosts\n", alive, dead, len(results))
		return nil
	},
}

// ------------------------------------------------------------------
// audit — compliance and analytics
// ------------------------------------------------------------------

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log operations",
}

var auditExportCmd = &cobra.Command{
	Use:   "export [--format json|csv] [--output file]",
	Short: "Export audit log for compliance reporting",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requirePermission(rbac.PermExport); err != nil {
			return err
		}
		dir, err := vault.Dir()
		if err != nil {
			return err
		}
		log, err := audit.NewLog(dir)
		if err != nil {
			return err
		}
		events, err := log.Recent(0)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			fmt.Println("No audit events found.")
			return nil
		}

		prof := vault.ActiveProfile()
		if prof == "" {
			prof = "default"
		}
		report := compliance.GenerateReport(events, prof)

		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")

		var w *os.File
		if output != "" {
			w, err = os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			defer w.Close()
		} else {
			w = os.Stdout
		}

		switch format {
		case "csv":
			if err := compliance.WriteCSV(w, report); err != nil {
				return err
			}
		default:
			if err := compliance.WriteJSON(w, report); err != nil {
				return err
			}
		}

		if output != "" {
			fmt.Fprintf(os.Stderr, "Exported %d events to %s\n", len(events), output)
		}
		return nil
	},
}

var auditStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show connection analytics summary",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requirePermission(rbac.PermViewAnalytics); err != nil {
			return err
		}
		dir, err := vault.Dir()
		if err != nil {
			return err
		}
		log, err := audit.NewLog(dir)
		if err != nil {
			return err
		}
		events, err := log.Recent(0)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			fmt.Println("No audit events found.")
			return nil
		}

		stats := analytics.Compute(events)

		fmt.Println("=== Connection Analytics ===")
		fmt.Printf("Total connections:  %d\n", stats.TotalConnections)
		fmt.Printf("Success rate:       %.1f%%\n", stats.SuccessRate)
		fmt.Printf("Successful:         %d\n", stats.SuccessCount)
		fmt.Printf("Failed:             %d\n", stats.FailureCount)
		fmt.Printf("Unique hosts:       %d\n", stats.UniqueHosts)
		fmt.Printf("Unique users:       %d\n", stats.UniqueUsers)

		if len(stats.MostConnected) > 0 {
			fmt.Println("\n--- Most Connected Hosts ---")
			for _, hs := range stats.MostConnected {
				fmt.Printf("  %-20s %-25s %d connections (%d ok, %d fail)\n",
					hs.Alias, hs.Hostname, hs.Connections, hs.Successes, hs.Failures)
			}
		}

		if len(stats.RecentFailures) > 0 {
			fmt.Println("\n--- Recent Failures ---")
			for _, ev := range stats.RecentFailures {
				fmt.Printf("  %s  %-20s %s@%s  %s\n",
					ev.Timestamp.Format("2006-01-02 15:04"),
					ev.HostAlias, ev.User, ev.Hostname, ev.Error)
			}
		}
		return nil
	},
}

// ------------------------------------------------------------------
// keys — SSH key management
// ------------------------------------------------------------------

var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "SSH key management",
}

var keysListCmd = &cobra.Command{
	Use:   "list",
	Short: "List SSH key pairs in ~/.ssh/",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requirePermission(rbac.PermManageKeys); err != nil {
			return err
		}
		keys, err := keymgr.ListKeys()
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			fmt.Println("No SSH key pairs found in ~/.ssh/")
			return nil
		}
		fmt.Println("SSH key pairs:")
		for _, k := range keys {
			pub, err := keymgr.ReadPublicKey(k)
			if err != nil {
				fmt.Printf("  - %s (could not read public key)\n", k)
				continue
			}
			// Truncate the public key for display.
			pubStr := strings.TrimSpace(string(pub))
			if len(pubStr) > 72 {
				pubStr = pubStr[:72] + "..."
			}
			fmt.Printf("  - %s\n    %s\n", k, pubStr)
		}
		return nil
	},
}

var keysGenCmd = &cobra.Command{
	Use:   "generate [name]",
	Short: "Generate a new Ed25519 SSH key pair",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requirePermission(rbac.PermManageKeys); err != nil {
			return err
		}
		comment, _ := cmd.Flags().GetString("comment")
		kp, err := keymgr.GenerateEd25519(args[0], comment)
		if err != nil {
			return err
		}
		fmt.Printf("Generated Ed25519 key pair:\n")
		fmt.Printf("  Private: ~/.ssh/%s\n", kp.Name)
		fmt.Printf("  Public:  ~/.ssh/%s.pub\n", kp.Name)
		fmt.Printf("\nPublic key:\n%s\n", string(kp.PublicKey))
		return nil
	},
}

// ------------------------------------------------------------------
// sessions — session recording management
// ------------------------------------------------------------------

var sessionsCmd = &cobra.Command{
	Use:   "sessions",
	Short: "List recorded SSH sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := requirePermission(rbac.PermViewSessions); err != nil {
			return err
		}
		dir, err := vault.Dir()
		if err != nil {
			return err
		}
		sessDir := filepath.Join(dir, "sessions")
		recordings, err := session.ListRecordings(sessDir)
		if err != nil {
			return err
		}
		if len(recordings) == 0 {
			fmt.Println("No session recordings found.")
			return nil
		}
		fmt.Printf("Session recordings (%d):\n\n", len(recordings))
		for _, r := range recordings {
			sizeKB := float64(r.Size) / 1024
			fmt.Printf("  %-45s  %6.1f KB  %s\n",
				r.Name, sizeKB, r.ModTime.Format("2006-01-02 15:04:05"))
		}
		return nil
	},
}

// ------------------------------------------------------------------
// init
// ------------------------------------------------------------------

func init() {
	rootCmd.PersistentFlags().StringVarP(&profile, "profile", "p", "", "profile to use (default: auto-detect)")

	// Role subcommands.
	roleCmd.AddCommand(roleGetCmd)
	roleCmd.AddCommand(roleSetCmd)

	// Audit subcommands.
	auditExportCmd.Flags().String("format", "json", "output format: json or csv")
	auditExportCmd.Flags().StringP("output", "o", "", "output file path (default: stdout)")
	auditCmd.AddCommand(auditExportCmd)
	auditCmd.AddCommand(auditStatsCmd)

	// Keys subcommands.
	keysGenCmd.Flags().String("comment", "", "comment for the SSH key")
	keysCmd.AddCommand(keysListCmd)
	keysCmd.AddCommand(keysGenCmd)

	// Register all top-level commands.
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(profilesCmd)
	rootCmd.AddCommand(roleCmd)
	rootCmd.AddCommand(healthCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(keysCmd)
	rootCmd.AddCommand(sessionsCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
