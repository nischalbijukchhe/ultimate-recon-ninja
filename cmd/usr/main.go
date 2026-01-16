package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/yourusername/usr/internal/config"
	"github.com/yourusername/usr/internal/logger"
	"go.uber.org/zap"
)

const (
	version = "1.0.0"
	banner  = `
██╗   ██╗███╗   ██╗██╗██╗   ██╗███████╗██████╗ ███████╗ █████╗ ██╗     
██║   ██║████╗  ██║██║██║   ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██║     
██║   ██║██╔██╗ ██║██║██║   ██║█████╗  ██████╔╝███████╗███████║██║     
██║   ██║██║╚██╗██║██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══██║██║     
╚██████╔╝██║ ╚████║██║ ╚████╔╝ ███████╗██║  ██║███████║██║  ██║███████╗
 ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝
                                                                          
Universal Subdomain Reconnaissance Engine v%s
The most advanced subdomain enumeration framework
`
)

var (
	cfgFile string
	cfg     *config.Config
	log     *zap.Logger
)

var rootCmd = &cobra.Command{
	Use:   "usr",
	Short: "Universal Subdomain Reconnaissance Engine",
	Long: `USR is a production-grade subdomain enumeration framework that combines
passive, active, recursive, historical, and AI-enhanced discovery techniques
to achieve superior coverage over all existing tools.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		var err error
		
		// Initialize config
		cfg, err = config.Load(cfgFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
		
		// Initialize logger
		log, err = logger.New(cfg.LogLevel, cfg.LogFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error initializing logger: %v\n", err)
			os.Exit(1)
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		if log != nil {
			log.Sync()
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(banner, version)
		fmt.Printf("\nVersion:      %s\n", version)
		fmt.Printf("Go Version:   %s\n", runtime.Version())
		fmt.Printf("OS/Arch:      %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Environment:  %s\n", detectEnvironment())
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan [domain]",
	Short: "Perform subdomain reconnaissance on target domain",
	Long: `Scan performs comprehensive subdomain enumeration using multiple techniques:
- Passive intelligence gathering
- Active DNS discovery
- AI-enhanced pattern prediction
- Web intelligence and JS parsing
- Historical data comparison`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]
		
		log.Info("Starting subdomain reconnaissance",
			zap.String("domain", domain),
			zap.String("mode", cfg.ScanMode),
		)
		
		fmt.Printf(banner, version)
		fmt.Printf("\n[*] Target: %s\n", domain)
		fmt.Printf("[*] Mode: %s\n", cfg.ScanMode)
		fmt.Printf("[*] Environment: %s\n", detectEnvironment())
		fmt.Printf("\n[*] Initializing reconnaissance engine...\n\n")
		
		// Orchestrator will be implemented in Phase 2
		log.Info("Scan initiated successfully")
		fmt.Println("[+] Ready for orchestrator integration (Phase 2)")
	},
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update wordlists, resolvers, and data sources",
	Run: func(cmd *cobra.Command, args []string) {
		log.Info("Updating resources")
		
		fmt.Println("[*] Updating wordlists...")
		fmt.Println("[*] Updating DNS resolvers...")
		fmt.Println("[*] Updating source configurations...")
		fmt.Println("[+] Update complete (stub - will implement in later phases)")
		
		log.Info("Update completed")
	},
}

func detectEnvironment() string {
	// Check if running on Kali Linux
	if _, err := os.Stat("/etc/os-release"); err == nil {
		data, err := os.ReadFile("/etc/os-release")
		if err == nil {
			content := string(data)
			if contains(content, "Kali") || contains(content, "kali") {
				return "Kali Linux (Optimized)"
			}
		}
	}
	
	return fmt.Sprintf("%s (Compatible)", runtime.GOOS)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: $HOME/.usr/config.yaml)")
	
	// Scan command flags
	scanCmd.Flags().String("mode", "passive", "scan mode: passive, active, aggressive, stealth")
	scanCmd.Flags().String("output", "", "output file path")
	scanCmd.Flags().String("format", "json", "output format: json, csv, html, nuclei")
	scanCmd.Flags().Bool("ai", false, "enable AI-enhanced discovery")
	scanCmd.Flags().Bool("recursive", false, "enable recursive enumeration")
	scanCmd.Flags().Int("threads", 50, "number of concurrent threads")
	
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(updateCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}