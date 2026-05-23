package main

import (
	"fmt"
	"os"
	"time"

	"assaultxss/internal/config"
	"assaultxss/internal/engine"
	"assaultxss/internal/logger"
	"assaultxss/internal/reporter"

	"github.com/fatih/color"
)

func main() {
	if len(os.Args) == 1 {
		config.PrintHelp()
		os.Exit(0)
	}

	cfg, err := config.ParseFlags()
	if err != nil {
		colorRed := color.New(color.FgRed, color.Bold)
		colorRed.Printf("\n[ERR] %v\n\n", err)
		config.PrintHelp()
		os.Exit(1)
	}

	PrintBanner()

	log := logger.NewLogger(cfg.Verbose)

	log.Info(fmt.Sprintf("AssaultXSS v1.0.0 initialized — %d target(s) loaded", len(cfg.URLs)))
	log.Info("Authorized bug bounty mode — ensure you have written scope permission")
	fmt.Println()

	sc := engine.NewScanner(cfg, log)
	start := time.Now()
	results := sc.Run()
	elapsed := time.Since(start)

	stats := sc.GetStats()
	log.PrintSummary(stats.PayloadsSent, stats.VulnsFound, stats.URLsScanned, elapsed)

	if cfg.ExportFile != "" && len(results) > 0 {
		reporter.ExportResults(results, cfg.ExportFile, log)
	} else if cfg.ExportFile != "" && len(results) == 0 {
		log.Info("No vulnerabilities found — export skipped")
	}

	if len(results) > 0 {
		os.Exit(2)
	}
	os.Exit(0)
}

func PrintBanner() {
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed, color.Bold)
	gray := color.New(color.FgHiBlack)

	red.Println(`
 █████╗ ███████╗███████╗ █████╗ ██╗   ██╗██╗  ████████╗██╗  ██╗███████╗███████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗██║   ██║██║  ╚══██╔══╝╚██╗██╔╝██╔════╝██╔════╝
███████║███████╗███████╗███████║██║   ██║██║     ██║    ╚███╔╝ ███████╗███████╗
██╔══██║╚════██║╚════██║██╔══██║██║   ██║██║     ██║    ██╔██╗ ╚════██║╚════██║
██║  ██║███████║███████║██║  ██║╚██████╔╝███████╗██║   ██╔╝ ██╗███████║███████║
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝`)
	cyan.Println("                    Advanced XSS Vulnerability Scanner v1.0.0")
	yellow.Println("                    For Authorized Bug Bounty Use Only")
	gray.Println("                    HackerOne / Bugcrowd  |  Ensure Written Scope Permission")
	fmt.Println()
}
