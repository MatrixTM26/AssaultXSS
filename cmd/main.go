package main

import (
	"fmt"
	"os"
	"time"

	"assaultxss/internal/config"
	"assaultxss/internal/engine"
	"assaultxss/internal/logger"
	"assaultxss/internal/reporter"
)

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31;1m"
	ansiCyan   = "\033[36;1m"
	ansiYellow = "\033[33m"
	ansiGray   = "\033[90m"
)

func main() {
	if len(os.Args) == 1 {
		config.PrintHelp()
		os.Exit(0)
	}

	cfg, err := config.ParseFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n%s[ERR]%s %v\n\n", ansiRed, ansiReset, err)
		config.PrintHelp()
		os.Exit(1)
	}

	PrintBanner()

	log := logger.NewLogger(cfg.Verbose)
	log.Info(fmt.Sprintf("AssaultXSS v1.2.0 — %d target(s) loaded", len(cfg.URLs)))
	if len(cfg.ExternalPayloads) > 0 {
		log.Info(fmt.Sprintf("external payloads: %d loaded", len(cfg.ExternalPayloads)))
	}
	log.Info("authorized bug bounty mode — ensure written scope permission")
	fmt.Println()

	sc := engine.NewScanner(cfg, log)
	start := time.Now()
	results := sc.Run()
	elapsed := time.Since(start)

	stats := sc.GetStats()
	breakdown := sc.GetSeverityBreakdown()
	log.PrintSummary(stats.PayloadsSent, stats.VulnsFound, stats.URLsScanned, elapsed, breakdown)

	if cfg.ExportFile != "" {
		if len(results) > 0 {
			reporter.ExportResults(results, cfg.ExportFile, log)
		} else {
			log.Info("no vulnerabilities found — export skipped")
		}
	}

	if len(results) > 0 {
		os.Exit(2)
	}
	os.Exit(0)
}

func PrintBanner() {
	fmt.Printf("%s", ansiRed)
	fmt.Println(` █████╗ ███████╗███████╗ █████╗ ██╗   ██╗██╗  ████████╗██╗  ██╗███████╗███████╗`)
	fmt.Println(`██╔══██╗██╔════╝██╔════╝██╔══██╗██║   ██║██║  ╚══██╔══╝╚██╗██╔╝██╔════╝██╔════╝`)
	fmt.Println(`███████║███████╗███████╗███████║██║   ██║██║     ██║    ╚███╔╝ ███████╗███████╗`)
	fmt.Println(`██╔══██║╚════██║╚════██║██╔══██║██║   ██║██║     ██║    ██╔██╗ ╚════██║╚════██║`)
	fmt.Println(`██║  ██║███████║███████║██║  ██║╚██████╔╝███████╗██║   ██╔╝ ██╗███████║███████║`)
	fmt.Println(`╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝`)
	fmt.Printf("%s", ansiReset)
	fmt.Printf("%s                 Advanced XSS Vulnerability Scanner v1.2.0%s\n", ansiCyan, ansiReset)
}
