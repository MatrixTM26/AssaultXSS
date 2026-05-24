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
		color.New(color.FgRed, color.Bold).Printf("\n[ERR] %v\n\n", err)
		config.PrintHelp()
		os.Exit(1)
	}

	PrintBanner()

	log := logger.NewLogger(cfg.Verbose)
	log.Info(fmt.Sprintf("AssaultXSS v1.1.0 — %d target(s) loaded", len(cfg.URLs)))

	if len(cfg.ExternalPayloads) > 0 {
		log.Info(fmt.Sprintf("External payloads: %d loaded from file", len(cfg.ExternalPayloads)))
	}

	log.Info("Authorized bug bounty mode — ensure written scope permission")
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
			log.Info("No vulnerabilities found — export skipped")
		}
	}

	if len(results) > 0 {
		os.Exit(2)
	}
	os.Exit(0)
}

func PrintBanner() {
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	red.Println(`
        _______                            __________  
        ___    |___________________ ____  ____  /_  /_ 
        __  /| |_  ___/_  ___/  __ '/  / / /_  /_  __/ 
        _  ___ |(__  )_(__  )/ /_/ // /_/ /_  / / /_   
        /_/  |_/____/ /____/ \__,_/ \__,_/ /_/  \__/ XSS
        ------------------------------------------------
	`)
	cyan.Println("        [+] Author: MatrixTM26")
	cyan.Println("        [+] Version: 1.0")
	red.Println("        ------------------------------------------------")
	fmt.Println()
}
