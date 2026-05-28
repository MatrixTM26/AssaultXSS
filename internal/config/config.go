package config

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	ToolName    = "AssaultXSS"
	ToolVersion = "1.2.0"
)

type Config struct {
	TargetURL        string
	URLFile          string
	Depth            int
	Timeout          int
	Threads          int
	Param            string
	Level            int
	Verbose          bool
	ExportFile       string
	ExternalPayloads []string
	URLs             []string
}

func ParseFlags() (*Config, error) {
	cfg := &Config{}

	var payloadFile string

	flag.StringVar(&cfg.TargetURL, "u", "", "Target URL to scan (e.g. https://target.com/page?q=test)")
	flag.StringVar(&cfg.URLFile, "L", "", "File containing list of URLs to scan")
	flag.IntVar(&cfg.Depth, "d", 2, "Crawl depth for link discovery (default: 2)")
	flag.IntVar(&cfg.Timeout, "t", 10, "HTTP request timeout in seconds (default: 10)")
	flag.IntVar(&cfg.Threads, "T", 5, "Number of concurrent threads (default: 5)")
	flag.StringVar(&cfg.Param, "p", "", "Specific parameter to test (optional, tests all if empty)")
	flag.IntVar(&cfg.Level, "l", 1, "Payload level: 1=Basic, 2=Medium, 3=Advanced, 4=Expert, 5=Full (default: 1)")
	flag.BoolVar(&cfg.Verbose, "V", false, "Enable verbose logging output")
	flag.StringVar(&cfg.ExportFile, "e", "", "Export results to file (e.g. results.json or results.txt)")
	flag.StringVar(&payloadFile, "W", "", "Load additional payloads from external file (one per line)")

	flag.Usage = PrintHelp
	flag.Parse()

	if cfg.TargetURL == "" && cfg.URLFile == "" {
		return nil, fmt.Errorf("no target specified — use -u <url> or -L <file>")
	}
	if cfg.Level < 1 || cfg.Level > 5 {
		return nil, fmt.Errorf("level must be between 1 and 5")
	}
	if cfg.Threads < 1 || cfg.Threads > 100 {
		return nil, fmt.Errorf("threads must be between 1 and 100")
	}

	if cfg.URLFile != "" {
		urls, err := ReadLines(cfg.URLFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read URL file: %v", err)
		}
		cfg.URLs = urls
	}
	if cfg.TargetURL != "" {
		cfg.URLs = append(cfg.URLs, cfg.TargetURL)
	}

	if payloadFile != "" {
		payloads, err := ReadLines(payloadFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read payload file: %v", err)
		}
		cfg.ExternalPayloads = payloads
		fmt.Printf("  [+] External payloads loaded: %d from %s\n", len(payloads), payloadFile)
	}

	return cfg, nil
}

func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func PrintHelp() {
	fmt.Print(`
 █████╗ ███████╗███████╗ █████╗ ██╗   ██╗██╗  ████████╗██╗  ██╗███████╗███████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗██║   ██║██║  ╚══██╔══╝╚██╗██╔╝██╔════╝██╔════╝
███████║███████╗███████╗███████║██║   ██║██║     ██║    ╚███╔╝ ███████╗███████╗
██╔══██║╚════██║╚════██║██╔══██║██║   ██║██║     ██║    ██╔██╗ ╚════██║╚════██║
██║  ██║███████║███████║██║  ██║╚██████╔╝███████╗██║   ██╔╝ ██╗███████║███████║
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝

  AssaultXSS v1.2.0 — Advanced XSS Vulnerability Scanner
  For authorized bug bounty use only (HackerOne / Bugcrowd)

USAGE:
  assaultxss [OPTIONS]

TARGET:
  -u  <url>     Single target URL
  -L  <file>    File with list of URLs (one per line)

SCAN OPTIONS:
  -d  <int>     Crawl depth for link/param discovery (default: 2)
  -t  <int>     Request timeout in seconds (default: 10)
  -T  <int>     Concurrent threads (default: 5)
  -p  <param>   Test only this specific parameter
  -l  <1-5>     Payload level (default: 1)

PAYLOAD:
  -W  <file>    Load extra payloads from external .txt file (one per line)

OUTPUT:
  -V            Verbose mode (show all reflection debug info)
  -e  <file>    Export results to file (.json or .txt)
  -h            Show this help

PAYLOAD LEVELS:
  Level 1  Basic     Common script/img/svg injections
  Level 2  Medium    Event handlers, tag breaks, attribute injection
  Level 3  Advanced  Encoding tricks, filter evasion, charcode
  Level 4  Expert    DOM-based, polyglots, WAF bypass, constructors
  Level 5  Full      All payloads + blind XSS probes

SEVERITY LEVELS:
  CRITICAL  Executable in script-block or event-handler context (score >= 80)
  HIGH      Executable payload reflected in active context (score >= 60)
  MEDIUM    Reflected with potential execution path (score >= 35)
  LOW       Reflected but likely non-executable context (score >= 15)

EXAMPLES:
  assaultxss -u "https://target.com/search?q=test" -l 2 -V
  assaultxss -u "https://target.com/page?q=x" -l 4 -T 8 -e results.json
  assaultxss -L urls.txt -T 10 -l 3 -e report.txt
  assaultxss -u "https://target.com" -p "q" -l 3 -V
  assaultxss -u "https://target.com" -W mypayloads.txt -l 3 -V
  assaultxss -u "https://target.com" -W /sdcard/payloads.txt -l 5 -e out.json

PAYLOAD FILE FORMAT (-W):
  # one payload per line, lines starting with # are ignored
  <script>alert(1)</script>
  <img src=x onerror=alert(1)>
  "><svg onload=alert(1)>

DISCLAIMER:
  Use ONLY on targets you own or have written permission to test.
  Unauthorized use is illegal. Always verify program scope first.

`)
}
