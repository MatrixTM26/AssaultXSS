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
	ToolVersion = "1.0.0"
	ToolAuthor  = "Bug Bounty Security Research Tool"
	ToolBanner  = `
 █████╗ ███████╗███████╗ █████╗ ██╗   ██╗██╗  ████████╗██╗  ██╗███████╗███████╗
██╔══██╗██╔════╝██╔════╝██╔══██╗██║   ██║██║  ╚══██╔══╝╚██╗██╔╝██╔════╝██╔════╝
███████║███████╗███████╗███████║██║   ██║██║     ██║    ╚███╔╝ ███████╗███████╗
██╔══██║╚════██║╚════██║██╔══██║██║   ██║██║     ██║    ██╔██╗ ╚════██║╚════██║
██║  ██║███████║███████║██║  ██║╚██████╔╝███████╗██║   ██╔╝ ██╗███████║███████║
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝
`
)

type Config struct {
	TargetURL  string
	URLFile    string
	Depth      int
	Timeout    int
	Threads    int
	Param      string
	Level      int
	Verbose    bool
	ExportFile string
	URLs       []string
}

func ParseFlags() (*Config, error) {
	cfg := &Config{}

	flag.StringVar(&cfg.TargetURL, "u", "", "Target URL to scan (e.g. https://target.com/page?q=test)")
	flag.StringVar(&cfg.URLFile, "L", "", "File containing list of URLs to scan")
	flag.IntVar(&cfg.Depth, "d", 2, "Crawl depth for link discovery (default: 2)")
	flag.IntVar(&cfg.Timeout, "t", 10, "HTTP request timeout in seconds (default: 10)")
	flag.IntVar(&cfg.Threads, "T", 5, "Number of concurrent threads (default: 5)")
	flag.StringVar(&cfg.Param, "p", "", "Specific parameter to test (optional, tests all if empty)")
	flag.IntVar(&cfg.Level, "l", 1, "Payload level: 1=Basic, 2=Medium, 3=Advanced, 4=Expert, 5=Full (default: 1)")
	flag.BoolVar(&cfg.Verbose, "V", false, "Enable verbose logging output")
	flag.StringVar(&cfg.ExportFile, "e", "", "Export results to file (e.g. results.json or results.txt)")

	flag.Usage = PrintHelp
	flag.Parse()

	if cfg.TargetURL == "" && cfg.URLFile == "" {
		return nil, fmt.Errorf("no target specified, use -u <url> or -L <file>")
	}

	if cfg.Level < 1 || cfg.Level > 5 {
		return nil, fmt.Errorf("level must be between 1 and 5")
	}

	if cfg.Threads < 1 || cfg.Threads > 100 {
		return nil, fmt.Errorf("threads must be between 1 and 100")
	}

	if cfg.URLFile != "" {
		urls, err := ReadURLFile(cfg.URLFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read URL file: %v", err)
		}
		cfg.URLs = urls
	}

	if cfg.TargetURL != "" {
		cfg.URLs = append(cfg.URLs, cfg.TargetURL)
	}

	return cfg, nil
}

func ReadURLFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return urls, scanner.Err()
}

func PrintHelp() {
	fmt.Printf("%s\n", ToolBanner)
	fmt.Printf("  %s v%s - Advanced XSS Vulnerability Scanner\n", ToolName, ToolVersion)
	fmt.Printf("  For authorized bug bounty use only (HackerOne / Bugcrowd)\n\n")
	fmt.Printf("USAGE:\n")
	fmt.Printf("  assaultxss [OPTIONS]\n\n")
	fmt.Printf("OPTIONS:\n")
	fmt.Printf("  -u  <url>     Target URL to scan\n")
	fmt.Printf("  -L  <file>    File containing list of URLs\n")
	fmt.Printf("  -d  <int>     Crawl depth for link discovery (default: 2)\n")
	fmt.Printf("  -t  <int>     Request timeout in seconds (default: 10)\n")
	fmt.Printf("  -T  <int>     Concurrent threads (default: 5)\n")
	fmt.Printf("  -p  <param>   Specific parameter to test\n")
	fmt.Printf("  -l  <1-5>     Payload level (1=Basic ... 5=Full)\n")
	fmt.Printf("  -V            Enable verbose output\n")
	fmt.Printf("  -e  <file>    Export results to file (.json or .txt)\n")
	fmt.Printf("  -h            Show this help message\n\n")
	fmt.Printf("PAYLOAD LEVELS:\n")
	fmt.Printf("  Level 1  Basic     - Common alert/confirm/prompt injections\n")
	fmt.Printf("  Level 2  Medium    - Tag breaking, event handlers\n")
	fmt.Printf("  Level 3  Advanced  - Filter evasion, encoding tricks\n")
	fmt.Printf("  Level 4  Expert    - DOM-based, polyglots, WAF bypass\n")
	fmt.Printf("  Level 5  Full      - All payloads including blind & stored XSS probes\n\n")
	fmt.Printf("EXAMPLES:\n")
	fmt.Printf("  assaultxss -u \"https://target.com/search?q=test\" -l 3 -V\n")
	fmt.Printf("  assaultxss -L urls.txt -T 10 -l 4 -e results.json\n")
	fmt.Printf("  assaultxss -u \"https://target.com/page\" -p \"q\" -l 5 -V -e out.txt\n\n")
	fmt.Printf("DISCLAIMER:\n")
	fmt.Printf("  This tool is intended ONLY for authorized security testing.\n")
	fmt.Printf("  Use only on targets you own or have written permission to test.\n")
	fmt.Printf("  Unauthorized use is illegal and unethical.\n\n")
}
