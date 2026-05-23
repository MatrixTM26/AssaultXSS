# AssaultXSS v1.0.0

**Advanced XSS Vulnerability Scanner — Authorized Bug Bounty Use Only**

> Built for HackerOne & Bugcrowd authorized security researchers.  
> Lightweight Go binary — runs perfectly on Android (Termux).

---

## Installation

### Prerequisites

- Go 1.21+ installed (`pkg install golang` on Termux)

### Build

```bash
git clone https://github.com/MatrixTM26/AssaultXSS.git
cd AssaultXSS
go mod tidy
go build -o assaultxss ./cmd/main.go
```

### Build for Android (ARM64)

```bash
GOOS=linux GOARCH=arm64 go build -o assaultxss-arm64 ./cmd/main.go
```

---

## Usage

```
assaultxss [OPTIONS]
```

| Flag         | Description                      |
| ------------ | -------------------------------- |
| `-u <url>`   | Target URL to scan               |
| `-L <file>`  | File containing list of URLs     |
| `-d <int>`   | Crawl depth (default: 2)         |
| `-t <int>`   | Timeout in seconds (default: 10) |
| `-T <int>`   | Concurrent threads (default: 5)  |
| `-p <param>` | Test specific parameter only     |
| `-l <1-5>`   | Payload level (1=Basic → 5=Full) |
| `-V`         | Enable verbose output            |
| `-e <file>`  | Export results (.json or .txt)   |
| `-h`         | Show help                        |

---

## Payload Levels

| Level | Name     | Description                                                             |
| ----- | -------- | ----------------------------------------------------------------------- |
| 1     | Basic    | alert/confirm/prompt, script tags, img onerror                          |
| 2     | Medium   | Case mix, event handlers, tag breaks, attribute injection               |
| 3     | Advanced | CharCode, base64 eval, unicode/hex escapes, URL encoded, filter evasion |
| 4     | Expert   | DOM-based, polyglots, WAF bypass, constructor chains, iframe srcdoc     |
| 5     | Full     | All above + blind XSS probes, dynamic import, Symbol/Proxy traps        |

---

## Examples

```bash
# Basic scan with verbose output
./assaultxss -u "https://target.com/search?q=test" -l 2 -V

# Advanced scan with export
./assaultxss -u "https://target.com/search?q=test" -l 4 -V -e results.json

# Bulk scan from file, 10 threads, full payloads
./assaultxss -L urls.txt -T 10 -l 5 -e report.txt

# Test specific parameter only
./assaultxss -u "https://target.com/page?q=x&cat=y" -p "q" -l 3 -V

# Deep crawl with timeout
./assaultxss -u "https://target.com" -d 3 -t 15 -T 8 -l 3 -V -e results.json
```

---

## Output

- **[VLN]** - Vulnerability confirmed with full details
- **[INF]** - Informational log (URL, params, progress)
- **[WRN]** - Warnings (redirects, unusual responses)
- **[ERR]** - Request or parsing errors
- **[DBG]** - Debug output (enabled with `-V`)

### Export Formats

- `.json` — Machine-readable with full metadata per finding
- `.txt` — Human-readable report with evidence snippets

---

## Log Output Example

```
[15:04:05.123] [INF] Scan initiated → https://target.com/search?q=test
[15:04:05.124] [INF] Loaded 87 payloads for level 3 (Advanced)
[15:04:05.312] [DBG] Parameter discovered: [q] at https://target.com/search
[15:04:05.800] [VLN] XSS CONFIRMED → https://target.com/search?q=test
              Parameter : q
              Type      : Reflected
              Level     : 3 (Advanced)
              Payload   : <img src=x onerror=eval(atob('YWxlcnQoMSk='))>
              PoC URL   : https://target.com/search?q=%3Cimg+src%3Dx...
              Evidence  : ...<div class="result"><img src=x onerror=eval(atob(...
```

---

## Project Structure

```
AssaultXSS/
├── cmd/
│   └── main.go              # Entry point
├── internal/
│   ├── config/config.go     # CLI flag parsing
│   ├── engine/engine.go     # Core scan engine
│   ├── crawler/crawler.go   # Link & form crawler
│   ├── payload/payload.go   # XSS payload database
│   ├── logger/logger.go     # Colored log output
│   └── reporter/reporter.go # JSON/TXT export
├── go.mod
├── Makefile
└── README.md
```

---

## Disclaimer

This tool is intended **ONLY** for authorized security testing on targets you own or have **written permission** to test. Unauthorized use is illegal and unethical. The author is not responsible for any misuse. Always verify scope in your bug bounty program before testing.
