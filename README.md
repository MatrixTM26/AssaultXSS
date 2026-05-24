# AssaultXSS

```txt
_______                            __________
___    |___________________ ____  ____  /_  /_
__  /| |_  ___/_  ___/  __ '/  / / /_  /_  __/
_  ___ |(__  )_(__  )/ /_/ // /_/ /_  / / /_
/_/  |_/____/ /____/ \__,_/ \__,_/ /_/  \__/ XSS
```

High speed & lightweight Cross Site Scripting (XSS) vulnerabilities scanner toolkit writen in Go.

![License](https://img.shields.io/badge/AGPL-v3-000000?style=for-the-badge&logo=gnu&logoColor=A42E2B&labelColor=000000&color=brightgreen)
![Golang](https://img.shields.io/badge/Golang-1.21+-000000?style=for-the-badge&logo=go&logoColor=00bef9)

### Installation & Usage

```bash
git clone https://github.com/MatrixTM26/AssaultXSS.git
cd AssaultXSS
go mod tidy
go build -o assaultxss ./cmd/main.go
```

### Options

```txt
./assaultxss [option]
```

| Flag         | Description                                |
| ------------ | ------------------------------------------ |
| `-u <url>`   | Target URL to scan                         |
| `-L <file>`  | File containing list of URLs               |
| `-d <int>`   | Crawl depth (default: 2)                   |
| `-t <int>`   | Timeout in seconds (default: 10)           |
| `-T <int>`   | Concurrent threads (default: 5)            |
| `-p <param>` | Test specific parameter only               |
| `-l <1-5>`   | Payload level (1=Basic → 5=Full)           |
| `-V`         | Enable verbose output                      |
| `-e <file>`  | Export results (.json or .txt)             |
| `-W <file>`  | Load xss payload from wordlist file (.txt) |
| `-h`         | Show help                                  |

### Payload Levels

| Level | Name     | Description                                                             |
| ----- | -------- | ----------------------------------------------------------------------- |
| 1     | Basic    | alert/confirm/prompt, script tags, img onerror                          |
| 2     | Medium   | Case mix, event handlers, tag breaks, attribute injection               |
| 3     | Advanced | CharCode, base64 eval, unicode/hex escapes, URL encoded, filter evasion |
| 4     | Expert   | DOM-based, polyglots, WAF bypass, constructor chains, iframe srcdoc     |
| 5     | Full     | All above + blind XSS probes, dynamic import, Symbol/Proxy traps        |

### Examples

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

### Output

- **[VLN]** - Vulnerability confirmed with full details
- **[INF]** - Informational log (URL, params, progress)
- **[WRN]** - Warnings (redirects, unusual responses)
- **[ERR]** - Request or parsing errors
- **[DBG]** - Debug output (enabled with `-V`)

#### Export Formats

- `.json` — Machine-readable with full metadata per finding
- `.txt` — Human-readable report with evidence snippets

### Log Output Example

```txt
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

## Credits

#### AUTHOR

[![AUTHOR](https://img.shields.io/badge/MatrixTM26-000000?style=for-the-badge&logo=github&logoColor=ffffff)](https://github.com/MatrixTM26)

#### License

![License](https://img.shields.io/badge/AGPL-v3-000000?style=for-the-badge&logo=gnu&logoColor=A42E2B&labelColor=000000&color=brightgreen)

#### Support Me

[![Ko-fi](https://img.shields.io/badge/KO--FI-000000?style=for-the-badge&logo=kofi&logoColor=ff0000)](https://ko-fi.com/MatrixTM26)
[![Trakteer](https://img.shields.io/badge/TRAKTEER-000000?style=for-the-badge&logo=buymeacoffee&logoColor=ff0000)](https://trakteer.id/MatrixTM26)
[![PayPal](https://img.shields.io/badge/PAYPAL-000000?style=for-the-badge&logo=paypal&logoColor=ff0000)](https://paypal.me/TeukuMaulana)

---

<p align="center"><b>&copy; 2023-2026 MatrixTM26</b></p>
