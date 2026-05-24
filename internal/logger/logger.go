package logger

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelSuccess
	LevelWarning
	LevelError
	LevelCritical
)

type SeverityLevel int

const (
	SeverityInfo     SeverityLevel = 0
	SeverityLow      SeverityLevel = 1
	SeverityMedium   SeverityLevel = 2
	SeverityHigh     SeverityLevel = 3
	SeverityCritical SeverityLevel = 4
)

type Logger struct {
	Verbose bool
	mu      sync.Mutex
	entries []LogEntry
}

type LogEntry struct {
	Timestamp string
	Level     string
	Message   string
	Extra     map[string]string
}

var (
	colorRed      = color.New(color.FgRed, color.Bold)
	colorGreen    = color.New(color.FgGreen, color.Bold)
	colorYellow   = color.New(color.FgYellow, color.Bold)
	colorCyan     = color.New(color.FgCyan, color.Bold)
	colorMagenta  = color.New(color.FgMagenta, color.Bold)
	colorWhite    = color.New(color.FgWhite)
	colorBlue     = color.New(color.FgBlue, color.Bold)
	colorGray     = color.New(color.FgHiBlack)
	colorOrange   = color.New(color.FgYellow)
	colorHiRed    = color.New(color.FgHiRed, color.Bold)
	colorHiGreen  = color.New(color.FgHiGreen, color.Bold)
	colorHiWhite  = color.New(color.FgHiWhite, color.Bold)
)

func NewLogger(verbose bool) *Logger {
	return &Logger{Verbose: verbose}
}

func (l *Logger) timestamp() string {
	return time.Now().Format("15:04:05.000")
}

func (l *Logger) Debug(msg string) {
	if !l.Verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.timestamp()
	colorGray.Printf("[%s] ", ts)
	colorBlue.Print("[DBG] ")
	colorGray.Printf("%s\n", msg)
	l.entries = append(l.entries, LogEntry{Timestamp: ts, Level: "DEBUG", Message: msg})
}

func (l *Logger) Info(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.timestamp()
	colorGray.Printf("[%s] ", ts)
	colorCyan.Print("[INF] ")
	colorWhite.Printf("%s\n", msg)
	l.entries = append(l.entries, LogEntry{Timestamp: ts, Level: "INFO", Message: msg})
}

func (l *Logger) Success(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.timestamp()
	colorGray.Printf("[%s] ", ts)
	colorGreen.Print("[VLN] ")
	colorGreen.Printf("%s\n", msg)
	l.entries = append(l.entries, LogEntry{Timestamp: ts, Level: "VULN", Message: msg})
}

func (l *Logger) Warning(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.timestamp()
	colorGray.Printf("[%s] ", ts)
	colorYellow.Print("[WRN] ")
	colorYellow.Printf("%s\n", msg)
	l.entries = append(l.entries, LogEntry{Timestamp: ts, Level: "WARN", Message: msg})
}

func (l *Logger) Error(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.timestamp()
	colorGray.Printf("[%s] ", ts)
	colorRed.Print("[ERR] ")
	colorRed.Printf("%s\n", msg)
	l.entries = append(l.entries, LogEntry{Timestamp: ts, Level: "ERROR", Message: msg})
}

func (l *Logger) Critical(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.timestamp()
	colorGray.Printf("[%s] ", ts)
	colorMagenta.Print("[CRT] ")
	colorMagenta.Printf("%s\n", msg)
	l.entries = append(l.entries, LogEntry{Timestamp: ts, Level: "CRITICAL", Message: msg})
}

func (l *Logger) ScanStart(targetURL string, level int, threads int) {
	l.Info(fmt.Sprintf("Scan initiated → %s", targetURL))
	l.Info(fmt.Sprintf("Payload level: %d | Threads: %d", level, threads))
}

func (l *Logger) ParamFound(param string, sourceURL string) {
	if !l.Verbose {
		return
	}
	l.Debug(fmt.Sprintf("Parameter discovered: [%s] at %s", param, sourceURL))
}

func (l *Logger) PayloadSent(targetURL string, param string, payloadStr string) {
	if !l.Verbose {
		return
	}
	truncated := payloadStr
	if len(truncated) > 60 {
		truncated = truncated[:60] + "..."
	}
	l.Debug(fmt.Sprintf("Testing [%s] | Payload: %s", param, truncated))
}

func (l *Logger) ReflectOnly(param string, targetURL string) {
	if !l.Verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.timestamp()
	colorGray.Printf("[%s] ", ts)
	colorBlue.Print("[RFL] ")
	colorBlue.Printf("Reflected (no exec context): [%s] %s\n", param, targetURL)
}

func (l *Logger) VulnFound(result VulnResult) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.timestamp()

	sev := result.Severity
	sevLabel, sevColor, borderColor := SeverityStyle(sev)

	fmt.Println()
	borderColor.Println(strings.Repeat("═", 82))
	colorGray.Printf("[%s] ", ts)
	sevColor.Printf(" %s  ", sevLabel)
	colorHiWhite.Printf("XSS %s", SeverityTitle(sev))
	if sev >= SeverityHigh {
		colorHiRed.Printf(" ← EXPLOITABLE")
	} else if sev == SeverityMedium {
		colorYellow.Printf(" ← POTENTIAL")
	} else {
		colorBlue.Printf(" ← REFLECT ONLY")
	}
	fmt.Println()
	borderColor.Println(strings.Repeat("─", 82))

	printField := func(label string, value string) {
		colorGray.Printf("  %-14s", label+":")
		colorWhite.Printf(" %s\n", value)
	}
	printFieldColor := func(label string, value string, c *color.Color) {
		colorGray.Printf("  %-14s", label+":")
		c.Printf(" %s\n", value)
	}

	printField("URL", result.URL)
	printField("Parameter", result.Parameter)
	printFieldColor("Severity", fmt.Sprintf("%s  [score: %d/100]", sevLabel, result.SeverityScore), sevColor)
	printFieldColor("XSS Type", result.XSSType, colorCyan)
	printField("Context", result.Context)
	printField("Match Type", result.MatchType)
	printField("Payload Lvl", fmt.Sprintf("%d (%s)", result.PayloadLevel, result.LevelName))
	printFieldColor("Payload", result.Payload, colorYellow)
	printFieldColor("PoC URL", result.PoCURL, colorHiGreen)
	printField("Status Code", fmt.Sprintf("%d  |  Response: %d bytes  |  Reflect count: %d", result.StatusCode, result.ResponseSize, result.ReflectCount))
	printFieldColor("Evidence", result.Evidence, colorGray)

	if sev >= SeverityHigh {
		colorGray.Printf("  %-14s", "Report Notes:")
		colorHiGreen.Printf(" Payload executed in %s — suitable for bug bounty report\n", result.Context)
	} else if sev == SeverityMedium {
		colorGray.Printf("  %-14s", "Report Notes:")
		colorYellow.Printf(" Reflected but execution not confirmed — verify manually in browser\n")
	} else {
		colorGray.Printf("  %-14s", "Report Notes:")
		colorBlue.Printf(" Value reflected in non-executable context — likely informational\n")
	}

	borderColor.Println(strings.Repeat("═", 82))
	fmt.Println()

	l.entries = append(l.entries, LogEntry{Timestamp: ts, Level: SeverityTitle(sev), Message: result.URL})
}

func SeverityStyle(sev SeverityLevel) (string, *color.Color, *color.Color) {
	switch sev {
	case SeverityCritical:
		return "[ CRITICAL ]", colorHiRed, colorHiRed
	case SeverityHigh:
		return "[   HIGH   ]", colorRed, colorRed
	case SeverityMedium:
		return "[  MEDIUM  ]", colorYellow, colorOrange
	case SeverityLow:
		return "[   LOW    ]", colorBlue, colorBlue
	default:
		return "[   INFO   ]", colorGray, colorGray
	}
}

func SeverityTitle(sev SeverityLevel) string {
	switch sev {
	case SeverityCritical:
		return "CRITICAL"
	case SeverityHigh:
		return "HIGH"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

func (l *Logger) PrintSummary(payloadsSent int, vulns int, scanned int, elapsed time.Duration, bySevertiy map[string]int) {
	fmt.Println()
	colorCyan.Println(strings.Repeat("═", 60))
	colorHiWhite.Println("  SCAN SUMMARY")
	colorCyan.Println(strings.Repeat("─", 60))
	colorWhite.Printf("  URLs Scanned      : %d\n", scanned)
	colorWhite.Printf("  Payloads Sent     : %d\n", payloadsSent)
	if vulns > 0 {
		colorHiRed.Printf("  Total Findings    : %d VULNERABILITIES FOUND\n", vulns)
	} else {
		colorWhite.Printf("  Total Findings    : 0\n")
	}
	if len(bySevertiy) > 0 {
		colorCyan.Println(strings.Repeat("─", 60))
		colorHiWhite.Println("  BREAKDOWN BY SEVERITY")
		if v, ok := bySevertiy["CRITICAL"]; ok && v > 0 {
			colorHiRed.Printf("    %-10s: %d\n", "CRITICAL", v)
		}
		if v, ok := bySevertiy["HIGH"]; ok && v > 0 {
			colorRed.Printf("    %-10s: %d\n", "HIGH", v)
		}
		if v, ok := bySevertiy["MEDIUM"]; ok && v > 0 {
			colorYellow.Printf("    %-10s: %d\n", "MEDIUM", v)
		}
		if v, ok := bySevertiy["LOW"]; ok && v > 0 {
			colorBlue.Printf("    %-10s: %d\n", "LOW", v)
		}
		if v, ok := bySevertiy["INFO"]; ok && v > 0 {
			colorGray.Printf("    %-10s: %d\n", "INFO", v)
		}
	}
	colorWhite.Printf("  Time Elapsed      : %s\n", elapsed.Round(time.Millisecond))
	colorCyan.Println(strings.Repeat("═", 60))
	fmt.Println()
}

func (l *Logger) GetEntries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.entries
}

type VulnResult struct {
	URL           string
	Parameter     string
	Payload       string
	XSSType       string
	PayloadLevel  int
	LevelName     string
	PoCURL        string
	Evidence      string
	Timestamp     string
	StatusCode    int
	ResponseSize  int
	ReflectCount  int
	Context       string
	MatchType     string
	Severity      SeverityLevel
	SeverityScore int
	Executable    bool
}
