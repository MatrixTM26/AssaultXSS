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
	colorRed     = color.New(color.FgRed, color.Bold)
	colorGreen   = color.New(color.FgGreen, color.Bold)
	colorYellow  = color.New(color.FgYellow, color.Bold)
	colorCyan    = color.New(color.FgCyan, color.Bold)
	colorMagenta = color.New(color.FgMagenta, color.Bold)
	colorWhite   = color.New(color.FgWhite)
	colorBlue    = color.New(color.FgBlue, color.Bold)
	colorGray    = color.New(color.FgHiBlack)
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
	colorWhite.Printf("%s\n", msg)
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

func (l *Logger) ScanStart(url string, level int, threads int) {
	l.Info(fmt.Sprintf("Scan initiated → %s", url))
	l.Info(fmt.Sprintf("Payload level: %d | Threads: %d", level, threads))
}

func (l *Logger) ParamFound(param string, url string) {
	if !l.Verbose {
		return
	}
	l.Debug(fmt.Sprintf("Parameter discovered: [%s] at %s", param, url))
}

func (l *Logger) PayloadSent(url string, param string, payload string) {
	if !l.Verbose {
		return
	}
	truncated := payload
	if len(truncated) > 60 {
		truncated = truncated[:60] + "..."
	}
	l.Debug(fmt.Sprintf("Testing [%s] → %s | Payload: %s", param, url, truncated))
}

func (l *Logger) VulnFound(result VulnResult) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := l.timestamp()
	colorGray.Printf("[%s] ", ts)
	colorGreen.Print("[VLN] ")
	colorGreen.Printf("XSS CONFIRMED → %s\n", result.URL)
	colorGray.Printf("[%s] ", ts)
	colorGreen.Print("      ")
	colorGreen.Printf("  Parameter : %s\n", result.Parameter)
	colorGray.Printf("[%s] ", ts)
	colorGreen.Print("      ")
	colorGreen.Printf("  Type      : %s\n", result.XSSType)
	colorGray.Printf("[%s] ", ts)
	colorGreen.Print("      ")
	colorGreen.Printf("  Level     : %d (%s)\n", result.PayloadLevel, result.LevelName)
	colorGray.Printf("[%s] ", ts)
	colorGreen.Print("      ")
	colorGreen.Printf("  Payload   : %s\n", result.Payload)
	colorGray.Printf("[%s] ", ts)
	colorGreen.Print("      ")
	colorGreen.Printf("  PoC URL   : %s\n", result.PoCURL)
	colorGray.Printf("[%s] ", ts)
	colorGreen.Print("      ")
	colorGreen.Printf("  Evidence  : %s\n", result.Evidence)
	fmt.Println(strings.Repeat("─", 80))
}

func (l *Logger) PrintSummary(total int, vulns int, scanned int, elapsed time.Duration) {
	fmt.Println()
	fmt.Println(strings.Repeat("═", 80))
	colorCyan.Println("  SCAN SUMMARY")
	fmt.Println(strings.Repeat("─", 80))
	colorWhite.Printf("  URLs Scanned      : %d\n", scanned)
	colorWhite.Printf("  Parameters Tested : %d\n", total)
	if vulns > 0 {
		colorGreen.Printf("  Vulnerabilities   : %d FOUND\n", vulns)
	} else {
		colorWhite.Printf("  Vulnerabilities   : %d found\n", vulns)
	}
	colorWhite.Printf("  Time Elapsed      : %s\n", elapsed.Round(time.Millisecond))
	fmt.Println(strings.Repeat("═", 80))
	fmt.Println()
}

func (l *Logger) GetEntries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.entries
}

type VulnResult struct {
	URL          string
	Parameter    string
	Payload      string
	XSSType      string
	PayloadLevel int
	LevelName    string
	PoCURL       string
	Evidence     string
	Timestamp    string
	StatusCode   int
	ResponseSize int
	ReflectCount int
	Context      string
}
