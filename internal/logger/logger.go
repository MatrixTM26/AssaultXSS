package logger

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type SeverityLevel int

const (
	SeverityInfo     SeverityLevel = 0
	SeverityLow      SeverityLevel = 1
	SeverityMedium   SeverityLevel = 2
	SeverityHigh     SeverityLevel = 3
	SeverityCritical SeverityLevel = 4
)

var (
	penGray    = NewPen(ansiGray)
	penRed     = NewPen(ansiRed)
	penYellow  = NewPen(ansiYellow)
	penBlue    = NewPen(ansiBlue)
	penCyan    = NewPen(ansiCyan)
	penHiRed   = NewPen(ansiHiRed)
	penHiGreen = NewPen(ansiHiGreen)
	penHiWhite = NewPen(ansiHiWhite)
	penOrange  = NewPen(ansiOrange)
)

type Logger struct {
	Verbose   bool
	mu        sync.Mutex
	entries   []LogEntry
	barActive bool
}

type LogEntry struct {
	Timestamp string
	Level     string
	Message   string
}

func NewLogger(verbose bool) *Logger {
	return &Logger{Verbose: verbose}
}

func (l *Logger) SetBarActive(v bool) {
	l.mu.Lock()
	l.barActive = v
	l.mu.Unlock()
}

func (l *Logger) ts() string {
	return time.Now().Format("15:04:05")
}

func (l *Logger) clearLine() {
	if l.barActive {
		fmt.Fprintf(os.Stderr, "\r\033[2K")
	}
}

func (l *Logger) line(levelColor *Pen, tag string, msg string) {
	l.clearLine()
	ts := l.ts()
	fmt.Printf("%s %s %s\n",
		penGray.Sprintf("[%s]", ts),
		levelColor.Sprintf("[%s]", tag),
		msg,
	)
	l.entries = append(l.entries, LogEntry{ts, tag, msg})
}

func (l *Logger) Debug(msg string) {
	if !l.Verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.line(penBlue, "DBG", penGray.Sprint(msg))
}

func (l *Logger) Info(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.line(penCyan, "INF", msg)
}

func (l *Logger) Warning(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.line(penYellow, "WRN", penYellow.Sprint(msg))
}

func (l *Logger) Error(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.line(penRed, "ERR", penRed.Sprint(msg))
}

func (l *Logger) ScanStart(targetURL string, level int, threads int) {
	l.Info(fmt.Sprintf("target url: %s", targetURL))
	l.Info(fmt.Sprintf("payload level: %d | threads: %d", level, threads))
}

func (l *Logger) ParamFound(param string, sourceURL string) {
	if !l.Verbose {
		return
	}
	l.Debug(fmt.Sprintf("parameter found: [%s] at %s", param, sourceURL))
}

func (l *Logger) PayloadSent(targetURL string, param string, payloadStr string) {
	if !l.Verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	truncated := payloadStr
	if len(truncated) > 60 {
		truncated = truncated[:60] + "..."
	}
	msg := fmt.Sprintf("testing [%s] -> %s",
		penHiWhite.Sprint(param),
		penGray.Sprint(truncated),
	)
	l.line(penBlue, "DBG", msg)
}

func (l *Logger) ReflectOnly(param string, note string) {
	if !l.Verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.line(penBlue, "RFL", fmt.Sprintf("reflected/no-exec: [%s] %s", param, penGray.Sprint(note)))
}

func (l *Logger) PayloadResult(bar interface{ Render() }, param string, payloadStr string, tag string, exec bool) {
	if !l.Verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	truncated := payloadStr
	if len(truncated) > 55 {
		truncated = truncated[:55] + "..."
	}

	var tagColor string
	switch tag {
	case "EXEC", "VULN":
		tagColor = ansiGreen
	case "REFLECT":
		tagColor = ansiYellow
	case "SANITIZED":
		tagColor = ansiBlue
	case "ERR":
		tagColor = ansiRed
	default:
		tagColor = ansiGray
	}

	ts := l.ts()
	l.clearLine()

	pct := ""
	execStr := "NO"
	if exec {
		execStr = ansiGreen + "YES" + ansiReset
		tagColor = ansiGreen
	}

	fmt.Printf("%s %s [%s%s%s] [%s] - %s\n",
		penGray.Sprintf("[%s]", ts),
		penBlue.Sprint("[DBG]"),
		tagColor, tag, ansiReset,
		penHiWhite.Sprint(param),
		penGray.Sprint(truncated),
	)
	_ = pct
	_ = execStr
	l.entries = append(l.entries, LogEntry{ts, "DBG", fmt.Sprintf("[%s] [%s] - %s", tag, param, truncated)})
}

func (l *Logger) VulnFound(result VulnResult) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := l.ts()
	sev := result.Severity
	sevPen, tag := sevStyle(sev)

	l.clearLine()
	fmt.Println()
	fmt.Println(penGray.Sprint(strings.Repeat("-", 72)))

	fmt.Printf("%s %s %s  %s\n",
		penGray.Sprintf("[%s]", ts),
		sevPen.Sprintf("[%s]", tag),
		penHiWhite.Sprintf("parameter: [%s]", result.Parameter),
		penGray.Sprintf("score: %s", sevPen.Sprintf("%d/100", result.SeverityScore)),
	)

	kv := func(key, val string) {
		fmt.Printf("           %s %s\n", penGray.Sprintf("%-12s", key), val)
	}
	kvC := func(key, val string, p *Pen) {
		fmt.Printf("           %s %s\n", penGray.Sprintf("%-12s", key), p.Sprint(val))
	}

	kv("target:", result.URL)
	kvC("payload:", result.Payload, penYellow)
	kv("context:", fmt.Sprintf("%s  (match: %s)", result.Context, result.MatchType))
	kv("type:", fmt.Sprintf("%s  lvl:%d (%s)  exec:%v  reflects:%d",
		result.XSSType, result.PayloadLevel, result.LevelName,
		result.Executable, result.ReflectCount,
	))
	kvC("poc:", result.PoCURL, penHiGreen)

	if result.Evidence != "" && result.Evidence != "(not found)" {
		ev := result.Evidence
		if len(ev) > 110 {
			ev = ev[:110] + "..."
		}
		kvC("evidence:", ev, penGray)
	}

	switch {
	case sev >= SeverityHigh:
		kvC("note:", "executable context confirmed — ready for bug bounty report", penHiGreen)
	case sev == SeverityMedium:
		kvC("note:", "reflected — verify execution manually in browser", penOrange)
	default:
		kvC("note:", "reflected in non-executable context", penBlue)
	}

	fmt.Println(penGray.Sprint(strings.Repeat("-", 72)))
	fmt.Println()

	l.entries = append(l.entries, LogEntry{ts, SeverityTitle(sev), result.URL})
}

func sevStyle(sev SeverityLevel) (*Pen, string) {
	switch sev {
	case SeverityCritical:
		return penHiRed, "CRITICAL"
	case SeverityHigh:
		return penRed, "HIGH"
	case SeverityMedium:
		return penYellow, "MEDIUM"
	case SeverityLow:
		return penBlue, "LOW"
	default:
		return penGray, "INFO"
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

func SeverityStyle(sev SeverityLevel) (string, *Pen, *Pen) {
	p, badge := sevStyle(sev)
	return badge, p, p
}

func (l *Logger) PrintSummary(payloadsSent int, vulns int, scanned int, elapsed time.Duration, bySeverity map[string]int) {
	fmt.Println()
	fmt.Println(penCyan.Sprint(strings.Repeat("=", 50)))
	fmt.Println(penCyan.Sprint("  scan summary"))
	fmt.Println(penGray.Sprint(strings.Repeat("-", 50)))

	row := func(k, v string) {
		fmt.Printf("  %s %s\n", penGray.Sprintf("%-22s", k), v)
	}

	row("urls scanned:", fmt.Sprintf("%d", scanned))
	row("payloads sent:", fmt.Sprintf("%d", payloadsSent))
	row("time elapsed:", elapsed.Round(time.Millisecond).String())

	if vulns > 0 {
		fmt.Println(penGray.Sprint(strings.Repeat("-", 50)))
		row("total findings:", penHiRed.Sprintf("%d", vulns))
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if v, ok := bySeverity[sev]; ok && v > 0 {
				p, _ := sevStyle(sevFromString(sev))
				fmt.Printf("  %s %s\n", penGray.Sprintf("%-22s", ""), p.Sprintf("[%s] %d", sev, v))
			}
		}
	} else {
		row("total findings:", "0")
	}

	fmt.Println(penCyan.Sprint(strings.Repeat("=", 50)))
	fmt.Println()
}

func sevFromString(s string) SeverityLevel {
	switch s {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityMedium
	case "LOW":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func (l *Logger) GetEntries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.entries
}

type VulnResult struct {
	URL           string        `json:"url"`
	Parameter     string        `json:"parameter"`
	Payload       string        `json:"payload"`
	XSSType       string        `json:"xss_type"`
	PayloadLevel  int           `json:"payload_level"`
	LevelName     string        `json:"level_name"`
	PoCURL        string        `json:"poc_url"`
	Evidence      string        `json:"evidence"`
	Timestamp     string        `json:"timestamp"`
	StatusCode    int           `json:"status_code"`
	ResponseSize  int           `json:"response_size"`
	ReflectCount  int           `json:"reflect_count"`
	Context       string        `json:"context"`
	MatchType     string        `json:"match_type"`
	Severity      SeverityLevel `json:"severity"`
	SeverityScore int           `json:"severity_score"`
	Executable    bool          `json:"executable"`
}
