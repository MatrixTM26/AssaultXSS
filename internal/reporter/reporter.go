package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"assaultxss/internal/logger"
)

type Report struct {
	ToolName    string              `json:"tool"`
	Version     string              `json:"version"`
	GeneratedAt string              `json:"generated_at"`
	TotalVulns  int                 `json:"total_vulnerabilities"`
	Breakdown   map[string]int      `json:"severity_breakdown"`
	Results     []logger.VulnResult `json:"results"`
}

func ExportResults(results []logger.VulnResult, exportPath string, log *logger.Logger) {
	if exportPath == "" {
		return
	}

	validated := FilterValidResults(results)
	if len(validated) == 0 {
		log.Warning("All findings failed strict validation — nothing exported")
		return
	}

	if strings.HasSuffix(strings.ToLower(exportPath), ".json") {
		ExportJSON(validated, exportPath, log)
	} else {
		ExportText(validated, exportPath, log)
	}
}

func FilterValidResults(results []logger.VulnResult) []logger.VulnResult {
	var out []logger.VulnResult
	for _, r := range results {
		if r.ReflectCount == 0 {
			continue
		}
		if r.Severity == logger.SeverityInfo {
			continue
		}
		if r.SeverityScore < 20 {
			continue
		}
		out = append(out, r)
	}
	return out
}

func BuildBreakdown(results []logger.VulnResult) map[string]int {
	out := make(map[string]int)
	for _, r := range results {
		out[logger.SeverityTitle(r.Severity)]++
	}
	return out
}

func ExportJSON(results []logger.VulnResult, path string, log *logger.Logger) {
	report := Report{
		ToolName:    "AssaultXSS",
		Version:     "1.2.0",
		GeneratedAt: time.Now().Format(time.RFC3339),
		TotalVulns:  len(results),
		Breakdown:   BuildBreakdown(results),
		Results:     results,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Error(fmt.Sprintf("Failed to marshal JSON: %v", err))
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Error(fmt.Sprintf("Failed to write JSON: %v", err))
		return
	}
	log.Info(fmt.Sprintf("Results exported → %s (%d findings)", path, len(results)))
}

func ExportText(results []logger.VulnResult, path string, log *logger.Logger) {
	var sb strings.Builder
	bd := BuildBreakdown(results)

	sb.WriteString(strings.Repeat("═", 82) + "\n")
	sb.WriteString("  AssaultXSS v1.2.0 — XSS Vulnerability Report\n")
	sb.WriteString(fmt.Sprintf("  Generated  : %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("  Findings   : %d (post strict-validation)\n", len(results)))
	sb.WriteString("  Scope      : Authorized bug bounty only\n")
	sb.WriteString("\n  SEVERITY BREAKDOWN\n")
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
		if v, ok := bd[sev]; ok && v > 0 {
			sb.WriteString(fmt.Sprintf("    %-10s : %d\n", sev, v))
		}
	}
	sb.WriteString(strings.Repeat("═", 82) + "\n\n")

	for i, r := range results {
		sb.WriteString(fmt.Sprintf("[ Finding #%d — %s  score:%d/100 ]\n", i+1, logger.SeverityTitle(r.Severity), r.SeverityScore))
		sb.WriteString(fmt.Sprintf("  URL           : %s\n", r.URL))
		sb.WriteString(fmt.Sprintf("  Parameter     : %s\n", r.Parameter))
		sb.WriteString(fmt.Sprintf("  XSS Type      : %s\n", r.XSSType))
		sb.WriteString(fmt.Sprintf("  Context       : %s\n", r.Context))
		sb.WriteString(fmt.Sprintf("  Match Type    : %s\n", r.MatchType))
		sb.WriteString(fmt.Sprintf("  Executable    : %v\n", r.Executable))
		sb.WriteString(fmt.Sprintf("  Reflect Count : %d\n", r.ReflectCount))
		sb.WriteString(fmt.Sprintf("  Payload Lvl   : %d (%s)\n", r.PayloadLevel, r.LevelName))
		sb.WriteString(fmt.Sprintf("  Payload       : %s\n", r.Payload))
		sb.WriteString(fmt.Sprintf("  PoC URL       : %s\n", r.PoCURL))
		sb.WriteString(fmt.Sprintf("  Evidence      : %s\n", r.Evidence))
		sb.WriteString(fmt.Sprintf("  Status Code   : %d  |  Response: %d bytes\n", r.StatusCode, r.ResponseSize))
		sb.WriteString(fmt.Sprintf("  Timestamp     : %s\n", r.Timestamp))
		sb.WriteString(strings.Repeat("─", 82) + "\n")
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		log.Error(fmt.Sprintf("Failed to write report: %v", err))
		return
	}
	log.Info(fmt.Sprintf("Results exported → %s (%d findings)", path, len(results)))
}
