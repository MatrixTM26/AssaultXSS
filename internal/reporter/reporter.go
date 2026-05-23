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
	Results     []logger.VulnResult `json:"results"`
}

func ExportResults(results []logger.VulnResult, exportPath string, log *logger.Logger) {
	if exportPath == "" {
		return
	}
	if strings.HasSuffix(strings.ToLower(exportPath), ".json") {
		ExportJSON(results, exportPath, log)
	} else {
		ExportText(results, exportPath, log)
	}
}

func ExportJSON(results []logger.VulnResult, path string, log *logger.Logger) {
	report := Report{
		ToolName:    "AssaultXSS",
		Version:     "1.0.0",
		GeneratedAt: time.Now().Format(time.RFC3339),
		TotalVulns:  len(results),
		Results:     results,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Error(fmt.Sprintf("Failed to marshal JSON: %v", err))
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Error(fmt.Sprintf("Failed to write JSON file: %v", err))
		return
	}
	log.Info(fmt.Sprintf("Results exported to JSON: %s (%d findings)", path, len(results)))
}

func ExportText(results []logger.VulnResult, path string, log *logger.Logger) {
	var sb strings.Builder
	sb.WriteString("═══════════════════════════════════════════════════════════════════════════════\n")
	sb.WriteString("  AssaultXSS v1.0.0 - XSS Vulnerability Scan Report\n")
	sb.WriteString(fmt.Sprintf("  Generated : %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("  Findings  : %d\n", len(results)))
	sb.WriteString("  Note      : For authorized bug bounty use only\n")
	sb.WriteString("═══════════════════════════════════════════════════════════════════════════════\n\n")

	for i, r := range results {
		sb.WriteString(fmt.Sprintf("[ Finding #%d ]\n", i+1))
		sb.WriteString(fmt.Sprintf("  URL          : %s\n", r.URL))
		sb.WriteString(fmt.Sprintf("  Parameter    : %s\n", r.Parameter))
		sb.WriteString(fmt.Sprintf("  XSS Type     : %s\n", r.XSSType))
		sb.WriteString(fmt.Sprintf("  Payload Lvl  : %d (%s)\n", r.PayloadLevel, r.LevelName))
		sb.WriteString(fmt.Sprintf("  Payload      : %s\n", r.Payload))
		sb.WriteString(fmt.Sprintf("  PoC URL      : %s\n", r.PoCURL))
		sb.WriteString(fmt.Sprintf("  Evidence     : %s\n", r.Evidence))
		sb.WriteString(fmt.Sprintf("  Context      : %s\n", r.Context))
		sb.WriteString(fmt.Sprintf("  Status Code  : %d\n", r.StatusCode))
		sb.WriteString(fmt.Sprintf("  Reflect Count: %d\n", r.ReflectCount))
		sb.WriteString(fmt.Sprintf("  Timestamp    : %s\n", r.Timestamp))
		sb.WriteString("─────────────────────────────────────────────────────────────────────────────\n")
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		log.Error(fmt.Sprintf("Failed to write report: %v", err))
		return
	}
	log.Info(fmt.Sprintf("Results exported to text: %s (%d findings)", path, len(results)))
}
