package engine

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"assaultxss/internal/config"
	"assaultxss/internal/crawler"
	"assaultxss/internal/logger"
	"assaultxss/internal/payload"

	"github.com/fatih/color"
)

const ProbeMarker = "xAssaultx31337"

var executablePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[^>]*>[\s\S]*?` + regexp.QuoteMeta("xAssaultx31337")),
	regexp.MustCompile(`(?i)on\w+\s*=\s*["']?[^"'>]*` + regexp.QuoteMeta("xAssaultx31337")),
	regexp.MustCompile(`(?i)<[a-z][^>]*\s+on\w+\s*=[^>]*` + regexp.QuoteMeta("xAssaultx31337")),
	regexp.MustCompile(`(?i)javascript\s*:[^"'>]*` + regexp.QuoteMeta("xAssaultx31337")),
	regexp.MustCompile(`(?i)<svg[^>]*>[^<]*` + regexp.QuoteMeta("xAssaultx31337")),
	regexp.MustCompile(`(?i)<img[^>]*onerror[^>]*` + regexp.QuoteMeta("xAssaultx31337")),
}

var executablePayloadPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<script[\s>]`),
	regexp.MustCompile(`(?i)\son\w+\s*=`),
	regexp.MustCompile(`(?i)javascript\s*:`),
	regexp.MustCompile(`(?i)<svg[\s>]`),
	regexp.MustCompile(`(?i)<img[^>]+onerror`),
	regexp.MustCompile(`(?i)<iframe[\s>]`),
	regexp.MustCompile(`(?i)<body[\s>]`),
	regexp.MustCompile(`(?i)<details[^>]+ontoggle`),
	regexp.MustCompile(`(?i)<input[^>]+onfocus`),
	regexp.MustCompile(`(?i)<video[\s>]`),
	regexp.MustCompile(`(?i)<audio[\s>]`),
}

type Scanner struct {
	Cfg     *config.Config
	Log     *logger.Logger
	Client  *http.Client
	Results []logger.VulnResult
	mu      sync.Mutex
	Stats   ScanStats
	Bar     *ProgressBar
}

type ScanStats struct {
	URLsScanned  int
	ParamsTested int
	PayloadsSent int
	VulnsFound   int
	ErrorCount   int
	StartTime    time.Time
}

type ProgressBar struct {
	Total     int64
	Current   int64
	Width     int
	Label     string
	StartTime time.Time
	mu        sync.Mutex
	finished  bool
}

func NewProgressBar(total int, label string) *ProgressBar {
	return &ProgressBar{
		Total:     int64(total),
		Width:     38,
		Label:     label,
		StartTime: time.Now(),
	}
}

func (pb *ProgressBar) Increment() {
	atomic.AddInt64(&pb.Current, 1)
	pb.Render()
}

func (pb *ProgressBar) Render() {
	pb.mu.Lock()
	defer pb.mu.Unlock()
	if pb.finished {
		return
	}
	current := atomic.LoadInt64(&pb.Current)
	total := pb.Total
	if total <= 0 {
		total = 1
	}
	pct := float64(current) / float64(total)
	if pct > 1.0 {
		pct = 1.0
	}
	filled := int(pct * float64(pb.Width))
	if filled > pb.Width {
		filled = pb.Width
	}
	elapsed := time.Since(pb.StartTime)
	var eta string
	if pct > 0.02 {
		remaining := time.Duration(float64(elapsed) / pct * (1 - pct))
		if remaining > time.Hour {
			eta = ">1h"
		} else {
			eta = remaining.Round(time.Second).String()
		}
	} else {
		eta = "---"
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", pb.Width-filled)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)
	gray := color.New(color.FgHiBlack)
	fmt.Fprintf(os.Stderr, "\r")
	gray.Fprintf(os.Stderr, "  [")
	if pct >= 1.0 {
		green.Fprintf(os.Stderr, "%s", bar)
	} else {
		cyan.Fprintf(os.Stderr, "%s", bar)
	}
	gray.Fprintf(os.Stderr, "] ")
	if pct >= 1.0 {
		green.Fprintf(os.Stderr, "%5.1f%%", pct*100)
	} else {
		cyan.Fprintf(os.Stderr, "%5.1f%%", pct*100)
	}
	gray.Fprintf(os.Stderr, "  %d/%d  ETA:%-6s  %s  ", current, total, eta, pb.Label)
}

func (pb *ProgressBar) Finish() {
	pb.mu.Lock()
	pb.finished = true
	pb.mu.Unlock()
	current := pb.Total
	bar := strings.Repeat("█", pb.Width)
	elapsed := time.Since(pb.StartTime).Round(time.Millisecond)
	green := color.New(color.FgGreen, color.Bold)
	gray := color.New(color.FgHiBlack)
	fmt.Fprintf(os.Stderr, "\r")
	gray.Fprintf(os.Stderr, "  [")
	green.Fprintf(os.Stderr, "%s", bar)
	gray.Fprintf(os.Stderr, "] ")
	green.Fprintf(os.Stderr, "100.0%%")
	gray.Fprintf(os.Stderr, "  %d/%d  done:%-8s  %s  \n", current, current, elapsed, pb.Label)
}

func NewScanner(cfg *config.Config, log *logger.Logger) *Scanner {
	return &Scanner{
		Cfg: cfg,
		Log: log,
		Client: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		Stats: ScanStats{StartTime: time.Now()},
	}
}

func (s *Scanner) Run() []logger.VulnResult {
	payloads := payload.GetPayloads(s.Cfg.Level, s.Cfg.ExternalPayloads)
	s.Log.Info(fmt.Sprintf("Loaded %d payloads for level %d (%s)", len(payloads), s.Cfg.Level, payload.LevelName(s.Cfg.Level)))

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.Cfg.Threads)
	for _, rawURL := range s.Cfg.URLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			s.ScanURL(u, payloads)
		}(rawURL)
	}
	wg.Wait()
	return s.Results
}

func (s *Scanner) ScanURL(rawURL string, payloads []payload.PayloadEntry) {
	s.Log.ScanStart(rawURL, s.Cfg.Level, s.Cfg.Threads)

	cr, err := crawler.NewCrawler(rawURL, s.Cfg.Depth, s.Cfg.Timeout, s.Cfg.Threads, s.Log)
	if err != nil {
		s.Log.Error(fmt.Sprintf("Crawler init failed: %v", err))
		return
	}

	s.Log.Info("Crawling pages and discovering parameters...")
	pages := cr.Crawl(rawURL)
	if len(pages) == 0 {
		parsed, perr := url.Parse(rawURL)
		if perr == nil {
			params := make(map[string][]string)
			for k, v := range parsed.Query() {
				params[k] = v
			}
			pages = []crawler.PageResult{{URL: rawURL, Params: params}}
		}
	}

	s.Log.Info(fmt.Sprintf("Discovered %d page(s) — probing reflective parameters...", len(pages)))

	type TestJob struct {
		PageURL string
		Param   string
		IsForm  bool
		Form    crawler.FormData
	}

	var jobs []TestJob
	seen := make(map[string]bool)

	for _, page := range pages {
		targetParams := page.Params
		if s.Cfg.Param != "" {
			targetParams = map[string][]string{s.Cfg.Param: {""}}
		}
		for param := range targetParams {
			key := page.URL + "|" + param
			if seen[key] {
				continue
			}
			seen[key] = true
			reflective, encType := s.ProbeReflection(page.URL, param)
			if reflective {
				s.Log.Info(fmt.Sprintf("Reflective param: [%s] at %s (type: %s)", param, page.URL, encType))
				jobs = append(jobs, TestJob{PageURL: page.URL, Param: param})
			} else {
				s.Log.Debug(fmt.Sprintf("Not reflective — skipping: [%s] at %s", param, page.URL))
			}
		}
		for _, form := range page.Forms {
			for param := range form.BuildParams() {
				if s.Cfg.Param != "" && param != s.Cfg.Param {
					continue
				}
				key := form.Action + "|form|" + param
				if seen[key] {
					continue
				}
				seen[key] = true
				reflective, encType := s.ProbeFormReflection(form, param)
				if reflective {
					s.Log.Info(fmt.Sprintf("Reflective form param: [%s] action=%s (type: %s)", param, form.Action, encType))
					jobs = append(jobs, TestJob{Param: param, IsForm: true, Form: form})
				}
			}
		}
	}

	if len(jobs) == 0 {
		s.Log.Warning("No reflective parameters found")
		s.Log.Warning("Try: -p <param> to force-test a specific param, or increase -d depth")
		return
	}

	totalTasks := len(jobs) * len(payloads)
	s.Log.Info(fmt.Sprintf("Testing %d reflective param(s) × %d payloads = %d requests", len(jobs), len(payloads), totalTasks))
	fmt.Fprintln(os.Stderr)

	bar := NewProgressBar(totalTasks, "xss-scan")
	s.Bar = bar

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.Cfg.Threads)

	for _, job := range jobs {
		s.mu.Lock()
		s.Stats.URLsScanned++
		s.mu.Unlock()
		wg.Add(1)
		sem <- struct{}{}
		go func(j TestJob) {
			defer wg.Done()
			defer func() { <-sem }()
			if j.IsForm {
				s.TestFormParameter(j.Form, j.Param, payloads, bar)
			} else {
				s.TestParameter(j.PageURL, j.Param, payloads, bar)
			}
		}(job)
	}

	wg.Wait()
	bar.Finish()
	fmt.Fprintln(os.Stderr)
}

func (s *Scanner) ProbeReflection(pageURL string, param string) (bool, string) {
	parsed, err := url.Parse(pageURL)
	if err != nil {
		return false, ""
	}
	q := url.Values{}
	for k, v := range parsed.Query() {
		q[k] = v
	}
	q.Set(param, ProbeMarker)
	cloned, _ := url.Parse(parsed.Scheme + "://" + parsed.Host + parsed.Path)
	cloned.RawQuery = q.Encode()
	_, body, _, err := s.DoRequest("GET", cloned.String(), nil)
	if err != nil {
		return false, ""
	}
	_, ok, encType := DetectReflection(body, ProbeMarker)
	return ok, encType
}

func (s *Scanner) ProbeFormReflection(form crawler.FormData, param string) (bool, string) {
	formData := make(url.Values)
	for k, v := range form.BuildParams() {
		formData.Set(k, v)
	}
	formData.Set(param, ProbeMarker)
	method := strings.ToUpper(form.Method)
	var targetURL string
	var body io.Reader
	if method == "POST" {
		targetURL = form.Action
		body = strings.NewReader(formData.Encode())
	} else {
		parsed, err := url.Parse(form.Action)
		if err != nil {
			return false, ""
		}
		parsed.RawQuery = formData.Encode()
		targetURL = parsed.String()
	}
	_, respBody, _, err := s.DoRequest(method, targetURL, body)
	if err != nil {
		return false, ""
	}
	_, ok, encType := DetectReflection(respBody, ProbeMarker)
	return ok, encType
}

func DetectReflection(body string, marker string) (string, bool, string) {
	if strings.Contains(body, marker) {
		return marker, true, "raw"
	}
	lower := strings.ToLower(marker)
	if strings.Contains(strings.ToLower(body), lower) {
		return lower, true, "case-insensitive"
	}
	if enc := url.QueryEscape(marker); strings.Contains(body, enc) {
		return enc, true, "url-encoded"
	}
	if enc := HTMLEntityEncode(marker); strings.Contains(body, enc) {
		return enc, true, "html-entity-encoded"
	}
	if dec := HTMLEntityDecode(marker); dec != marker && strings.Contains(body, dec) {
		return dec, true, "html-entity-decoded"
	}
	return "", false, ""
}

func (s *Scanner) TestParameter(pageURL string, param string, payloads []payload.PayloadEntry, bar *ProgressBar) {
	s.mu.Lock()
	s.Stats.ParamsTested++
	s.mu.Unlock()

	baseParsed, err := url.Parse(pageURL)
	if err != nil {
		for range payloads {
			bar.Increment()
		}
		return
	}
	baseQuery := url.Values{}
	for k, v := range baseParsed.Query() {
		baseQuery[k] = v
	}

	for _, p := range payloads {
		s.mu.Lock()
		s.Stats.PayloadsSent++
		s.mu.Unlock()

		cloned, _ := url.Parse(baseParsed.Scheme + "://" + baseParsed.Host + baseParsed.Path)
		q := url.Values{}
		for k, v := range baseQuery {
			q[k] = v
		}
		q.Set(param, p.Value)
		cloned.RawQuery = q.Encode()
		testURL := cloned.String()

		s.Log.PayloadSent(testURL, param, p.Value)

		_, body, statusCode, err := s.DoRequest("GET", testURL, nil)
		if err != nil {
			s.mu.Lock()
			s.Stats.ErrorCount++
			s.mu.Unlock()
			bar.Increment()
			continue
		}

		result, found := s.AnalyzeResponse(body, p, param, testURL, statusCode, "GET")
		if found {
			s.mu.Lock()
			s.Stats.VulnsFound++
			s.Results = append(s.Results, result)
			s.mu.Unlock()
			fmt.Fprintln(os.Stderr)
			s.Log.VulnFound(result)
		} else if s.Cfg.Verbose {
			evidence, ok, _ := DetectReflection(body, p.Value)
			if ok {
				s.Log.ReflectOnly(param, evidence)
			}
		}
		bar.Increment()
	}
}

func (s *Scanner) TestFormParameter(form crawler.FormData, param string, payloads []payload.PayloadEntry, bar *ProgressBar) {
	s.mu.Lock()
	s.Stats.ParamsTested++
	s.mu.Unlock()

	for _, p := range payloads {
		s.mu.Lock()
		s.Stats.PayloadsSent++
		s.mu.Unlock()

		formData := make(url.Values)
		for k, v := range form.BuildParams() {
			formData.Set(k, v)
		}
		formData.Set(param, p.Value)

		method := strings.ToUpper(form.Method)
		var targetURL string
		var body io.Reader

		if method == "POST" {
			targetURL = form.Action
			body = strings.NewReader(formData.Encode())
		} else {
			parsed, err := url.Parse(form.Action)
			if err != nil {
				bar.Increment()
				continue
			}
			parsed.RawQuery = formData.Encode()
			targetURL = parsed.String()
		}

		s.Log.PayloadSent(targetURL, param, p.Value)

		_, respBody, statusCode, err := s.DoRequest(method, targetURL, body)
		if err != nil {
			s.mu.Lock()
			s.Stats.ErrorCount++
			s.mu.Unlock()
			bar.Increment()
			continue
		}

		pocURL := targetURL
		if method == "POST" {
			if parsed, perr := url.Parse(form.Action); perr == nil {
				parsed.RawQuery = formData.Encode()
				pocURL = parsed.String()
			}
		}

		result, found := s.AnalyzeResponse(respBody, p, param, pocURL, statusCode, method)
		if found {
			s.mu.Lock()
			s.Stats.VulnsFound++
			s.Results = append(s.Results, result)
			s.mu.Unlock()
			fmt.Fprintln(os.Stderr)
			s.Log.VulnFound(result)
		}
		bar.Increment()
	}
}

func (s *Scanner) DoRequest(method string, rawURL string, body io.Reader) (*http.Response, string, int, error) {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return nil, "", 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Connection", "keep-alive")
	if method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, "", 0, err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return resp, "", resp.StatusCode, err
	}
	return resp, string(respBytes), resp.StatusCode, nil
}

func (s *Scanner) AnalyzeResponse(body string, p payload.PayloadEntry, param string, testURL string, statusCode int, method string) (logger.VulnResult, bool) {
	evidence, reflected, context, matchType := s.CheckReflection(body, p.Value)
	if !reflected {
		return logger.VulnResult{}, false
	}

	executable := IsExecutableReflection(body, p.Value, context)
	sev, score := ScoreVulnerability(p, context, matchType, executable)

	if sev == logger.SeverityInfo {
		return logger.VulnResult{}, false
	}

	pocURL := s.BuildPoCURL(testURL, param, p.Value)
	return logger.VulnResult{
		URL:           testURL,
		Parameter:     param,
		Payload:       p.Value,
		XSSType:       p.XSSType,
		PayloadLevel:  p.Level,
		LevelName:     payload.LevelName(p.Level),
		PoCURL:        pocURL,
		Evidence:      evidence,
		Timestamp:     time.Now().Format(time.RFC3339),
		StatusCode:    statusCode,
		ResponseSize:  len(body),
		ReflectCount:  strings.Count(body, p.Value),
		Context:       context,
		MatchType:     matchType,
		Severity:      sev,
		SeverityScore: score,
		Executable:    executable,
	}, true
}

func IsExecutableReflection(body string, payloadVal string, context string) bool {
	switch context {
	case "text-node", "attribute-value-quoted":
		return false
	case "html-entity-encoded":
		return false
	}

	for _, pat := range executablePayloadPatterns {
		if pat.MatchString(payloadVal) {
			idx := strings.Index(strings.ToLower(body), strings.ToLower(payloadVal[:min(len(payloadVal), 10)]))
			if idx == -1 {
				continue
			}
			surrounding := body
			if idx > 50 {
				surrounding = body[idx-50:]
			}
			if len(surrounding) > 200 {
				surrounding = surrounding[:200]
			}
			lsurr := strings.ToLower(surrounding)
			if strings.Contains(lsurr, "<script") ||
				containsEventHandler(lsurr) ||
				strings.Contains(lsurr, "javascript:") ||
				strings.Contains(lsurr, "<svg") ||
				strings.Contains(lsurr, "onerror") {
				return true
			}
		}
	}
	return false
}

func containsEventHandler(s string) bool {
	events := []string{"onclick", "onmouseover", "onload", "onerror", "onfocus",
		"onblur", "onchange", "onsubmit", "onkeyup", "onkeydown", "ontoggle",
		"onanimationstart", "onbegin", "onstart"}
	for _, ev := range events {
		if strings.Contains(s, ev) {
			return true
		}
	}
	return false
}

func ScoreVulnerability(p payload.PayloadEntry, context string, matchType string, executable bool) (logger.SeverityLevel, int) {
	score := 0

	switch matchType {
	case "raw":
		score += 40
	case "url-decoded":
		score += 35
	case "case-insensitive":
		score += 30
	case "html-entity-decoded":
		score += 20
	case "html-entity-encoded":
		score += 5
	default:
		score += 10
	}

	switch context {
	case "script-block":
		score += 35
	case "event-handler":
		score += 30
	case "attribute-value-url":
		score += 25
	case "html-attribute":
		score += 15
	case "text-node":
		score += 5
	case "attribute-value-quoted":
		score += 5
	default:
		score += 10
	}

	if executable {
		score += 20
	}

	score += p.Level * 2

	switch {
	case score >= 80:
		return logger.SeverityCritical, score
	case score >= 60:
		return logger.SeverityHigh, score
	case score >= 35:
		return logger.SeverityMedium, score
	case score >= 15:
		return logger.SeverityLow, score
	default:
		return logger.SeverityInfo, score
	}
}

func (s *Scanner) CheckReflection(body string, payloadVal string) (string, bool, string, string) {
	type candidate struct {
		needle    string
		matchType string
	}

	candidates := []candidate{
		{payloadVal, "raw"},
	}

	if dec, err := url.QueryUnescape(payloadVal); err == nil && dec != payloadVal {
		candidates = append(candidates, candidate{dec, "url-decoded"})
	}

	htmlDec := HTMLEntityDecode(payloadVal)
	if htmlDec != payloadVal {
		candidates = append(candidates, candidate{htmlDec, "html-entity-decoded"})
	}

	htmlEnc := HTMLEntityEncode(payloadVal)
	if htmlEnc != payloadVal {
		candidates = append(candidates, candidate{htmlEnc, "html-entity-encoded"})
	}

	lowerBody := strings.ToLower(body)

	for _, c := range candidates {
		if strings.Contains(body, c.needle) {
			ev := s.ExtractEvidence(body, c.needle)
			ctx := s.DetermineContext(body, c.needle)
			return ev, true, ctx, c.matchType
		}
		lowerNeedle := strings.ToLower(c.needle)
		if strings.Contains(lowerBody, lowerNeedle) {
			idx := strings.Index(lowerBody, lowerNeedle)
			actual := body[idx : idx+len(lowerNeedle)]
			ev := s.ExtractEvidence(body, actual)
			ctx := s.DetermineContext(body, actual)
			return ev, true, ctx, c.matchType + "/case-insensitive"
		}
	}

	stripped := StripHTMLTags(payloadVal)
	if len(stripped) > 4 && stripped != payloadVal && strings.Contains(body, stripped) {
		ev := s.ExtractEvidence(body, stripped)
		ctx := s.DetermineContext(body, stripped)
		return ev, true, ctx, "partial-content"
	}

	return "", false, "", ""
}

func (s *Scanner) ExtractEvidence(body string, needle string) string {
	idx := strings.Index(body, needle)
	if idx == -1 {
		return "(not found)"
	}
	start := idx - 100
	end := idx + len(needle) + 100
	if start < 0 {
		start = 0
	}
	if end > len(body) {
		end = len(body)
	}
	snippet := strings.ReplaceAll(body[start:end], "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\r", "")
	snippet = strings.Join(strings.Fields(snippet), " ")
	return "..." + snippet + "..."
}

func (s *Scanner) DetermineContext(body string, needle string) string {
	idx := strings.Index(body, needle)
	if idx == -1 {
		return "unknown"
	}
	before := body[:idx]
	lastTag := strings.LastIndex(before, "<")
	lastClose := strings.LastIndex(before, ">")

	if lastTag == -1 || lastClose > lastTag {
		if strings.Contains(before[max(0, lastClose):], "=") {
			return "attribute-value-quoted"
		}
		return "text-node"
	}

	segment := strings.ToLower(before[lastTag:])

	if strings.HasPrefix(segment, "<script") {
		return "script-block"
	}
	if strings.HasPrefix(segment, "<style") {
		return "style-block"
	}
	if containsEventHandler(segment) {
		return "event-handler"
	}
	if strings.Contains(segment, "href=") || strings.Contains(segment, "src=") ||
		strings.Contains(segment, "action=") || strings.Contains(segment, "data=") ||
		strings.Contains(segment, "formaction=") {
		return "attribute-value-url"
	}
	if idx > 0 && (body[idx-1] == '"' || body[idx-1] == '\'') {
		return "attribute-value-quoted"
	}
	return "html-attribute"
}

func (s *Scanner) BuildPoCURL(rawURL string, param string, payloadVal string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + "?" + param + "=" + url.QueryEscape(payloadVal)
	}
	q := parsed.Query()
	q.Set(param, payloadVal)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func (s *Scanner) GetStats() ScanStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Stats
}

func (s *Scanner) GetSeverityBreakdown() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int)
	for _, r := range s.Results {
		out[logger.SeverityTitle(r.Severity)]++
	}
	return out
}

func HTMLEntityDecode(input string) string {
	return strings.NewReplacer(
		"&lt;", "<", "&gt;", ">", "&amp;", "&",
		"&quot;", "\"", "&#34;", "\"", "&#39;", "'",
		"&#x27;", "'", "&#x2F;", "/", "&#47;", "/",
		"&apos;", "'", "&#x3C;", "<", "&#x3E;", ">",
		"&#60;", "<", "&#62;", ">", "&#x22;", "\"",
		"&#x60;", "`", "&grave;", "`",
	).Replace(input)
}

func HTMLEntityEncode(input string) string {
	var sb strings.Builder
	for _, r := range input {
		switch r {
		case '<':
			sb.WriteString("&lt;")
		case '>':
			sb.WriteString("&gt;")
		case '"':
			sb.WriteString("&quot;")
		case '\'':
			sb.WriteString("&#39;")
		case '&':
			sb.WriteString("&amp;")
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func StripHTMLTags(input string) string {
	var sb strings.Builder
	inTag := false
	for _, r := range input {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag && !unicode.IsSpace(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
