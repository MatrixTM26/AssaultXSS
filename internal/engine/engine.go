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
)

const (
	ansiReset  = "\033[0m"
	ansiGray   = "\033[90m"
	ansiRed    = "\033[31;1m"
	ansiGreen  = "\033[32;1m"
	ansiYellow = "\033[33;1m"
	ansiCyan   = "\033[36;1m"
	ansiBlue   = "\033[34;1m"
	ansiWhite  = "\033[97;1m"
)

const ProbeMarker = "xAssaultx31337"

type ReflectionResult struct {
	Found        bool
	MatchType    string
	NeedleUsed   string
	ReflectCount int
	Evidence     string
	Context      string
	QuoteContext  QuoteCtx
	Sanitized    bool
	SanitizeNote string
}

type QuoteCtx int

const (
	QuoteNone     QuoteCtx = iota
	QuoteDouble
	QuoteSingle
	QuoteUnquoted
)

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

// ProgressBar renders to stderr so it never mixes with stdout log lines
type ProgressBar struct {
	Total     int64
	Current   int64
	Width     int
	StartTime time.Time
	mu        sync.Mutex
	finished  bool
}

func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{
		Total:     int64(total),
		Width:     36,
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
		rem := time.Duration(float64(elapsed) / pct * (1 - pct))
		if rem > time.Hour {
			eta = ">1h"
		} else {
			eta = rem.Round(time.Second).String()
		}
	} else {
		eta = "---"
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", pb.Width-filled)
	fmt.Fprintf(os.Stderr, "\r\033[2K%s[%s%s%s] %s%.1f%%%s  %d/%d  ETA:%s",
		ansiGray, ansiCyan, bar, ansiGray,
		ansiCyan, pct*100, ansiReset,
		current, total, eta,
	)
}

func (pb *ProgressBar) Finish() {
	pb.mu.Lock()
	pb.finished = true
	pb.mu.Unlock()
	current := pb.Total
	bar := strings.Repeat("█", pb.Width)
	elapsed := time.Since(pb.StartTime).Round(time.Millisecond)
	fmt.Fprintf(os.Stderr, "\r\033[2K%s[%s%s%s] %s100.0%%%s  %d/%d  done:%s\n",
		ansiGray, ansiGreen, bar, ansiGray,
		ansiGreen, ansiReset,
		current, current, elapsed,
	)
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
	s.Log.Info(fmt.Sprintf("loaded %d payloads for level %d (%s)", len(payloads), s.Cfg.Level, payload.LevelName(s.Cfg.Level)))

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
		s.Log.Error(fmt.Sprintf("crawler init failed: %v", err))
		return
	}

	s.Log.Info(fmt.Sprintf("crawling with depth=%d...", s.Cfg.Depth))
	pages := cr.Crawl(rawURL)

	// Always preserve the original URL with its own params
	origParsed, origErr := url.Parse(rawURL)
	if origErr == nil {
		origParams := origParsed.Query()
		if len(origParams) > 0 {
			alreadyPresent := false
			for _, pg := range pages {
				if pg.URL == rawURL {
					alreadyPresent = true
					break
				}
			}
			if !alreadyPresent {
				params := make(map[string][]string)
				for k, v := range origParams {
					params[k] = append([]string{}, v...)
				}
				pages = append([]crawler.PageResult{{URL: rawURL, Params: params}}, pages...)
				s.Log.Debug(fmt.Sprintf("re-added original url: %s", rawURL))
			}
		}
	}

	if len(pages) == 0 {
		s.Log.Warning("no pages found — skipping")
		return
	}

	s.Log.Info(fmt.Sprintf("discovered %d page(s) — building test queue...", len(pages)))

	type TestJob struct {
		PageURL string
		Param   string
		IsForm  bool
		Form    crawler.FormData
	}

	var jobs []TestJob
	seenJobs := make(map[string]bool)

	for _, page := range pages {
		urlParams := page.Params
		if s.Cfg.Param != "" {
			urlParams = map[string][]string{s.Cfg.Param: {""}}
		}
		for param := range urlParams {
			key := "url|" + page.URL + "|" + param
			if seenJobs[key] {
				continue
			}
			seenJobs[key] = true
			jobs = append(jobs, TestJob{PageURL: page.URL, Param: param})
		}
		for _, form := range page.Forms {
			for param := range form.BuildParams() {
				if s.Cfg.Param != "" && param != s.Cfg.Param {
					continue
				}
				key := "form|" + form.Method + "|" + form.Action + "|" + param
				if seenJobs[key] {
					continue
				}
				seenJobs[key] = true
				jobs = append(jobs, TestJob{Param: param, IsForm: true, Form: form})
			}
		}
	}

	if len(jobs) == 0 {
		s.Log.Warning("no parameters found to test")
		s.Log.Warning("tips: -d 3 for deeper crawl, -p <param> to force a param, -V for debug")
		return
	}

	total := len(jobs) * len(payloads)
	s.Log.Info(fmt.Sprintf("queued %d param(s) × %d payloads = %d requests", len(jobs), len(payloads), total))
	fmt.Fprintln(os.Stderr)

	bar := NewProgressBar(total)
	s.Bar = bar
	s.Log.SetBarActive(true)

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
	s.Log.SetBarActive(false)
	bar.Finish()
	fmt.Fprintln(os.Stderr)
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
		baseQuery[k] = append([]string{}, v...)
	}

	for _, p := range payloads {
		s.mu.Lock()
		s.Stats.PayloadsSent++
		s.mu.Unlock()

		cloned := *baseParsed
		q := url.Values{}
		for k, v := range baseQuery {
			q[k] = v
		}
		q.Set(param, p.Value)
		cloned.RawQuery = q.Encode()
		testURL := cloned.String()

		_, body, statusCode, err := s.DoRequest("GET", testURL, nil)
		if err != nil {
			s.mu.Lock()
			s.Stats.ErrorCount++
			s.mu.Unlock()
			bar.Increment()
			s.Log.PayloadResult(bar, param, p.Value, "ERR", false)
			continue
		}

		result, found := s.AnalyzeResponse(body, p, param, testURL, statusCode)
		if found {
			s.mu.Lock()
			s.Stats.VulnsFound++
			s.Results = append(s.Results, result)
			s.mu.Unlock()
			s.Log.VulnFound(result)
		} else {
			rr := CheckReflection(body, p.Value)
			tag := "NO-REFLECT"
			if rr.Found && rr.ReflectCount > 0 {
				if rr.Sanitized {
					tag = "SANITIZED"
				} else {
					tag = "REFLECT"
				}
			}
			s.Log.PayloadResult(bar, param, p.Value, tag, false)
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

		_, respBody, statusCode, err := s.DoRequest(method, targetURL, body)
		if err != nil {
			s.mu.Lock()
			s.Stats.ErrorCount++
			s.mu.Unlock()
			bar.Increment()
			s.Log.PayloadResult(bar, param, p.Value, "ERR", false)
			continue
		}

		pocURL := targetURL
		if method == "POST" {
			if parsed, perr := url.Parse(form.Action); perr == nil {
				parsed.RawQuery = formData.Encode()
				pocURL = parsed.String()
			}
		}

		result, found := s.AnalyzeResponse(respBody, p, param, pocURL, statusCode)
		if found {
			s.mu.Lock()
			s.Stats.VulnsFound++
			s.Results = append(s.Results, result)
			s.mu.Unlock()
			s.Log.VulnFound(result)
		} else {
			rr := CheckReflection(respBody, p.Value)
			tag := "NO-REFLECT"
			if rr.Found && rr.ReflectCount > 0 {
				tag = "REFLECT"
			}
			s.Log.PayloadResult(bar, param, p.Value, tag, false)
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

func (s *Scanner) AnalyzeResponse(body string, p payload.PayloadEntry, param string, testURL string, statusCode int) (logger.VulnResult, bool) {
	rr := CheckReflection(body, p.Value)

	if !rr.Found || rr.ReflectCount == 0 {
		return logger.VulnResult{}, false
	}
	// Only skip if clearly sanitized (HTML-entity-encoded variant returned)
	if rr.Sanitized && rr.MatchType == "html-entity-encoded" {
		return logger.VulnResult{}, false
	}

	executable := CheckExecutable(body, p.Value, rr.Context)
	breakout := CheckAttributeBreakout(rr)
	sev, score := ScoreVulnerability(p, rr, breakout, executable)

	// Lower minimum threshold — text-node reflect is still LOW, not dropped
	if sev == logger.SeverityInfo && score < 10 {
		return logger.VulnResult{}, false
	}
	// Force minimum LOW for any valid raw reflection
	if sev == logger.SeverityInfo && rr.MatchType == "raw" && rr.ReflectCount > 0 {
		sev = logger.SeverityLow
		if score < 20 {
			score = 20
		}
	}

	pocURL := BuildPoCURL(testURL, param, p.Value)
	return logger.VulnResult{
		URL:          testURL,
		Parameter:    param,
		Payload:      p.Value,
		XSSType:      p.XSSType,
		PayloadLevel: p.Level,
		LevelName:    payload.LevelName(p.Level),
		PoCURL:       pocURL,
		Evidence:     rr.Evidence,
		Timestamp:    time.Now().Format(time.RFC3339),
		StatusCode:   statusCode,
		ResponseSize: len(body),
		ReflectCount: rr.ReflectCount,
		Context:      rr.Context,
		MatchType:    rr.MatchType,
		Severity:     sev,
		SeverityScore: score,
		Executable:   executable,
	}, true
}

func CheckReflection(body string, payloadVal string) ReflectionResult {
	type candidate struct {
		needle    string
		matchType string
	}

	candidates := []candidate{{payloadVal, "raw"}}

	if dec, err := url.QueryUnescape(payloadVal); err == nil && dec != payloadVal {
		candidates = append(candidates, candidate{dec, "url-decoded"})
	}
	if htmlDec := HTMLEntityDecode(payloadVal); htmlDec != payloadVal {
		candidates = append(candidates, candidate{htmlDec, "html-entity-decoded"})
	}

	lowerBody := strings.ToLower(body)

	for _, c := range candidates {
		if strings.Contains(body, c.needle) {
			count := strings.Count(body, c.needle)
			evidence := ExtractEvidence(body, c.needle)
			ctx, qctx := DetermineContext(body, c.needle)
			sanitized, note := IsSanitizedInContext(body, c.needle, ctx)
			return ReflectionResult{true, c.matchType, c.needle, count, evidence, ctx, qctx, sanitized, note}
		}
		lower := strings.ToLower(c.needle)
		if strings.Contains(lowerBody, lower) {
			idx := strings.Index(lowerBody, lower)
			actual := body[idx : idx+len(lower)]
			count := strings.Count(lowerBody, lower)
			evidence := ExtractEvidence(body, actual)
			ctx, qctx := DetermineContext(body, actual)
			sanitized, note := IsSanitizedInContext(body, actual, ctx)
			return ReflectionResult{true, c.matchType + "/case-insensitive", actual, count, evidence, ctx, qctx, sanitized, note}
		}
	}

	// Check HTML-entity-encoded (server encoded our payload)
	htmlEnc := HTMLEntityEncode(payloadVal)
	if htmlEnc != payloadVal && strings.Contains(body, htmlEnc) {
		count := strings.Count(body, htmlEnc)
		evidence := ExtractEvidence(body, htmlEnc)
		ctx, qctx := DetermineContext(body, htmlEnc)
		return ReflectionResult{true, "html-entity-encoded", htmlEnc, count, evidence, ctx, qctx, true, "server encoded payload — not directly executable"}
	}

	return ReflectionResult{Found: false}
}

func IsSanitizedInContext(body string, needle string, ctx string) (bool, string) {
	idx := strings.Index(body, needle)
	if idx == -1 {
		return false, ""
	}
	win := 40
	start := idx - win
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + win
	if end > len(body) {
		end = len(body)
	}
	surr := body[start:end]

	// If angle brackets in payload but they appear encoded in surrounding — sanitized
	if strings.ContainsAny(needle, "<>") {
		if strings.Contains(surr, "&lt;") || strings.Contains(surr, "&gt;") ||
			strings.Contains(surr, "&#60;") || strings.Contains(surr, "&#62;") ||
			strings.Contains(surr, "&#x3C;") || strings.Contains(surr, "&#x3E;") {
			return true, "angle brackets HTML-encoded in response"
		}
	}

	// Quotes encoded inside attribute context
	if (ctx == "attribute-value-quoted" || ctx == "attribute-value-url") && strings.ContainsAny(needle, "\"'") {
		if strings.Contains(surr, "&quot;") || strings.Contains(surr, "&#34;") ||
			strings.Contains(surr, "&#x22;") || strings.Contains(surr, "&#39;") ||
			strings.Contains(surr, "&#x27;") {
			return true, "quotes HTML-encoded inside attribute"
		}
	}
	return false, ""
}

func CheckAttributeBreakout(rr ReflectionResult) bool {
	if rr.Context != "attribute-value-quoted" && rr.Context != "html-attribute" {
		return true
	}
	if rr.Sanitized {
		return false
	}
	switch rr.QuoteContext {
	case QuoteDouble:
		return strings.Contains(rr.NeedleUsed, "\"") || strings.Contains(rr.NeedleUsed, ">")
	case QuoteSingle:
		return strings.Contains(rr.NeedleUsed, "'") || strings.Contains(rr.NeedleUsed, ">")
	case QuoteUnquoted:
		return strings.ContainsAny(rr.NeedleUsed, " \t\n>")
	}
	return false
}

func CheckExecutable(body string, payloadVal string, ctx string) bool {
	// text-node context: browser renders as text, not HTML — not executable
	if ctx == "text-node" || ctx == "style-block" {
		return false
	}

	execPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<script[\s>]`),
		regexp.MustCompile(`(?i)<script$`),
		regexp.MustCompile(`(?i)\son\w+\s*=`),
		regexp.MustCompile(`(?i)javascript\s*:`),
		regexp.MustCompile(`(?i)<svg[\s/>]`),
		regexp.MustCompile(`(?i)<img[^>]+onerror`),
		regexp.MustCompile(`(?i)<iframe[\s>]`),
		regexp.MustCompile(`(?i)<details[^>]+ontoggle`),
		regexp.MustCompile(`(?i)<input[^>]+onfocus`),
		regexp.MustCompile(`(?i)<video[^>]+onerror`),
		regexp.MustCompile(`(?i)<audio[^>]+onerror`),
		regexp.MustCompile(`(?i)<body[^>]+on\w+`),
	}

	lp := strings.ToLower(payloadVal)
	lBody := strings.ToLower(body)

	for _, pat := range execPatterns {
		if !pat.MatchString(lp) {
			continue
		}
		// Confirm the actual reflected string in body also matches the pattern
		prefix := lp
		if len(prefix) > 14 {
			prefix = prefix[:14]
		}
		idx := strings.Index(lBody, prefix)
		if idx == -1 {
			continue
		}
		end := idx + len(payloadVal) + 10
		if end > len(lBody) {
			end = len(lBody)
		}
		if pat.MatchString(lBody[idx:end]) {
			return true
		}
	}
	return false
}

func ScoreVulnerability(p payload.PayloadEntry, rr ReflectionResult, breakout bool, executable bool) (logger.SeverityLevel, int) {
	if rr.ReflectCount == 0 {
		return logger.SeverityInfo, 0
	}

	score := 0

	// Match type score
	switch {
	case rr.MatchType == "raw":
		score += 40
	case rr.MatchType == "url-decoded":
		score += 35
	case strings.HasSuffix(rr.MatchType, "case-insensitive"):
		score += 25
	case rr.MatchType == "html-entity-decoded":
		score += 18
	default:
		score += 5
	}

	// Context score — executable context gets high bonus
	switch rr.Context {
	case "script-block":
		score += 35
	case "event-handler":
		score += 32
	case "attribute-value-url":
		score += 22
	case "html-attribute":
		if breakout {
			score += 20
		} else {
			score += 8
		}
	case "attribute-value-quoted":
		if breakout {
			score += 16
		} else {
			score += 3
		}
	case "text-node":
		score += 5
	default:
		score += 10
	}

	if executable {
		score += 22
	}
	if breakout {
		score += 5
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

func DetermineContext(body string, needle string) (string, QuoteCtx) {
	idx := strings.Index(body, needle)
	if idx == -1 {
		return "unknown", QuoteNone
	}
	before := body[:idx]
	lastTag := strings.LastIndex(before, "<")
	lastClose := strings.LastIndex(before, ">")

	if lastTag == -1 || lastClose > lastTag {
		afterClose := before
		if lastClose >= 0 {
			afterClose = before[lastClose:]
		}
		if strings.Contains(afterClose, "=") {
			return "attribute-value-quoted", detectQuoteContext(before)
		}
		return "text-node", QuoteNone
	}

	seg := strings.ToLower(before[lastTag:])

	if strings.HasPrefix(seg, "<script") {
		return "script-block", QuoteNone
	}
	if strings.HasPrefix(seg, "<style") {
		return "style-block", QuoteNone
	}
	if matched, _ := regexp.MatchString(`\bon\w+\s*=`, seg); matched {
		return "event-handler", QuoteNone
	}
	for _, attr := range []string{"href=", "src=", "action=", "data=", "formaction=", "content="} {
		if strings.Contains(seg, attr) {
			return "attribute-value-url", detectQuoteContext(before)
		}
	}
	qctx := detectQuoteContext(before)
	if qctx != QuoteNone {
		return "attribute-value-quoted", qctx
	}
	return "html-attribute", QuoteUnquoted
}

func detectQuoteContext(before string) QuoteCtx {
	lastEq := strings.LastIndex(before, "=")
	if lastEq == -1 {
		return QuoteNone
	}
	rest := strings.TrimSpace(before[lastEq+1:])
	if strings.HasPrefix(rest, "\"") {
		return QuoteDouble
	}
	if strings.HasPrefix(rest, "'") {
		return QuoteSingle
	}
	if len(rest) > 0 {
		return QuoteUnquoted
	}
	return QuoteNone
}

func ExtractEvidence(body string, needle string) string {
	idx := strings.Index(body, needle)
	if idx == -1 {
		return "(not found)"
	}
	start := idx - 80
	end := idx + len(needle) + 80
	if start < 0 {
		start = 0
	}
	if end > len(body) {
		end = len(body)
	}
	s := strings.Join(strings.Fields(strings.ReplaceAll(body[start:end], "\r", "")), " ")
	return "..." + s + "..."
}

func BuildPoCURL(rawURL string, param string, payloadVal string) string {
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
		} else if r == '>' {
			inTag = false
		} else if !inTag && !unicode.IsSpace(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
