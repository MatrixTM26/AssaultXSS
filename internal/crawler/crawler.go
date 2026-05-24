package crawler

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"assaultxss/internal/logger"
	"golang.org/x/net/html"
)

type Crawler struct {
	BaseURL *url.URL
	Depth   int
	Timeout int
	Threads int
	Log     *logger.Logger
	Visited map[string]bool
	mu      sync.Mutex
	Client  *http.Client
}

type PageResult struct {
	URL    string
	Params map[string][]string
	Forms  []FormData
}

type FormData struct {
	Action string
	Method string
	Inputs []InputField
}

type InputField struct {
	Name  string
	Type  string
	Value string
}

func NewCrawler(baseURL string, depth int, timeout int, threads int, log *logger.Logger) (*Crawler, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}
	return &Crawler{
		BaseURL: parsed,
		Depth:   depth,
		Timeout: timeout,
		Threads: threads,
		Log:     log,
		Visited: make(map[string]bool),
		Client: &http.Client{
			Timeout: time.Duration(timeout) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 8 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}, nil
}

type workItem struct {
	pageURL string
	depth   int
}

func (c *Crawler) Crawl(startURL string) []PageResult {
	var results []PageResult
	var resultsMu sync.Mutex

	queue := make(chan workItem, 512)
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.Threads)

	enqueue := func(u string, d int) {
		normalized := NormalizeURL(u)
		if normalized == "" {
			return
		}
		c.mu.Lock()
		if c.Visited[normalized] {
			c.mu.Unlock()
			return
		}
		c.Visited[normalized] = true
		c.mu.Unlock()
		wg.Add(1)
		queue <- workItem{pageURL: normalized, depth: d}
	}

	enqueue(startURL, 0)

	go func() {
		wg.Wait()
		close(queue)
	}()

	for item := range queue {
		go func(it workItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			c.Log.Debug(fmt.Sprintf("Crawling [depth=%d]: %s", it.depth, it.pageURL))
			page, links, jsLinks := c.FetchPage(it.pageURL)

			if page != nil {
				resultsMu.Lock()
				results = append(results, *page)
				resultsMu.Unlock()
			}

			if it.depth < c.Depth {
				allLinks := append(links, jsLinks...)
				for _, link := range allLinks {
					if c.IsSameHost(link) {
						enqueue(link, it.depth+1)
					}
				}
			}
		}(item)
	}

	return results
}

func (c *Crawler) FetchPage(rawURL string) (*PageResult, []string, []string) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		c.Log.Debug(fmt.Sprintf("Fetch failed: %s → %v", rawURL, err))
		return nil, nil, nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10; Mobile) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := c.Client.Do(req)
	if err != nil {
		c.Log.Debug(fmt.Sprintf("Fetch failed: %s → %v", rawURL, err))
		return nil, nil, nil
	}
	defer resp.Body.Close()

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, nil
	}

	params := make(map[string][]string)
	for k, v := range parsed.Query() {
		params[k] = v
		c.Log.ParamFound(k, rawURL)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "html") && !strings.Contains(contentType, "text") && contentType != "" {
		return &PageResult{URL: rawURL, Params: params}, nil, nil
	}

	doc, err := html.Parse(resp.Body)
	if err != nil {
		return &PageResult{URL: rawURL, Params: params}, nil, nil
	}

	var links []string
	var jsLinks []string
	var forms []FormData

	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			switch tag {
			case "a":
				href := AttrVal(n, "href")
				if href != "" {
					resolved := c.ResolveURL(rawURL, href)
					if resolved != "" {
						if HasQueryParams(resolved) {
							links = append([]string{resolved}, links...)
						} else {
							links = append(links, resolved)
						}
					}
				}

			case "form":
				form := c.ParseForm(n, rawURL)
				forms = append(forms, form)
				for k := range form.BuildParams() {
					params[k] = []string{""}
					c.Log.ParamFound(k, rawURL)
				}

			case "input", "textarea", "select", "button":
				name := AttrVal(n, "name")
				if name != "" {
					params[name] = []string{""}
					c.Log.ParamFound(name, rawURL)
				}

			case "script":
				src := AttrVal(n, "src")
				if src != "" {
					resolved := c.ResolveURL(rawURL, src)
					if resolved != "" && c.IsSameHost(resolved) {
						jsLinks = append(jsLinks, resolved)
					}
				}
				if n.FirstChild != nil && n.FirstChild.Type == html.TextNode {
					extracted := ExtractURLsFromJS(n.FirstChild.Data, rawURL, c)
					links = append(links, extracted...)
				}

			case "link":
				rel := AttrVal(n, "rel")
				href := AttrVal(n, "href")
				if href != "" && (rel == "alternate" || rel == "") {
					resolved := c.ResolveURL(rawURL, href)
					if resolved != "" && c.IsSameHost(resolved) {
						links = append(links, resolved)
					}
				}

			case "meta":
				httpEquiv := strings.ToLower(AttrVal(n, "http-equiv"))
				if httpEquiv == "refresh" {
					content := AttrVal(n, "content")
					if idx := strings.Index(strings.ToLower(content), "url="); idx != -1 {
						refreshURL := content[idx+4:]
						resolved := c.ResolveURL(rawURL, strings.Trim(refreshURL, "'\""))
						if resolved != "" {
							links = append(links, resolved)
						}
					}
				}
			}

			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "action", "formaction":
					resolved := c.ResolveURL(rawURL, attr.Val)
					if resolved != "" && c.IsSameHost(resolved) {
						links = append(links, resolved)
					}
				case "data-url", "data-href", "data-src", "data-action":
					resolved := c.ResolveURL(rawURL, attr.Val)
					if resolved != "" && c.IsSameHost(resolved) && HasQueryParams(resolved) {
						links = append(links, resolved)
					}
				}
			}
		}

		for child := n.FirstChild; child != nil; child = child.NextSibling {
			traverse(child)
		}
	}
	traverse(doc)

	return &PageResult{URL: rawURL, Params: params, Forms: forms}, links, jsLinks
}

func ExtractURLsFromJS(jsCode string, baseURL string, c *Crawler) []string {
	var found []string
	patterns := []string{`fetch('`, `fetch("`, `axios.get('`, `axios.get("`,
		`location.href='`, `location.href="`, `window.location='`}
	for _, pat := range patterns {
		idx := 0
		for {
			pos := strings.Index(jsCode[idx:], pat)
			if pos == -1 {
				break
			}
			start := idx + pos + len(pat)
			end := strings.IndexAny(jsCode[start:], "'\"")
			if end == -1 {
				break
			}
			candidate := jsCode[start : start+end]
			if strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "http") {
				resolved := c.ResolveURL(baseURL, candidate)
				if resolved != "" && c.IsSameHost(resolved) {
					found = append(found, resolved)
				}
			}
			idx = start + end + 1
		}
	}
	return found
}

func (c *Crawler) ParseForm(n *html.Node, baseURL string) FormData {
	form := FormData{Method: "GET", Action: baseURL}
	for _, attr := range n.Attr {
		switch strings.ToLower(attr.Key) {
		case "action":
			if attr.Val != "" {
				resolved := c.ResolveURL(baseURL, attr.Val)
				if resolved != "" {
					form.Action = resolved
				}
			}
		case "method":
			form.Method = strings.ToUpper(attr.Val)
		}
	}
	var walkInputs func(*html.Node)
	walkInputs = func(n *html.Node) {
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			switch tag {
			case "input", "textarea", "select":
				field := InputField{
					Name:  AttrVal(n, "name"),
					Type:  AttrVal(n, "type"),
					Value: AttrVal(n, "value"),
				}
				if field.Name != "" {
					form.Inputs = append(form.Inputs, field)
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walkInputs(child)
		}
	}
	walkInputs(n)
	return form
}

func (f *FormData) BuildParams() map[string]string {
	params := make(map[string]string)
	for _, input := range f.Inputs {
		if input.Name != "" {
			skip := strings.EqualFold(input.Type, "submit") ||
				strings.EqualFold(input.Type, "button") ||
				strings.EqualFold(input.Type, "image") ||
				strings.EqualFold(input.Type, "reset")
			if !skip {
				params[input.Name] = input.Value
			}
		}
	}
	return params
}

func AttrVal(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if strings.ToLower(attr.Key) == key {
			return attr.Val
		}
	}
	return ""
}

func HasQueryParams(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return len(parsed.RawQuery) > 0
}

func NormalizeURL(rawURL string) string {
	if strings.HasPrefix(rawURL, "javascript:") ||
		strings.HasPrefix(rawURL, "mailto:") ||
		strings.HasPrefix(rawURL, "tel:") ||
		strings.HasPrefix(rawURL, "data:") {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	parsed.Fragment = ""
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	return parsed.String()
}

func (c *Crawler) ResolveURL(base string, href string) string {
	href = strings.TrimSpace(href)
	if href == "" || strings.HasPrefix(href, "javascript:") ||
		strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "#") ||
		strings.HasPrefix(href, "tel:") || strings.HasPrefix(href, "data:") {
		return ""
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}
	resolved := baseURL.ResolveReference(ref)
	resolved.Fragment = ""
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return ""
	}
	return resolved.String()
}

func (c *Crawler) IsSameHost(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(parsed.Host, c.BaseURL.Host)
}
