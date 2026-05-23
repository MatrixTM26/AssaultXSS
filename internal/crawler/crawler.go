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
	BaseURL    *url.URL
	Depth      int
	Timeout    int
	Threads    int
	Log        *logger.Logger
	Visited    map[string]bool
	mu         sync.Mutex
	Client     *http.Client
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
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}, nil
}

func (c *Crawler) Crawl(startURL string) []PageResult {
	var results []PageResult
	var mu sync.Mutex
	type workItem struct {
		url   string
		depth int
	}
	queue := make(chan workItem, 256)
	var wg sync.WaitGroup
	sem := make(chan struct{}, c.Threads)
	queue <- workItem{url: startURL, depth: 0}
	go func() {
		wg.Wait()
		close(queue)
	}()
	initialItem := <-queue
	wg.Add(1)
	go func(item workItem) {
		defer wg.Done()
		sem <- struct{}{}
		defer func() { <-sem }()
		c.mu.Lock()
		if c.Visited[item.url] {
			c.mu.Unlock()
			return
		}
		c.Visited[item.url] = true
		c.mu.Unlock()
		c.Log.Debug(fmt.Sprintf("Crawling [depth=%d]: %s", item.depth, item.url))
		page, links := c.FetchPage(item.url)
		if page != nil {
			mu.Lock()
			results = append(results, *page)
			mu.Unlock()
		}
		if item.depth < c.Depth {
			for _, link := range links {
				c.mu.Lock()
				seen := c.Visited[link]
				c.mu.Unlock()
				if !seen && c.IsSameHost(link) {
					wg.Add(1)
					go func(u string, d int) {
						defer wg.Done()
						sem <- struct{}{}
						defer func() { <-sem }()
						c.mu.Lock()
						if c.Visited[u] {
							c.mu.Unlock()
							return
						}
						c.Visited[u] = true
						c.mu.Unlock()
						c.Log.Debug(fmt.Sprintf("Crawling [depth=%d]: %s", d, u))
						p, subLinks := c.FetchPage(u)
						if p != nil {
							mu.Lock()
							results = append(results, *p)
							mu.Unlock()
						}
						if d < c.Depth {
							for _, sl := range subLinks {
								c.mu.Lock()
								seenSub := c.Visited[sl]
								c.mu.Unlock()
								if !seenSub && c.IsSameHost(sl) {
									queue <- workItem{url: sl, depth: d + 1}
								}
							}
						}
					}(link, item.depth+1)
				}
			}
		}
	}(initialItem)
	for item := range queue {
		wg.Add(1)
		go func(i workItem) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			c.mu.Lock()
			if c.Visited[i.url] {
				c.mu.Unlock()
				return
			}
			c.Visited[i.url] = true
			c.mu.Unlock()
			page, _ := c.FetchPage(i.url)
			if page != nil {
				mu.Lock()
				results = append(results, *page)
				mu.Unlock()
			}
		}(item)
	}
	return results
}

func (c *Crawler) FetchPage(rawURL string) (*PageResult, []string) {
	resp, err := c.Client.Get(rawURL)
	if err != nil {
		c.Log.Debug(fmt.Sprintf("Fetch failed: %s → %v", rawURL, err))
		return nil, nil
	}
	defer resp.Body.Close()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil
	}
	params := make(map[string][]string)
	for k, v := range parsed.Query() {
		params[k] = v
		c.Log.ParamFound(k, rawURL)
	}
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return nil, nil
	}
	var links []string
	var forms []FormData
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "a":
				for _, attr := range n.Attr {
					if attr.Key == "href" {
						resolved := c.ResolveURL(rawURL, attr.Val)
						if resolved != "" {
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
			case "input", "textarea", "select":
				for _, attr := range n.Attr {
					if attr.Key == "name" && attr.Val != "" {
						params[attr.Val] = []string{""}
						c.Log.ParamFound(attr.Val, rawURL)
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			traverse(child)
		}
	}
	traverse(doc)
	page := &PageResult{
		URL:    rawURL,
		Params: params,
		Forms:  forms,
	}
	return page, links
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
			switch strings.ToLower(n.Data) {
			case "input", "textarea", "select":
				field := InputField{}
				for _, attr := range n.Attr {
					switch attr.Key {
					case "name":
						field.Name = attr.Val
					case "type":
						field.Type = attr.Val
					case "value":
						field.Value = attr.Val
					}
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
			params[input.Name] = input.Value
		}
	}
	return params
}

func (c *Crawler) ResolveURL(base string, href string) string {
	if strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") || strings.HasPrefix(href, "#") {
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
	return resolved.String()
}

func (c *Crawler) IsSameHost(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return parsed.Host == c.BaseURL.Host
}
