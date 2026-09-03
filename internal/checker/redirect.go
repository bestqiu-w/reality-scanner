package checker

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HTTPCheckResult HTTP 检测结果
type HTTPCheckResult struct {
	Accessible    bool
	StatusCode    int
	FinalDomain   string
	IsRedirected  bool
	RedirectChain []string
	Headers       map[string]string
}

// CheckHTTP 跟踪重定向并获取 HTTP 状态与响应头
func CheckHTTP(ctx context.Context, domain string, timeout time.Duration) *HTTPCheckResult {
	const maxRedirects = 5
	const httpsScheme = "https://"

	result := &HTTPCheckResult{
		Accessible:    false,
		StatusCode:    0,
		FinalDomain:   domain,
		RedirectChain: []string{domain},
		Headers:       make(map[string]string),
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // 禁用自动重定向，由我们手动跟踪
		},
	}

	currentURL := httpsScheme + domain

	for i := 0; i < maxRedirects; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
		if err != nil {
			break
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			break
		}

		result.Accessible = true
		result.StatusCode = resp.StatusCode

		// 保存 HTTP 响应头
		for k, v := range resp.Header {
			if len(v) > 0 {
				result.Headers[k] = v[0]
			}
		}

		// 检查 3xx 重定向
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			loc := resp.Header.Get("Location")
			resp.Body.Close()
			if loc != "" {
				if strings.HasPrefix(loc, "/") {
					u, _ := url.Parse(currentURL)
					loc = u.Scheme + "://" + u.Host + loc
				} else if !strings.HasPrefix(loc, "http") {
					loc = httpsScheme + loc
				}

				parsedLoc, err := url.Parse(loc)
				if err == nil {
					newHost := parsedLoc.Hostname()
					if newHost != "" && newHost != domain {
						result.RedirectChain = append(result.RedirectChain, newHost)
						result.IsRedirected = true
						currentURL = loc
						domain = newHost
						continue
					}
				}
			}
		}

		resp.Body.Close()
		break
	}

	u, err := url.Parse(currentURL)
	if err == nil && u.Hostname() != "" {
		result.FinalDomain = u.Hostname()
	}

	return result
}
