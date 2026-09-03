package checker

import (
	"bufio"
	"strings"
	"sync"

	"reality-scanner/internal/assets"
)

// HotWebsiteDetector 热门网站检测器
type HotWebsiteDetector struct {
	hotWebsites map[string]bool
	once        sync.Once
}

var defaultHotDetector = &HotWebsiteDetector{
	hotWebsites: make(map[string]bool),
}

// GetHotDetector 单例获取
func GetHotDetector() *HotWebsiteDetector {
	defaultHotDetector.once.Do(func() {
		defaultHotDetector.loadList()
	})
	return defaultHotDetector
}

func (hd *HotWebsiteDetector) loadList() {
	r, err := assets.GetHotWebsitesReader()
	if err != nil {
		return
	}
	defer r.Close()

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			clean := strings.ToLower(line)
			hd.hotWebsites[clean] = true
			if strings.HasPrefix(clean, "*.") {
				hd.hotWebsites[strings.TrimPrefix(clean, "*.")] = true
			}
		}
	}
}

// IsHotWebsite 判断是否属于热门大厂网站（如 apple.com / microsoft.com）
func (hd *HotWebsiteDetector) IsHotWebsite(domain string) bool {
	domain = strings.ToLower(domain)
	if hd.hotWebsites[domain] {
		return true
	}

	// 匹配子域名
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if hd.hotWebsites[parent] || hd.hotWebsites["*."+parent] {
			return true
		}
	}

	return false
}
