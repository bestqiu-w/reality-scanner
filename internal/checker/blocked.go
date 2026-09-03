package checker

import (
	"bufio"
	"strings"
	"sync"

	"reality-scanner/internal/assets"
)

// BlockedDetector GFWList 阻断检测器
type BlockedDetector struct {
	rules map[string]bool
	once  sync.Once
}

var defaultBlockedDetector = &BlockedDetector{
	rules: make(map[string]bool),
}

// GetBlockedDetector 单例获取
func GetBlockedDetector() *BlockedDetector {
	defaultBlockedDetector.once.Do(func() {
		defaultBlockedDetector.loadRules()
	})
	return defaultBlockedDetector
}

func (bd *BlockedDetector) loadRules() {
	r, err := assets.GetGFWListReader()
	if err != nil {
		return
	}
	defer r.Close()

	scanner := bufio.NewScanner(r)
	inPayload := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "payload:" {
			inPayload = true
			continue
		}
		if !inPayload {
			continue
		}

		if strings.HasPrefix(line, "- '") && strings.HasSuffix(line, "'") {
			domain := strings.TrimPrefix(line, "- '")
			domain = strings.TrimSuffix(domain, "'")
			domain = strings.TrimPrefix(domain, "+.")
			if domain != "" {
				bd.rules[strings.ToLower(domain)] = true
			}
		}
	}
}

// IsBlocked 检查域名是否被 GFW 封锁
func (bd *BlockedDetector) IsBlocked(domain string) (bool, string) {
	domain = strings.ToLower(domain)
	if bd.rules[domain] {
		return true, "GFWList 黑名单命中"
	}

	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if bd.rules[parent] {
			return true, "GFWList 主域命中: " + parent
		}
	}

	return false, ""
}
