package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"reality-scanner/internal/model"
)

// ReadCandidatesFromCSV 从 CSV 文件智能读取候选域名与关联 IP（彻底修复 BUG-01）
func ReadCandidatesFromCSV(filePath string) ([]model.Candidate, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("无法打开 CSV 文件: %w", err)
	}
	defer f.Close()

	return ParseCSV(f)
}

// ParseCSV 动态解析 CSV 内容，自适应各种表头格式
func ParseCSV(r io.Reader) ([]model.Candidate, error) {
	reader := csv.NewReader(r)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("解析 CSV 失败: %w", err)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("CSV 文件为空")
	}

	// 1. 尝试从首行表头匹配列索引
	domainColIdx := -1
	ipColIdx := -1

	header := records[0]
	headerMap := make(map[string]int)
	for i, col := range header {
		headerMap[strings.ToUpper(strings.TrimSpace(col))] = i
	}

	// 匹配域名列
	domainCandidates := []string{"CERT_DOMAIN", "DOMAIN", "TARGET_DOMAIN", "HOST", "CERTDOMAIN"}
	for _, name := range domainCandidates {
		if idx, ok := headerMap[name]; ok {
			domainColIdx = idx
			break
		}
	}

	// 匹配 IP 列
	ipCandidates := []string{"IP", "TARGET_IP", "HOST_IP", "ORIGIN", "SERVER_IP"}
	for _, name := range ipCandidates {
		if idx, ok := headerMap[name]; ok {
			ipColIdx = idx
			break
		}
	}

	startRow := 1

	// 如果首行没有匹配到表头，可能是无表头文件或已知固定格式
	if domainColIdx == -1 {
		colCount := len(records[0])
		if colCount == 11 {
			// RealiTLScanner-main 11列格式：
			// IP,ORIGIN,TLS,ALPN,CURVE,CERT_LENGTH,CERT_SIGNATURE,CERT_PUBLICKEY,CERT_DOMAIN,CERT_ISSUER,GEO_CODE
			domainColIdx = 8
			ipColIdx = 0
			startRow = 1
		} else if colCount == 5 {
			// 老版本 5列格式：
			// IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE
			domainColIdx = 2
			ipColIdx = 0
			startRow = 1
		} else {
			// 扫描前几行探测哪一列是域名
			domainColIdx = detectDomainColumn(records)
			if domainColIdx == -1 {
				return nil, fmt.Errorf("未能从 CSV 中识别域名列，请确认包含 CERT_DOMAIN 或 DOMAIN 列")
			}
			ipColIdx = detectIPColumn(records)
			// 如果首行本身就是域名而不是表头，从第 0 行开始读
			if isPossibleDomain(records[0][domainColIdx]) && !strings.Contains(strings.ToUpper(records[0][domainColIdx]), "DOMAIN") {
				startRow = 0
			}
		}
	}

	// 2. 提取候选数据
	var candidates []model.Candidate
	seen := make(map[string]bool)

	for i := startRow; i < len(records); i++ {
		row := records[i]
		if len(row) <= domainColIdx {
			continue
		}

		rawDomain := strings.Trim(strings.TrimSpace(row[domainColIdx]), `"'`)
		if rawDomain == "" || seen[rawDomain] {
			continue
		}

		// 过滤通配符与非法字符
		if strings.Contains(rawDomain, "*") || strings.Contains(rawDomain, " ") || !strings.Contains(rawDomain, ".") {
			continue
		}

		targetIP := ""
		if ipColIdx >= 0 && len(row) > ipColIdx {
			rawIP := strings.Trim(strings.TrimSpace(row[ipColIdx]), `"'`)
			if net.ParseIP(rawIP) != nil {
				targetIP = rawIP
			}
		}

		seen[rawDomain] = true
		candidates = append(candidates, model.Candidate{
			Domain:   rawDomain,
			TargetIP: targetIP,
		})
	}

	return candidates, nil
}

func detectDomainColumn(records [][]string) int {
	for c := 0; c < len(records[0]); c++ {
		matchCount := 0
		checkRows := len(records)
		if checkRows > 5 {
			checkRows = 5
		}
		for r := 0; r < checkRows; r++ {
			if isPossibleDomain(records[r][c]) {
				matchCount++
			}
		}
		if matchCount >= 2 {
			return c
		}
	}
	return -1
}

func detectIPColumn(records [][]string) int {
	for c := 0; c < len(records[0]); c++ {
		matchCount := 0
		checkRows := len(records)
		if checkRows > 5 {
			checkRows = 5
		}
		for r := 0; r < checkRows; r++ {
			if net.ParseIP(strings.TrimSpace(records[r][c])) != nil {
				matchCount++
			}
		}
		if matchCount >= 2 {
			return c
		}
	}
	return -1
}

func isPossibleDomain(s string) bool {
	s = strings.TrimSpace(s)
	if strings.Contains(s, ".") && !strings.Contains(s, " ") && len(s) >= 4 {
		if net.ParseIP(s) == nil && !strings.HasPrefix(s, "TLS") {
			return true
		}
	}
	return false
}
