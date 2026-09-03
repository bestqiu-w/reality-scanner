package checker

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"

	"reality-scanner/internal/assets"
)

// CDNDetector CDN 综合识别器（已完整修复死代码问题）
type CDNDetector struct {
	cnameStrongSuffix   map[string]bool
	httpStrongHeader    map[string]bool
	httpMediumHeader    map[string]bool
	httpValueCdnDomains map[string]bool
	nsHintSuffix        map[string]bool
	certIssuerHint      map[string]bool
	once                sync.Once
}

var defaultCDNDetector = &CDNDetector{
	cnameStrongSuffix:   make(map[string]bool),
	httpStrongHeader:    make(map[string]bool),
	httpMediumHeader:    make(map[string]bool),
	httpValueCdnDomains: make(map[string]bool),
	nsHintSuffix:        make(map[string]bool),
	certIssuerHint:      make(map[string]bool),
}

// GetCDNDetector 单例获取
func GetCDNDetector() *CDNDetector {
	defaultCDNDetector.once.Do(func() {
		defaultCDNDetector.loadKeywords()
	})
	return defaultCDNDetector
}

func (cd *CDNDetector) loadKeywords() {
	r, err := assets.GetCDNKeywordsReader()
	if err != nil {
		return
	}
	defer r.Close()

	scanner := bufio.NewScanner(r)
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasSuffix(line, ":") {
			currentSection = line
			continue
		}

		// 移除可能存在的注释
		val := strings.TrimSpace(strings.Split(line, "#")[0])
		if val == "" {
			continue
		}

		switch currentSection {
		case "cname_strong_suffix:":
			cd.cnameStrongSuffix[strings.ToLower(val)] = true
		case "http_strong_header:":
			cd.httpStrongHeader[strings.ToLower(val)] = true
		case "http_medium_header:":
			cd.httpMediumHeader[strings.ToLower(val)] = true
		case "http_value_cdn_domains:":
			cd.httpValueCdnDomains[strings.ToLower(val)] = true
		case "ns_hint_suffix:":
			cd.nsHintSuffix[strings.ToLower(val)] = true
		case "cert_issuer_hint:":
			cd.certIssuerHint[strings.ToLower(val)] = true
		}
	}
}

// DetectCDN 结合 CNAME、响应头、NS 记录与证书签发者识别 CDN
func (cd *CDNDetector) DetectCDN(domain string, headers map[string]string, certIssuer string) (isCDN bool, provider string, confidence string, evidence string) {
	// 1. 高置信度：CNAME 强特征匹配
	if cname, err := net.LookupCNAME(domain); err == nil {
		cnameClean := strings.TrimSuffix(strings.ToLower(cname), ".")
		for suffix := range cd.cnameStrongSuffix {
			if strings.Contains(cnameClean, suffix) {
				return true, "CDN", "高", fmt.Sprintf("CNAME特征: %s 包含 %s", cnameClean, suffix)
			}
		}
	}

	// 2. 高置信度：HTTP 强响应头匹配
	if headers != nil {
		for hName, hVal := range headers {
			hNameLower := strings.ToLower(hName)
			hValLower := strings.ToLower(hVal)

			if cd.httpStrongHeader[hNameLower] {
				return true, "CDN", "高", fmt.Sprintf("HTTP强特征头: %s", hName)
			}

			// 特殊 Server 头
			if hNameLower == "server" {
				for strongServer := range cd.httpStrongHeader {
					if strings.HasPrefix(strongServer, "server: ") {
						srvToken := strings.TrimPrefix(strongServer, "server: ")
						if strings.Contains(hValLower, srvToken) {
							return true, "CDN", "高", fmt.Sprintf("Server特征: %s", hVal)
						}
					}
				}
			}

			// HTTP 响应头值命中 CDN 域名
			for cdnDom := range cd.httpValueCdnDomains {
				if strings.Contains(hValLower, cdnDom) {
					return true, "CDN", "高", fmt.Sprintf("头值CDN域名: %s 包含 %s", hName, cdnDom)
				}
			}
		}
	}

	// 3. 中等置信度：NS 记录匹配
	if nsRecords, err := net.LookupNS(domain); err == nil {
		for _, ns := range nsRecords {
			nsHost := strings.ToLower(ns.Host)
			for hint := range cd.nsHintSuffix {
				if strings.Contains(nsHost, hint) {
					return true, "CDN", "中", fmt.Sprintf("NS特征: %s", ns.Host)
				}
			}
		}
	}

	// 4. 中等置信度：HTTP 中等特征头
	if headers != nil {
		for hName := range headers {
			if cd.httpMediumHeader[strings.ToLower(hName)] {
				return true, "CDN", "中", fmt.Sprintf("HTTP特征头: %s", hName)
			}
		}
	}

	// 5. 低置信度：证书签发者特征
	if certIssuer != "" {
		issuerLower := strings.ToLower(certIssuer)
		for hint := range cd.certIssuerHint {
			if strings.Contains(issuerLower, hint) {
				return true, "CDN", "低", fmt.Sprintf("证书签发者提示: %s", certIssuer)
			}
		}
	}

	return false, "", "-", ""
}
