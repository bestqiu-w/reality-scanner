package model

import (
	"net"
	"time"
)

// HostType 扫描目标类型
type HostType int

const (
	HostTypeUnknown HostType = iota
	HostTypeIP
	HostTypeCIDR
	HostTypeDomain
)

// Host 扫描目标实体
type Host struct {
	IP     net.IP
	Origin string
	Type   HostType
}

// Candidate 探测发现的候选域名与IP
type Candidate struct {
	TargetIP   string
	Domain     string
	CertIssuer string
	ALPN       string
	TLSVersion string
}

// StatusCodeCategory 状态码分类
const (
	StatusCodeCategorySafe     = "safe"     // 200, 301, 302, 404
	StatusCodeCategoryExcluded = "excluded" // 401, 403, 407, 408, 429, 5xx
	StatusCodeCategoryNetwork  = "network"  // 网络不可达
)

// ClassifyStatusCode 分类 HTTP 状态码
func ClassifyStatusCode(statusCode int, accessible bool) string {
	if !accessible {
		return StatusCodeCategoryNetwork
	}
	switch statusCode {
	case 200, 301, 302, 404:
		return StatusCodeCategorySafe
	default:
		return StatusCodeCategoryExcluded
	}
}

// DetectionResult 统一检测结果结构
type DetectionResult struct {
	Domain     string        `json:"domain"`
	TargetIP   string        `json:"target_ip"` // 关联的探测 IP
	Suitable   bool          `json:"suitable"`  // 是否符合 Reality 要求
	Stars      int           `json:"stars"`     // 推荐星级 1-5
	Duration   time.Duration `json:"duration"`  // 总耗时
	Error      error         `json:"error,omitempty"`
	EarlyExit  bool          `json:"early_exit"`

	// 网络与重定向检测
	Accessible    bool     `json:"accessible"`
	StatusCode    int      `json:"status_code"`
	StatusCat     string   `json:"status_category"`
	FinalDomain   string   `json:"final_domain"`
	IsRedirected  bool     `json:"is_redirected"`
	RedirectChain []string `json:"redirect_chain,omitempty"`

	// TLS 检测
	SupportsTLS13  bool          `json:"supports_tls13"`
	SupportsX25519 bool          `json:"supports_x25519"`
	SupportsHTTP2  bool          `json:"supports_http2"`
	HandshakeTime  time.Duration `json:"handshake_time"`
	CipherSuite    string        `json:"cipher_suite"`

	// 证书检测
	CertValid           bool      `json:"cert_valid"`
	CertDaysUntilExpiry int       `json:"cert_days_until_expiry"`
	CertIssuer          string    `json:"cert_issuer"`
	CertSubject         string    `json:"cert_subject"`
	SNIMatch            bool      `json:"sni_match"`
	NotBefore           time.Time `json:"not_before"`
	NotAfter            time.Time `json:"not_after"`

	// CDN 与热门网站
	IsCDN         bool   `json:"is_cdn"`
	CDNProvider   string `json:"cdn_provider"`
	CDNConfidence string `json:"cdn_confidence"` // 高 / 中 / 低 / -
	CDNEvidence   string `json:"cdn_evidence"`
	IsHotWebsite  bool   `json:"is_hot_website"`

	// GFW 与地理位置
	IsBlocked     bool   `json:"is_blocked"`
	BlockedReason string `json:"blocked_reason"`
	Country       string `json:"country"`
	IsDomestic    bool   `json:"is_domestic"`

	// DNS 一致性校验
	DNSMatchLevel string   `json:"dns_match_level"` // direct, subnet, cdn, remote, dead, none
	DNSMatchDesc  string   `json:"dns_match_desc"`  // 直连 (优), 同C段 (邻居), 套CDN源站, 跨网段, 无解析
	ResolvedIPs   []string `json:"resolved_ips"`
}
