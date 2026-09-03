package checker

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"
)

// TLSCheckResult TLS 深度检测结果
type TLSCheckResult struct {
	SupportsTLS13  bool
	SupportsX25519 bool
	SupportsHTTP2  bool
	HandshakeTime  time.Duration
	CipherSuite    string

	CertValid           bool
	CertDaysUntilExpiry int
	CertIssuer          string
	CertSubject         string
	SNIMatch            bool
	NotBefore           time.Time
	NotAfter            time.Time
}

// CheckTLS 执行双重 TLS 校验（综合特性与强制 X25519）
func CheckTLS(ctx context.Context, domain string, targetIP string, timeout time.Duration) *TLSCheckResult {
	result := &TLSCheckResult{}

	// 确定连接目标地址
	dialAddr := net.JoinHostPort(domain, "443")
	if targetIP != "" {
		dialAddr = net.JoinHostPort(targetIP, "443")
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// 第一次握手：常规 TLS 1.3 + H2 + 证书校验
	start := time.Now()
	rawConn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return result
	}
	defer rawConn.Close()

	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	tlsCfg := &tls.Config{
		ServerName:         domain,
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true, // 我们手动进行更精细的证书检验
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return result
	}

	result.HandshakeTime = time.Since(start)
	state := tlsConn.ConnectionState()

	result.SupportsTLS13 = (state.Version == tls.VersionTLS13)
	result.SupportsHTTP2 = (state.NegotiatedProtocol == "h2")
	result.CipherSuite = tls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		now := time.Now()

		result.NotBefore = leaf.NotBefore
		result.NotAfter = leaf.NotAfter
		result.CertIssuer = strings.Join(leaf.Issuer.Organization, " | ")
		result.CertSubject = leaf.Subject.CommonName

		// 主机名/SNI 匹配验证
		result.SNIMatch = (leaf.VerifyHostname(domain) == nil)

		// 证书有效期检查
		inPeriod := now.After(leaf.NotBefore) && now.Before(leaf.NotAfter)
		result.CertValid = inPeriod && result.SNIMatch

		if now.Before(leaf.NotAfter) {
			result.CertDaysUntilExpiry = int(time.Until(leaf.NotAfter).Hours() / 24)
		} else {
			result.CertDaysUntilExpiry = 0
		}
	}

	// 如果基础要求（TLS1.3 + H2 + SNI匹配）不满足，则不必执行第二次握手
	if !result.SupportsTLS13 || !result.SupportsHTTP2 || !result.SNIMatch {
		return result
	}

	// 第二次握手：强制指定仅 X25519 曲线握手
	result.SupportsX25519 = checkX25519Only(ctx, dialAddr, domain, timeout)

	return result
}

// checkX25519Only 强制仅提供 X25519 握手
func checkX25519Only(ctx context.Context, dialAddr string, serverName string, timeout time.Duration) bool {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	rawConn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return false
	}
	defer rawConn.Close()

	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	x25519Config := &tls.Config{
		ServerName:         serverName,
		CurvePreferences:   []tls.CurveID{tls.X25519},
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(rawConn, x25519Config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false
	}

	state := tlsConn.ConnectionState()
	return state.Version == tls.VersionTLS13
}
