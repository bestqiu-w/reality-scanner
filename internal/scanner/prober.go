// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"reality-scanner/internal/model"
)

// ScannerConfig 探测配置
type ScannerConfig struct {
	Port       int
	Threads    int
	Timeout    time.Duration
	EnableIPv6 bool
}

// Prober 快速 TLS 探测器
type Prober struct {
	cfg ScannerConfig
}

// NewProber 创建探测器
func NewProber(cfg ScannerConfig) *Prober {
	if cfg.Port <= 0 {
		cfg.Port = 443
	}
	if cfg.Threads <= 0 {
		cfg.Threads = 20
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	return &Prober{cfg: cfg}
}

// ScanTargets 并发探测 Host 通道，将发现的 Candidate 通过回调或通道返回
func (p *Prober) ScanTargets(ctx context.Context, hostChan <-chan model.Host, onCandidate func(cand model.Candidate)) {
	var wg sync.WaitGroup
	wg.Add(p.cfg.Threads)

	for i := 0; i < p.cfg.Threads; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case host, ok := <-hostChan:
					if !ok {
						return
					}
					p.probeHost(ctx, host, onCandidate)
				}
			}
		}()
	}

	wg.Wait()
}

// probeHost 探测单个 Host
func (p *Prober) probeHost(ctx context.Context, host model.Host, onCandidate func(cand model.Candidate)) {
	var targetIP net.IP
	var serverName string

	if host.IP != nil {
		targetIP = host.IP
	} else if host.Type == model.HostTypeDomain {
		serverName = host.Origin
		ips, err := net.LookupIP(host.Origin)
		if err != nil || len(ips) == 0 {
			return
		}
		for _, ip := range ips {
			if ip.To4() != nil || p.cfg.EnableIPv6 {
				targetIP = ip
				break
			}
		}
	}

	if targetIP == nil {
		return
	}

	hostPort := net.JoinHostPort(targetIP.String(), strconv.Itoa(p.cfg.Port))

	dialer := &net.Dialer{
		Timeout: p.cfg.Timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(p.cfg.Timeout))

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}
	if serverName != "" {
		tlsCfg.ServerName = serverName
	}

	tlsConn := tls.Client(conn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return
	}

	state := tlsConn.ConnectionState()
	// Reality 核心硬性条件：TLS 1.3 + ALPN h2
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" {
		return
	}

	if len(state.PeerCertificates) == 0 {
		return
	}

	// 修复 BUG-02：规范提取叶子证书
	leaf := state.PeerCertificates[0]
	issuer := strings.Join(leaf.Issuer.Organization, " | ")

	// 收集所有候选域名（SAN + CN）
	rawDomains := make([]string, 0, len(leaf.DNSNames)+1)
	if len(leaf.DNSNames) > 0 {
		rawDomains = append(rawDomains, leaf.DNSNames...)
	}
	if leaf.Subject.CommonName != "" {
		rawDomains = append(rawDomains, leaf.Subject.CommonName)
	}

	seen := make(map[string]bool)
	for _, domain := range rawDomains {
		clean := strings.ToLower(strings.TrimSpace(domain))
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true

		if shouldExcludeDomain(clean) {
			continue
		}

		// 触发候选发现
		onCandidate(model.Candidate{
			TargetIP:   targetIP.String(),
			Domain:     clean,
			CertIssuer: issuer,
			ALPN:       state.NegotiatedProtocol,
			TLSVersion: "TLS 1.3",
		})
	}
}

// shouldExcludeDomain 过滤不需要的伪装目标
func shouldExcludeDomain(domain string) bool {
	// 1. 排除通配符 (*)
	if strings.Contains(domain, "*") {
		return true
	}

	// 2. 排除特殊与无效关键词
	excludePatterns := []string{
		"localhost",
		"local",
		"internal",
		"invalid",
		"fake certificate",
		"cloudflare origin certificate",
		"fortigate",
		"unspecified",
	}
	for _, pat := range excludePatterns {
		if strings.Contains(domain, pat) {
			return true
		}
	}

	// 3. 排除纯 IP 地址格式
	if net.ParseIP(domain) != nil {
		return true
	}

	// 4. 校验标准域名格式
	return !ValidateDomainName(domain)
}
