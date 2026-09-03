package checker

import (
	"context"
	"net"
	"time"
)

// DNSMatchResult DNS 一致性交叉检验结果
type DNSMatchResult struct {
	ResolvedIPs []string
	MatchLevel  string // "direct", "subnet", "cdn", "remote", "dead", "none"
	MatchDesc   string // "直连 (优)", "同C段 (邻居)", "套CDN源站", "跨网段", "无解析(已失效)"
	IsDead      bool   // 域名无任何公网解析记录
}

// 常见主流 Anycast CDN 网段（用于识别套了 CDN 的裸露源站）
var knownCDNCIDRs = []string{
	// Cloudflare
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	// Fastly
	"151.101.0.0/16", "199.232.0.0/16",
	// CloudFront (部分主要网段)
	"13.32.0.0/15", "13.35.0.0/16", "52.84.0.0/15", "54.192.0.0/16",
	"54.230.0.0/16", "54.239.128.0/18", "54.240.128.0/18", "205.251.192.0/19",
}

var parsedCDNCIDRs []*net.IPNet

func init() {
	for _, cidr := range knownCDNCIDRs {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			parsedCDNCIDRs = append(parsedCDNCIDRs, ipNet)
		}
	}
}

// CheckDNSConsistency 权威校验域名的公网真实解析与探测 IP 的一致性
func CheckDNSConsistency(ctx context.Context, domain string, targetIP string, timeout time.Duration) DNSMatchResult {
	result := DNSMatchResult{
		MatchLevel: "none",
		MatchDesc:  "-",
	}

	resolvedIPs := resolvePublicDNS(ctx, domain, timeout)
	for _, ip := range resolvedIPs {
		result.ResolvedIPs = append(result.ResolvedIPs, ip.String())
	}

	// 1. 无任何解析记录（空域名/已注销）
	if len(resolvedIPs) == 0 {
		result.MatchLevel = "dead"
		result.MatchDesc = "无解析 (已注销)"
		result.IsDead = true
		return result
	}

	// 如果没有目标 IP（例如直接 check domain 模式），只记录公网 IP 列表
	if targetIP == "" {
		result.MatchLevel = "resolved"
		result.MatchDesc = "正常解析"
		return result
	}

	tgtIP := net.ParseIP(targetIP)
	if tgtIP == nil {
		result.MatchLevel = "none"
		result.MatchDesc = "IP无效"
		return result
	}

	// 2. 完全匹配：targetIP 存在于公网解析 IP 中 (Direct Match)
	for _, rIP := range resolvedIPs {
		if rIP.Equal(tgtIP) {
			result.MatchLevel = "direct"
			result.MatchDesc = "直连 (优)"
			return result
		}
	}

	// 3. 同 C 段匹配 (Same /24 Subnet)
	tgt4 := tgtIP.To4()
	if tgt4 != nil {
		for _, rIP := range resolvedIPs {
			r4 := rIP.To4()
			if r4 != nil && tgt4[0] == r4[0] && tgt4[1] == r4[1] && tgt4[2] == r4[2] {
				result.MatchLevel = "subnet"
				result.MatchDesc = "同C段 (邻居)"
				return result
			}
		}
	}

	// 4. 套了 CDN 的源站裸露检测 (DNS 解析为 Cloudflare/Fastly 等 CDN，但探测 IP 为独立主机)
	for _, rIP := range resolvedIPs {
		for _, cidr := range parsedCDNCIDRs {
			if cidr.Contains(rIP) {
				result.MatchLevel = "cdn"
				result.MatchDesc = "套CDN源站"
				return result
			}
		}
	}

	// 5. 跨网段不匹配（如伯克利大学镜像站，能在公网访问但与当前探测 IP 不在同一网段）
	result.MatchLevel = "remote"
	result.MatchDesc = "跨网段"
	return result
}

// resolvePublicDNS 使用公网权威 DNS 服务器解析域名，过滤 Fake-IP
func resolvePublicDNS(ctx context.Context, domain string, timeout time.Duration) []net.IP {
	dnsServers := []string{
		"8.8.8.8:53",
		"8.8.4.4:53",
		"223.5.5.5:53",
		"1.1.1.1:53",
	}

	for _, server := range dnsServers {
		ips := queryDNSWithServer(ctx, domain, server, timeout)
		if len(ips) > 0 {
			// 过滤本地 Fake-IP (198.18.0.0/15)
			var valid []net.IP
			for _, ip := range ips {
				if !isFakeIP(ip) {
					valid = append(valid, ip)
				}
			}
			if len(valid) > 0 {
				return valid
			}
		}
	}

	// 如果直接公网 UDP 53 均受阻，回退到系统默认 Resolver 并过滤 Fake-IP
	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	sysIPs, err := net.DefaultResolver.LookupIP(ctxTimeout, "ip4", domain)
	if err == nil {
		var valid []net.IP
		for _, ip := range sysIPs {
			if !isFakeIP(ip) {
				valid = append(valid, ip)
			}
		}
		return valid
	}

	return nil
}

func queryDNSWithServer(ctx context.Context, domain string, dnsServer string, timeout time.Duration) []net.IP {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := r.LookupIP(ctxTimeout, "ip4", domain)
	if err != nil {
		return nil
	}
	return ips
}

// isFakeIP 过滤 Clash / Mihomo 常用的 198.18.0.0/15 Fake-IP 网段
func isFakeIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}
