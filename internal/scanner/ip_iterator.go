// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package scanner

import (
	"bufio"
	"io"
	"math"
	"math/big"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"reality-scanner/internal/model"
)

// IterateAddr 根据给定目标地址生成待扫描 Host 通道
func IterateAddr(addr string, radius int, infinite bool, enableIPv6 bool) <-chan model.Host {
	hostChan := make(chan model.Host, 100)

	// 1. 是否是 CIDR
	if _, _, err := net.ParseCIDR(addr); err == nil {
		go func() {
			defer close(hostChan)
			IterateCIDR(addr, hostChan, enableIPv6)
		}()
		return hostChan
	}

	// 2. 是否是 IP
	ip := net.ParseIP(addr)
	if ip == nil {
		// 可能是域名，解析其 IP
		ips, err := net.LookupIP(addr)
		if err == nil && len(ips) > 0 {
			for _, item := range ips {
				if item.To4() != nil || enableIPv6 {
					ip = item
					break
				}
			}
		}
	}

	if ip == nil {
		// 纯域名，直接推入
		go func() {
			defer close(hostChan)
			if ValidateDomainName(addr) {
				hostChan <- model.Host{
					IP:     nil,
					Origin: addr,
					Type:   model.HostTypeDomain,
				}
			}
		}()
		return hostChan
	}

	// 3. IP 辐射迭代
	go func() {
		defer close(hostChan)
		// 首先发送初始 IP
		hostChan <- model.Host{
			IP:     ip,
			Origin: addr,
			Type:   model.HostTypeIP,
		}

		if radius <= 0 && !infinite {
			return
		}

		maxCount := radius * 2
		if infinite {
			maxCount = math.MaxInt32
		}

		lowIP := ip
		highIP := ip

		for i := 0; i < maxCount; i++ {
			if i%2 == 0 {
				lowIP = NextIP(lowIP, false)
				if lowIP == nil {
					continue
				}
				hostChan <- model.Host{
					IP:     lowIP,
					Origin: lowIP.String(),
					Type:   model.HostTypeIP,
				}
			} else {
				highIP = NextIP(highIP, true)
				if highIP == nil {
					continue
				}
				hostChan <- model.Host{
					IP:     highIP,
					Origin: highIP.String(),
					Type:   model.HostTypeIP,
				}
			}
		}
	}()

	return hostChan
}

// IterateCIDR 遍历 CIDR 内的所有可用 IP
func IterateCIDR(cidr string, hostChan chan<- model.Host, enableIPv6 bool) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return
	}
	if !p.Addr().Is4() && !enableIPv6 {
		return
	}
	p = p.Masked()
	curr := p.Addr()
	for {
		if !p.Contains(curr) {
			break
		}
		ip := net.ParseIP(curr.String())
		if ip != nil {
			hostChan <- model.Host{
				IP:     ip,
				Origin: cidr,
				Type:   model.HostTypeCIDR,
			}
		}
		curr = curr.Next()
	}
}

// IterateReader 从 Reader 读取目标列表
func IterateReader(reader io.Reader, enableIPv6 bool) <-chan model.Host {
	hostChan := make(chan model.Host, 100)
	scanner := bufio.NewScanner(reader)

	go func() {
		defer close(hostChan)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// IP
			ip := net.ParseIP(line)
			if ip != nil && (ip.To4() != nil || enableIPv6) {
				hostChan <- model.Host{
					IP:     ip,
					Origin: line,
					Type:   model.HostTypeIP,
				}
				continue
			}

			// CIDR
			if _, _, err := net.ParseCIDR(line); err == nil {
				IterateCIDR(line, hostChan, enableIPv6)
				continue
			}

			// 域名
			if ValidateDomainName(line) {
				hostChan <- model.Host{
					IP:     nil,
					Origin: line,
					Type:   model.HostTypeDomain,
				}
				continue
			}
		}
	}()

	return hostChan
}

// NextIP 计算上一位或下一位 IP
func NextIP(ip net.IP, increment bool) net.IP {
	ipb := big.NewInt(0).SetBytes(ip)
	if increment {
		ipb.Add(ipb, big.NewInt(1))
	} else {
		ipb.Sub(ipb, big.NewInt(1))
	}

	b := ipb.Bytes()
	if len(b) > len(ip) {
		return nil // 溢出
	}
	// 补全前导零
	padded := append(make([]byte, len(ip)-len(b)), b...)
	return net.IP(padded)
}

// ValidateDomainName 校验域名格式合法性
func ValidateDomainName(domain string) bool {
	if len(domain) < 3 || len(domain) > 255 {
		return false
	}
	r := regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$`)
	return r.MatchString(domain)
}
