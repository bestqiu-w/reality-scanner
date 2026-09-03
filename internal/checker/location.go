package checker

import (
	"fmt"
	"net"
	"sync"

	"reality-scanner/internal/assets"

	"github.com/oschwald/geoip2-golang"
)

// LocationDetector 地理位置检测器
type LocationDetector struct {
	reader *geoip2.Reader
	once   sync.Once
}

var defaultLocationDetector = &LocationDetector{}

// GetLocationDetector 获取单例
func GetLocationDetector() *LocationDetector {
	defaultLocationDetector.once.Do(func() {
		reader, err := assets.GetGeoIPReader()
		if err == nil {
			defaultLocationDetector.reader = reader
		}
	})
	return defaultLocationDetector
}

// CheckLocation 检测 IP 或域名的地理位置
func (ld *LocationDetector) CheckLocation(ipStr string, domain string) (country string, isDomestic bool, err error) {
	var targetIP net.IP

	if ipStr != "" {
		targetIP = net.ParseIP(ipStr)
	}

	if targetIP == nil && domain != "" {
		ips, err := net.LookupIP(domain)
		if err != nil || len(ips) == 0 {
			return "未知", false, fmt.Errorf("DNS解析失败: %v", err)
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				targetIP = ip
				break
			}
		}
		if targetIP == nil {
			targetIP = ips[0]
		}
	}

	if targetIP == nil {
		return "未知", false, fmt.Errorf("无效的IP目标")
	}

	if ld.reader == nil {
		return "N/A", false, nil
	}

	record, err := ld.reader.Country(targetIP)
	if err != nil {
		return "未知", false, err
	}

	country = record.Country.IsoCode
	if name, ok := record.Country.Names["zh-CN"]; ok && name != "" {
		country = name
	} else if country == "" {
		country = record.Country.Names["en"]
	}

	isDomestic = (record.Country.IsoCode == "CN" || country == "中国")
	return country, isDomestic, nil
}
