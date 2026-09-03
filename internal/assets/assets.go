package assets

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"os"

	"github.com/oschwald/geoip2-golang"
)

//go:embed data/Country.mmdb
var embeddedCountryMMDB []byte

//go:embed data/gfwlist.conf
var embeddedGFWList []byte

//go:embed data/cdn_keywords.txt
var embeddedCDNKeywords []byte

//go:embed data/hot_websites.txt
var embeddedHotWebsites []byte

// GetGeoIPReader 获取 GeoIP Reader，优先从本地文件加载，若不存在则从嵌入内存加载
func GetGeoIPReader() (*geoip2.Reader, error) {
	// 1. 尝试本地路径
	localPaths := []string{
		"data/Country.mmdb",
		"Country.mmdb",
		"./data/Country.mmdb",
	}
	for _, p := range localPaths {
		if _, err := os.Stat(p); err == nil {
			reader, err := geoip2.Open(p)
			if err == nil {
				return reader, nil
			}
		}
	}

	// 2. 从嵌入字节切片加载
	if len(embeddedCountryMMDB) > 0 {
		return geoip2.FromBytes(embeddedCountryMMDB)
	}

	return nil, fmt.Errorf("Country.mmdb not found locally or in embedded assets")
}

// openLocalOrEmbedded 辅助函数：打开本地文件或使用嵌入数据
func openLocalOrEmbedded(localPaths []string, embedded []byte) (io.ReadCloser, error) {
	for _, p := range localPaths {
		if _, err := os.Stat(p); err == nil {
			f, err := os.Open(p)
			if err == nil {
				return f, nil
			}
		}
	}
	if len(embedded) > 0 {
		return io.NopCloser(bytes.NewReader(embedded)), nil
	}
	return nil, fmt.Errorf("asset not found locally or in embedded assets")
}

// GetGFWListReader 获取 GFWList 读取流
func GetGFWListReader() (io.ReadCloser, error) {
	return openLocalOrEmbedded([]string{"data/gfwlist.conf", "gfwlist.conf"}, embeddedGFWList)
}

// GetCDNKeywordsReader 获取 CDN 关键字读取流
func GetCDNKeywordsReader() (io.ReadCloser, error) {
	return openLocalOrEmbedded([]string{"data/cdn_keywords.txt", "cdn_keywords.txt"}, embeddedCDNKeywords)
}

// GetHotWebsitesReader 获取热门网站读取流
func GetHotWebsitesReader() (io.ReadCloser, error) {
	return openLocalOrEmbedded([]string{"data/hot_websites.txt", "hot_websites.txt"}, embeddedHotWebsites)
}
