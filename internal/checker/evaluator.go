package checker

import (
	"fmt"
	"sort"

	"reality-scanner/internal/model"
)

// EvaluateSuitability 综合评估目标是否适合作为 Reality 伪装域名，并计算推荐星级
func EvaluateSuitability(res *model.DetectionResult) {
	// 1. 硬性条件检查
	if res.IsBlocked {
		res.Suitable = false
		res.Error = fmt.Errorf("域名被墙（%s）", res.BlockedReason)
		res.Stars = 0
		return
	}

	if res.IsDomestic {
		res.Suitable = false
		res.Error = fmt.Errorf("国内网站/境内IP")
		res.Stars = 0
		return
	}

	if !res.Accessible {
		res.Suitable = false
		res.Error = fmt.Errorf("网络不可达")
		res.Stars = 0
		return
	}

	if res.StatusCat == model.StatusCodeCategoryExcluded {
		res.Suitable = false
		res.Error = fmt.Errorf("HTTP状态码不自然: %d", res.StatusCode)
		res.Stars = 0
		return
	}

	if !res.SupportsTLS13 {
		res.Suitable = false
		res.Error = fmt.Errorf("不支持 TLS 1.3")
		res.Stars = 0
		return
	}

	if !res.SupportsX25519 {
		res.Suitable = false
		res.Error = fmt.Errorf("不支持 X25519 密钥交换")
		res.Stars = 0
		return
	}

	if !res.SupportsHTTP2 {
		res.Suitable = false
		res.Error = fmt.Errorf("不支持 HTTP/2")
		res.Stars = 0
		return
	}

	if !res.SNIMatch {
		res.Suitable = false
		res.Error = fmt.Errorf("证书域名与 SNI 不匹配")
		res.Stars = 0
		return
	}

	if !res.CertValid || res.CertDaysUntilExpiry <= 0 {
		res.Suitable = false
		res.Error = fmt.Errorf("证书已过期或无效")
		res.Stars = 0
		return
	}

	if res.DNSMatchLevel == "dead" {
		res.Suitable = false
		res.Error = fmt.Errorf("域名无有效公网DNS解析(已注销/失效)")
		res.Stars = 0
		return
	}

	// 所有硬性指标均满足
	res.Suitable = true

	// 2. 星级评分计算 (1 ~ 5 星)
	stars := 1 // 基础硬性条件达标赋予 1 星

	// ① 握手低延迟 (<= 200ms)
	if res.HandshakeTime > 0 && res.HandshakeTime.Milliseconds() <= 200 {
		stars++
	}

	// ② 无 CDN 特征
	if !res.IsCDN {
		stars++
	}

	// ③ 非热门大厂网站
	if !res.IsHotWebsite {
		stars++
	}

	// ④ 证书有效期充沛 (>= 60天)
	if res.CertDaysUntilExpiry >= 60 {
		stars++
	}

	// ⑤ DNS 一致性优秀 (直连同服或同C段邻居 +1星)
	if res.DNSMatchLevel == "direct" || res.DNSMatchLevel == "subnet" {
		stars++
	}

	if stars > 5 {
		stars = 5
	}
	res.Stars = stars
}

// SortResultsByStars 排序结果：高星级优先（降序），同星级直连匹配与低延迟优先
func SortResultsByStars(results []*model.DetectionResult) {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Stars != results[j].Stars {
			return results[i].Stars > results[j].Stars // 降序：5星在前
		}
		// 同星级：DNS直连匹配优先于其他
		weightI := dnsWeight(results[i].DNSMatchLevel)
		weightJ := dnsWeight(results[j].DNSMatchLevel)
		if weightI != weightJ {
			return weightI > weightJ
		}
		return results[i].HandshakeTime < results[j].HandshakeTime // 延迟低在前
	})
}

func dnsWeight(level string) int {
	switch level {
	case "direct":
		return 3
	case "subnet":
		return 2
	case "cdn":
		return 1
	default:
		return 0
	}
}
