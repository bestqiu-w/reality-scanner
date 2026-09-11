package checker

import (
	"fmt"
	"net"
	"sort"
	"time"

	"reality-scanner/internal/model"
)

// EvaluateSuitability 综合评估目标是否适合作为 Reality 伪装域名，并计算百分制量化得分与推荐星级
func EvaluateSuitability(res *model.DetectionResult) {
	res.ScoreDetail = make(map[string]float64)

	// 1. 硬性一票否决指标检查
	if res.IsBlocked {
		res.Suitable = false
		res.Error = fmt.Errorf("域名被墙（%s）", res.BlockedReason)
		res.Stars = 0
		res.Score = 0
		return
	}

	if res.IsDomestic {
		res.Suitable = false
		res.Error = fmt.Errorf("国内网站/境内IP")
		res.Stars = 0
		res.Score = 0
		return
	}

	if !res.Accessible {
		res.Suitable = false
		res.Error = fmt.Errorf("网络不可达")
		res.Stars = 0
		res.Score = 0
		return
	}

	if res.StatusCat == model.StatusCodeCategoryExcluded {
		res.Suitable = false
		res.Error = fmt.Errorf("HTTP状态码不自然: %d", res.StatusCode)
		res.Stars = 0
		res.Score = 0
		return
	}

	if !res.SupportsTLS13 {
		res.Suitable = false
		res.Error = fmt.Errorf("不支持 TLS 1.3")
		res.Stars = 0
		res.Score = 0
		return
	}

	if !res.SupportsX25519 {
		res.Suitable = false
		res.Error = fmt.Errorf("不支持 X25519 密钥交换")
		res.Stars = 0
		res.Score = 0
		return
	}

	if !res.SupportsHTTP2 {
		res.Suitable = false
		res.Error = fmt.Errorf("不支持 HTTP/2")
		res.Stars = 0
		res.Score = 0
		return
	}

	if !res.SNIMatch {
		res.Suitable = false
		res.Error = fmt.Errorf("证书域名与 SNI 不匹配")
		res.Stars = 0
		res.Score = 0
		return
	}

	if !res.CertValid || res.CertDaysUntilExpiry <= 0 {
		res.Suitable = false
		res.Error = fmt.Errorf("证书已过期或无效")
		res.Stars = 0
		res.Score = 0
		return
	}

	if res.DNSMatchLevel == "dead" {
		res.Suitable = false
		res.Error = fmt.Errorf("域名无有效公网DNS解析(已注销/失效)")
		res.Stars = 0
		res.Score = 0
		return
	}

	// 所有硬性技术门槛均已通过
	res.Suitable = true

	// 2. 五大核心维度加权百分制量化打分 (总分 100 分)
	// ① 维度 1: DNS 拓扑一致性 (满分 30 分 - 核心对抗防探测)
	var dnsScore float64
	switch res.DNSMatchLevel {
	case "direct":
		dnsScore = 30.0 // 1:1 权威直连当前目标 IP
	case "subnet":
		dnsScore = 22.0 // 同 C 段 (/24) 优质邻居
	case "remote":
		// 检查是否属于同 B 段 (/16)
		if isSameBSubnetList(res.TargetIP, res.ResolvedIPs) {
			dnsScore = 15.0
		} else {
			dnsScore = 8.0 // 跨大洲/跨网段
		}
	case "cdn":
		dnsScore = 4.0 // 套 CDN 裸露源站 (公网解析为 Anycast CDN，源站暴露在外)
	case "resolved":
		dnsScore = 20.0 // 单域名快速体检模式（无关联探测 IP，正常公网解析赋基准分）
	default:
		dnsScore = 8.0
	}

	// ② 维度 2: CDN 隐蔽度 (满分 25 分 - 核心防二次审查与流量偷跑)
	var cdnScore float64
	if !res.IsCDN {
		cdnScore = 25.0 // 完全无 CDN 特征，纯原生独立主机
	} else {
		switch res.CDNConfidence {
		case "低":
			cdnScore = 15.0
		case "中":
			cdnScore = 8.0
		case "高":
			cdnScore = 0.0 // 明确公认大厂 CDN (Cloudflare/Akamai等)
		default:
			cdnScore = 5.0
		}
	}

	// ③ 维度 3: 握手与 RTT 时延 (满分 20 分 - 本地电脑跨洋公网宽松平滑线性插值，杜绝断崖)
	latencyScore := calcLatencyScore(res.HandshakeTime)

	// ④ 维度 4: 域名冷门度/非大厂 (满分 15 分 - 防从众效应与定点审计)
	var hotScore float64
	if !res.IsHotWebsite {
		hotScore = 15.0 // 小众、合规的普通独立站点 (最安全隐蔽)
	} else {
		hotScore = 3.0 // Apple、Google、Microsoft 等大厂高频站点 (重点监控名单)
	}

	// ⑤ 维度 5: 证书长效稳定性 (满分 10 分 - 长期免维护周期)
	var certScore float64
	days := res.CertDaysUntilExpiry
	switch {
	case days >= 75:
		certScore = 10.0
	case days >= 60:
		certScore = 8.0
	case days >= 30:
		certScore = 5.0
	case days >= 15:
		certScore = 2.0
	default:
		certScore = 0.0
	}

	// 3. 计算综合量化总得分与映射星级
	totalScore := dnsScore + cdnScore + latencyScore + hotScore + certScore
	if totalScore > 100.0 {
		totalScore = 100.0
	}
	res.Score = totalScore
	res.ScoreDetail["dns"] = dnsScore
	res.ScoreDetail["cdn"] = cdnScore
	res.ScoreDetail["latency"] = latencyScore
	res.ScoreDetail["hot"] = hotScore
	res.ScoreDetail["cert"] = certScore

	// 动态映射星级
	switch {
	case totalScore >= 90.0:
		res.Stars = 5 // 极品神仙目标
	case totalScore >= 80.0:
		res.Stars = 4 // 优质推荐目标
	case totalScore >= 70.0:
		res.Stars = 3 // 合格可用目标
	case totalScore >= 60.0:
		res.Stars = 2 // 勉强可用目标
	default:
		res.Stars = 1 // 不推荐
	}
}

// isSameBSubnetList 检查 targetIP 与 resolvedIPs 是否存在处于同一 /16 B段的地址
func isSameBSubnetList(targetIP string, resolvedIPs []string) bool {
	tgtIP := net.ParseIP(targetIP)
	if tgtIP == nil {
		return false
	}
	tgt4 := tgtIP.To4()
	if tgt4 == nil {
		return false
	}
	for _, rStr := range resolvedIPs {
		rIP := net.ParseIP(rStr)
		if rIP == nil {
			continue
		}
		r4 := rIP.To4()
		if r4 != nil && tgt4[0] == r4[0] && tgt4[1] == r4[1] {
			return true
		}
	}
	return false
}

// SortResultsByStars 排序结果：高分优先（降序），同分按握手延迟升序
func SortResultsByStars(results []*model.DetectionResult) {
	sort.Slice(results, func(i, j int) bool {
		// 1. 优先按百分制综合得分降序排序 (高分在前)
		if results[i].Score != results[j].Score {
			return results[i].Score > results[j].Score
		}
		// 2. 得分相同时按星级降序
		if results[i].Stars != results[j].Stars {
			return results[i].Stars > results[j].Stars
		}
		// 3. 星级相同时按握手延迟升序 (低延迟在前)
		return results[i].HandshakeTime < results[j].HandshakeTime
	})
}

// calcLatencyScore 专为本地电脑跨网段/跨洋探测设计的宽松平滑线性插值算法 (满分 20 分)
// 彻底消除阶梯临界断崖，让分数随毫秒数平滑连续过渡
func calcLatencyScore(d time.Duration) float64 {
	if d <= 0 {
		return 1.0
	}
	ms := float64(d.Milliseconds())

	type point struct {
		ms    float64
		score float64
	}

	// 关键物理锚点:
	// - 150ms 以内: 亚太优质直连或本土极速链路，满分 20.0
	// - 150 ~ 350ms: 美西等跨洋直连优质公网，平滑衰减至 16.0
	// - 350 ~ 650ms: 普通跨洋长链路标准时延 (TCP+TLS两次往返)，平滑衰减至 10.0
	// - 650 ~ 1000ms: 轻度拥塞或绕路，平滑衰减至 5.0
	// - 1000 ~ 1500ms: 严重延迟，平滑衰减至 1.0
	points := []point{
		{ms: 150.0, score: 20.0},
		{ms: 350.0, score: 16.0},
		{ms: 650.0, score: 10.0},
		{ms: 1000.0, score: 5.0},
		{ms: 1500.0, score: 1.0},
	}

	if ms <= points[0].ms {
		return points[0].score
	}

	for i := 0; i < len(points)-1; i++ {
		p1 := points[i]
		p2 := points[i+1]
		if ms <= p2.ms {
			// 线性插值公式
			return p1.score - (ms-p1.ms)*(p1.score-p2.score)/(p2.ms-p1.ms)
		}
	}

	return 1.0
}
