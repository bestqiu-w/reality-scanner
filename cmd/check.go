package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"reality-scanner/internal/checker"
	"reality-scanner/internal/model"
	"reality-scanner/internal/output"
)

// ExecuteCheck 执行单域名检测
func ExecuteCheck(args []string) {
	if len(args) == 0 {
		fmt.Println("错误: 请指定要检测的域名，例如: reality-scanner check apple.com")
		return
	}

	domain := args[0]
	fmt.Printf("[%s] 开始对域名进行深度 Reality 合规评估: %s\n", time.Now().Format("15:04:05"), domain)

	pipe := checker.NewPipeline(3 * time.Second)
	res := pipe.Check(context.Background(), domain, "")

	checker.SortResultsByStars([]*model.DetectionResult{res})

	fmt.Println()
	fmt.Println(output.FormatTable([]*model.DetectionResult{res}))

	// 详细诊断信息
	fmt.Println("【诊断详情】:")
	fmt.Printf(" - TLS 1.3 支持: %v\n", res.SupportsTLS13)
	fmt.Printf(" - X25519 曲线支持: %v\n", res.SupportsX25519)
	fmt.Printf(" - HTTP/2 (h2) 协商: %v\n", res.SupportsHTTP2)
	fmt.Printf(" - SNI 主机名匹配: %v\n", res.SNIMatch)
	fmt.Printf(" - 证书有效天数: %d 天 (有效: %v)\n", res.CertDaysUntilExpiry, res.CertValid)
	fmt.Printf(" - 证书签发者: %s\n", res.CertIssuer)
	fmt.Printf(" - 是否使用 CDN: %v (等级: %s, 证据: %s)\n", res.IsCDN, res.CDNConfidence, res.CDNEvidence)
	fmt.Printf(" - 是否热门大厂网站: %v\n", res.IsHotWebsite)
	fmt.Printf(" - 是否被 GFW 封锁: %v\n", res.IsBlocked)
	fmt.Printf(" - 归属国家/地区: %s (境内: %v)\n", res.Country, res.IsDomestic)
	fmt.Printf(" - HTTP 状态码: %d\n", res.StatusCode)
	if res.Suitable {
		fmt.Printf(" - 综合量化评分: %.1f / 100 [推荐星级: %s]\n", res.Score, strings.Repeat("★", res.Stars))
		if len(res.ScoreDetail) > 0 {
			fmt.Printf(" - 评分细则拆解: DNS一致性: %.1f/30 | CDN隐蔽度: %.1f/25 | 握手时延: %.1f/20 | 域名冷门度: %.1f/15 | 证书长效: %.1f/10\n",
				res.ScoreDetail["dns"], res.ScoreDetail["cdn"], res.ScoreDetail["latency"], res.ScoreDetail["hot"], res.ScoreDetail["cert"])
		}
	}
	if res.Error != nil {
		fmt.Printf(" - 排除原因: %v\n", res.Error)
	}
}
