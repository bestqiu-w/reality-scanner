package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"reality-scanner/internal/model"
)

// SaveTextReport 保存小白用户易读的文本报告
func SaveTextReport(filePath string, results []*model.DetectionResult) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	var suitableCount int
	for _, r := range results {
		if r.Suitable {
			suitableCount++
		}
	}

	var sb strings.Builder
	sb.WriteString("=================================================================\n")
	sb.WriteString("            Reality 伪装目标域名扫描与质量评估报告\n")
	sb.WriteString(fmt.Sprintf("  生成时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("  合格推荐目标: %d 个\n", suitableCount))
	sb.WriteString("=================================================================\n\n")

	if suitableCount == 0 {
		sb.WriteString("本次扫描未发现完全满足 Reality 要求的伪装域名。\n")
		sb.WriteString("建议：扩大扫描半径（如 -radius 128），或更换邻近网段重新探测。\n")
	} else {
		sb.WriteString("【推荐伪装目标清单 (按推荐度从高到低排序)】:\n\n")
		rank := 1
		for _, r := range results {
			if !r.Suitable {
				continue
			}

			domain := r.Domain
			if r.FinalDomain != "" {
				domain = r.FinalDomain
			}

			targetIP := r.TargetIP
			if targetIP == "" {
				targetIP = "公网解析"
			}

			starsCount := r.Stars
			if starsCount < 1 {
				starsCount = 1
			} else if starsCount > 5 {
				starsCount = 5
			}
			stars := strings.Repeat("★", starsCount) + strings.Repeat("☆", 5-starsCount)
			cdnDesc := "无 (强烈推荐)"
			if r.IsCDN {
				cdnDesc = fmt.Sprintf("有 (%s置信度)", r.CDNConfidence)
			}
			hotDesc := "否"
			if r.IsHotWebsite {
				hotDesc = "是 (大厂高频网站，稍降权)"
			}

			sb.WriteString(fmt.Sprintf("[%d] 域名: %s\n", rank, domain))
			sb.WriteString(fmt.Sprintf("    综合评分: %.1f / 100 [推荐星级: %s]\n", r.Score, stars))
			if len(r.ScoreDetail) > 0 {
				sb.WriteString(fmt.Sprintf("    打分细则: DNS一致性: %.1f/30 | CDN隐蔽度: %.1f/25 | 握手时延: %.1f/20 | 域名冷门度: %.1f/15 | 证书长效: %.1f/10\n",
					r.ScoreDetail["dns"], r.ScoreDetail["cdn"], r.ScoreDetail["latency"], r.ScoreDetail["hot"], r.ScoreDetail["cert"]))
			}
			sb.WriteString(fmt.Sprintf("    关联探测IP: %s\n", targetIP))
			sb.WriteString(fmt.Sprintf("    DNS一致性: %s (公网解析: %s)\n", r.DNSMatchDesc, strings.Join(r.ResolvedIPs, ", ")))
			sb.WriteString(fmt.Sprintf("    握手耗时: %dms\n", r.HandshakeTime.Milliseconds()))
			sb.WriteString(fmt.Sprintf("    证书剩余有效期: %d天 (签发者: %s)\n", r.CertDaysUntilExpiry, r.CertIssuer))
			sb.WriteString(fmt.Sprintf("    CDN特征: %s\n", cdnDesc))
			sb.WriteString(fmt.Sprintf("    热门网站: %s\n", hotDesc))
			sb.WriteString(fmt.Sprintf("    Reality配置参考: dest = \"%s:443\", serverNames = [\"%s\"]\n", domain, domain))
			sb.WriteString("-----------------------------------------------------------------\n")
			rank++
		}
	}

	_, err = f.WriteString(sb.String())
	return err
}

// SaveCSV 保存标准 CSV 数据文件
func SaveCSV(filePath string, results []*model.DetectionResult) error {
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// 表头
	header := []string{
		"DOMAIN", "TARGET_IP", "SCORE", "STARS", "DNS_MATCH", "RESOLVED_IPS", "SUITABLE", "HANDSHAKE_MS",
		"CERT_DAYS", "CERT_ISSUER", "IS_CDN", "CDN_CONFIDENCE", "IS_HOT", "STATUS_CODE",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		domain := r.Domain
		if r.FinalDomain != "" {
			domain = r.FinalDomain
		}

		record := []string{
			domain,
			r.TargetIP,
			fmt.Sprintf("%.1f", r.Score),
			strconv.Itoa(r.Stars),
			r.DNSMatchDesc,
			strings.Join(r.ResolvedIPs, ";"),
			strconv.FormatBool(r.Suitable),
			strconv.FormatInt(r.HandshakeTime.Milliseconds(), 10),
			strconv.Itoa(r.CertDaysUntilExpiry),
			r.CertIssuer,
			strconv.FormatBool(r.IsCDN),
			r.CDNConfidence,
			strconv.FormatBool(r.IsHotWebsite),
			strconv.Itoa(r.StatusCode),
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}

	return nil
}
