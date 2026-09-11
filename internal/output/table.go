package output

import (
	"fmt"
	"strings"

	"reality-scanner/internal/model"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

// FormatTable 格式化适合的域名表格
func FormatTable(results []*model.DetectionResult) string {
	if len(results) == 0 {
		return "未找到任何符合 Reality 要求的域名。\n"
	}

	var buf strings.Builder
	t := table.NewWriter()
	t.SetOutputMirror(&buf)

	// 表头
	t.AppendHeader(table.Row{
		"最终域名", "关联IP", "DNS匹配", "基础指标", "握手耗时", "证书天数", "CDN特征", "热门", "综合评分", "星级", "状态",
	})

	t.SetStyle(table.StyleDefault)
	t.Style().Options.SeparateRows = true
	t.Style().Options.SeparateColumns = true
	t.Style().Options.DrawBorder = true
	t.Style().Options.SeparateHeader = true

	t.Style().Color.Header = []text.Color{text.FgHiWhite, text.Bold}
	t.Style().Color.Row = []text.Color{text.FgWhite}
	t.Style().Color.Border = []text.Color{text.FgWhite}

	t.SetColumnConfigs([]table.ColumnConfig{
		{Name: "最终域名", Align: text.AlignLeft},
		{Name: "关联IP", Align: text.AlignCenter},
		{Name: "DNS匹配", Align: text.AlignCenter},
		{Name: "基础指标", Align: text.AlignCenter},
		{Name: "握手耗时", Align: text.AlignCenter},
		{Name: "证书天数", Align: text.AlignCenter},
		{Name: "CDN特征", Align: text.AlignCenter},
		{Name: "热门", Align: text.AlignCenter},
		{Name: "综合评分", Align: text.AlignCenter},
		{Name: "星级", Align: text.AlignCenter},
		{Name: "状态", Align: text.AlignCenter},
	})

	for _, res := range results {
		domain := res.Domain
		if res.FinalDomain != "" {
			domain = res.FinalDomain
		}

		targetIP := res.TargetIP
		if targetIP == "" {
			targetIP = "-"
		}

		// DNS 匹配
		var dnsMatchText string
		switch res.DNSMatchLevel {
		case "direct":
			dnsMatchText = text.FgGreen.Sprint("直连 (优)")
		case "subnet":
			dnsMatchText = text.FgCyan.Sprint("同C段")
		case "cdn":
			dnsMatchText = text.FgYellow.Sprint("套CDN")
		case "remote":
			dnsMatchText = text.FgWhite.Sprint("跨网段")
		case "dead":
			dnsMatchText = text.FgRed.Sprint("无解析")
		case "resolved":
			dnsMatchText = text.FgGreen.Sprint("已解析")
		default:
			dnsMatchText = "-"
		}

		// 基础指标 (TLS1.3 + X25519 + H2 + SNI)
		var baseCondText string
		if res.SupportsTLS13 && res.SupportsX25519 && res.SupportsHTTP2 && res.SNIMatch {
			baseCondText = text.FgGreen.Sprint("✓ 合格")
		} else {
			baseCondText = text.FgRed.Sprint("✗ 不符")
		}

		// 握手耗时
		var handshakeText string
		if res.HandshakeTime > 0 {
			ms := res.HandshakeTime.Milliseconds()
			handshakeText = fmt.Sprintf("%dms", ms)
			if ms <= 300 {
				handshakeText = text.FgGreen.Sprint(handshakeText)
			} else if ms <= 650 {
				handshakeText = text.FgYellow.Sprint(handshakeText)
			} else {
				handshakeText = text.FgRed.Sprint(handshakeText)
			}
		} else {
			handshakeText = text.FgRed.Sprint("-")
		}

		// 证书天数
		var certText string
		if res.CertValid && res.CertDaysUntilExpiry > 0 {
			certText = fmt.Sprintf("%d天", res.CertDaysUntilExpiry)
			if res.CertDaysUntilExpiry >= 60 {
				certText = text.FgGreen.Sprint(certText)
			} else if res.CertDaysUntilExpiry >= 30 {
				certText = text.FgYellow.Sprint(certText)
			} else {
				certText = text.FgRed.Sprint(certText)
			}
		} else {
			certText = text.FgRed.Sprint("已过期")
		}

		// CDN 特征
		var cdnText string
		if res.IsCDN {
			cdnText = text.FgRed.Sprint(res.CDNConfidence)
		} else {
			cdnText = text.FgGreen.Sprint("无 (优)")
		}

		// 热门网站
		var hotText string
		if res.IsHotWebsite {
			hotText = text.FgYellow.Sprint("是 (热)")
		} else {
			hotText = text.FgGreen.Sprint("否")
		}

		// 综合评分
		var scoreText string
		if res.Suitable {
			scoreVal := fmt.Sprintf("%.1f", res.Score)
			switch {
			case res.Score >= 90.0:
				scoreText = text.FgHiGreen.Sprint(scoreVal)
			case res.Score >= 80.0:
				scoreText = text.FgGreen.Sprint(scoreVal)
			case res.Score >= 70.0:
				scoreText = text.FgYellow.Sprint(scoreVal)
			case res.Score >= 60.0:
				scoreText = text.FgHiYellow.Sprint(scoreVal)
			default:
				scoreText = text.FgRed.Sprint(scoreVal)
			}
		} else {
			scoreText = text.FgRed.Sprint("-")
		}

		// 推荐星级 (固定 5 字符等宽显示：实心星 + 空心星，彻底解决单星字体形变问题)
		var starsText string
		if res.Suitable {
			starsCount := res.Stars
			if starsCount < 1 {
				starsCount = 1
			} else if starsCount > 5 {
				starsCount = 5
			}
			starStr := strings.Repeat("★", starsCount) + strings.Repeat("☆", 5-starsCount)
			starsText = text.FgYellow.Sprint(starStr)
		} else {
			starsText = text.FgRed.Sprint("不适合")
		}

		// HTTP 状态码
		var statusText string
		if res.Accessible {
			statusText = fmt.Sprintf("%d", res.StatusCode)
			switch res.StatusCode {
			case 200:
				statusText = text.FgGreen.Sprint(statusText)
			case 301, 302:
				statusText = text.FgYellow.Sprint(statusText)
			case 404:
				statusText = text.FgBlue.Sprint(statusText)
			default:
				statusText = text.FgRed.Sprint(statusText)
			}
		} else {
			statusText = text.FgRed.Sprint("不可达")
		}

		t.AppendRow(table.Row{
			domain,
			targetIP,
			dnsMatchText,
			baseCondText,
			handshakeText,
			certText,
			cdnText,
			hotText,
			scoreText,
			starsText,
			statusText,
		})
	}

	t.Render()
	return buf.String()
}
