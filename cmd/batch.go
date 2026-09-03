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

// ExecuteBatch 执行多域名并发检测
func ExecuteBatch(args []string) {
	if len(args) == 0 {
		fmt.Println("错误: 请输入要检测的域名列表，例如: reality-scanner batch apple.com tesla.com")
		return
	}

	var candidates []model.Candidate
	for _, a := range args {
		for _, d := range strings.Fields(a) {
			d = strings.TrimSpace(d)
			if d != "" {
				candidates = append(candidates, model.Candidate{Domain: d})
			}
		}
	}

	fmt.Printf("[%s] 开始并发批量检测 %d 个域名...\n\n", time.Now().Format("15:04:05"), len(candidates))

	pipe := checker.NewPipeline(3 * time.Second)
	results := pipe.CheckBatch(context.Background(), candidates, 10, func(done, total int, res *model.DetectionResult) {
		status := "合格"
		if !res.Suitable {
			status = "排除"
		}
		fmt.Printf("   [%d/%d] 检测: %-28s => %s\n", done, total, res.Domain, status)
	})

	checker.SortResultsByStars(results)

	fmt.Println()
	fmt.Println(output.FormatTable(results))
}
