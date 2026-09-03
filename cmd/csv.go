package cmd

import (
	"context"
	"fmt"
	"time"

	"reality-scanner/internal/checker"
	"reality-scanner/internal/model"
	"reality-scanner/internal/output"
)

// ExecuteCSV 从 CSV 文件读取并批量检测
func ExecuteCSV(args []string) {
	if len(args) == 0 {
		fmt.Println("错误: 请指定 CSV 文件路径，例如: reality-scanner csv file.csv")
		return
	}

	csvFile := args[0]
	fmt.Printf("[%s] 正在解析 CSV 文件: %s\n", time.Now().Format("15:04:05"), csvFile)

	candidates, err := output.ReadCandidatesFromCSV(csvFile)
	if err != nil {
		fmt.Printf("读取 CSV 文件失败: %v\n", err)
		return
	}

	fmt.Printf("[%s] 成功从 CSV 提取到 %d 个待测域名\n\n", time.Now().Format("15:04:05"), len(candidates))

	pipe := checker.NewPipeline(3 * time.Second)
	results := pipe.CheckBatch(context.Background(), candidates, 12, func(done, total int, res *model.DetectionResult) {
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
