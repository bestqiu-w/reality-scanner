package cmd

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"reality-scanner/internal/checker"
	"reality-scanner/internal/model"
	"reality-scanner/internal/output"
	"reality-scanner/internal/scanner"
)

// ExecuteScan 执行全自动扫描与评估
func ExecuteScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var (
		addr       string
		radius     int
		threads    int
		port       int
		timeout    time.Duration
		outFile    string
		infinite   bool
		enableIPv6 bool
	)

	fs.StringVar(&addr, "addr", "", "扫描目标 IP、CIDR 或域名")
	fs.IntVar(&radius, "radius", 64, "单个 IP 时的扫描半径 (邻近 IP 数量)")
	fs.IntVar(&threads, "thread", 25, "并发扫描线程数")
	fs.IntVar(&port, "port", 443, "扫描端口")
	fs.DurationVar(&timeout, "timeout", 3*time.Second, "单次请求超时时间")
	fs.StringVar(&outFile, "out", "", "结果输出路径 (.txt 或 .csv)")
	fs.BoolVar(&infinite, "infinite", false, "是否开启无限扫描模式")
	fs.BoolVar(&enableIPv6, "6", false, "启用 IPv6")

	if err := fs.Parse(args); err != nil {
		return
	}

	if addr == "" {
		fmt.Println("错误: 必须通过 -addr 指定扫描目标，例如 -addr 1.2.3.4 或 -addr 1.2.3.0/24")
		fs.PrintDefaults()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n收到中断信号，正在退出并保存已有结果...")
		cancel()
	}()

	fmt.Printf("[%s] 开始探测目标 %s (端口 %d, 并发 %d, 范围半径 %d)...\n",
		time.Now().Format("15:04:05"), addr, port, threads, radius)

	hostChan := scanner.IterateAddr(addr, radius, infinite, enableIPv6)
	prober := scanner.NewProber(scanner.ScannerConfig{
		Port:       port,
		Threads:    threads,
		Timeout:    timeout,
		EnableIPv6: enableIPv6,
	})

	var candidates []model.Candidate
	candidateMap := make(map[string]bool)

	prober.ScanTargets(ctx, hostChan, func(cand model.Candidate) {
		if !candidateMap[cand.Domain] {
			candidateMap[cand.Domain] = true
			candidates = append(candidates, cand)
			fmt.Printf("   [+] 发现候选: %-30s (IP: %s)\n", cand.Domain, cand.TargetIP)
		}
	})

	if len(candidates) == 0 {
		fmt.Println("\n未在目标附近探测到任何开放 TLS 1.3 的域名服务。")
		return
	}

	fmt.Printf("\n[%s] 探测完成，发现 %d 个候选域名，进入 Reality 质量评估...\n\n",
		time.Now().Format("15:04:05"), len(candidates))

	pipe := checker.NewPipeline(timeout)
	results := pipe.CheckBatch(ctx, candidates, 10, func(done, total int, res *model.DetectionResult) {
		status := "合格"
		if !res.Suitable {
			status = "排除"
		}
		fmt.Printf("   [%d/%d] 校验: %-28s => %s (%s)\n", done, total, res.Domain, status, res.Country)
	})

	checker.SortResultsByStars(results)

	fmt.Println()
	fmt.Println("【Reality 伪装目标质量评估结果】")
	fmt.Println(output.FormatTable(results))

	if outFile != "" {
		var err error
		if strings.HasSuffix(strings.ToLower(outFile), ".csv") {
			err = output.SaveCSV(outFile, results)
		} else {
			err = output.SaveTextReport(outFile, results)
		}
		if err != nil {
			fmt.Printf("保存结果失败: %v\n", err)
		} else {
			fmt.Printf("结果已成功保存到: %s\n", outFile)
		}
	}
}
