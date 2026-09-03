package cmd

import (
	"fmt"
	"os"

	"reality-scanner/internal/assets"
)

const Version = "v1.0.0"

// Execute 统一命令行入口
func Execute() {
	// 后台静默检查规则库更新（不阻塞，网络不通自动跳过）
	assets.AutoBackgroundCheck()

	if len(os.Args) == 1 {
		showHelp()
		return
	}

	subCmd := os.Args[1]
	switch subCmd {
	case "scan":
		ExecuteScan(os.Args[2:])
	case "check":
		ExecuteCheck(os.Args[2:])
	case "batch":
		ExecuteBatch(os.Args[2:])
	case "csv":
		ExecuteCSV(os.Args[2:])
	case "update":
		ExecuteUpdate(os.Args[2:])
	case "version", "-v", "--version":
		showVersion()
	case "help", "-h", "--help":
		showHelp()
	default:
		fmt.Printf("未知命令: %s\n\n", subCmd)
		showHelp()
		os.Exit(1)
	}
}

func showVersion() {
	fmt.Printf("reality-scanner %s - Reality 目标网站扫描与质量评估一体化工具\n", Version)
}

func showHelp() {
	fmt.Println("reality-scanner - Reality 目标网站扫描与质量评估一体化工具")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  reality-scanner scan [flags]         一体化全自动扫描并评估目标网段")
	fmt.Println("  reality-scanner check <domain>       评估单个域名是否适合作为 Reality 目标")
	fmt.Println("  reality-scanner batch <domain1> ...  并发评估多个域名")
	fmt.Println("  reality-scanner csv <file.csv>       从 CSV 文件智能批量导入并评估")
	fmt.Println("  reality-scanner update [-force]      检查并更新 GeoIP 与规则数据文件")
	fmt.Println("  reality-scanner version              显示版本号")
	fmt.Println()
	fmt.Println("scan 命令选项:")
	fmt.Println("  -addr <ip/cidr/domain>   扫描目标 IP、CIDR 或域名 (必填)")
	fmt.Println("  -radius <int>            当 -addr 为单个 IP 时的扫描半径 (默认 64)")
	fmt.Println("  -thread <int>            扫描探测并发线程数 (默认 20)")
	fmt.Println("  -port <int>              探测端口 (默认 443)")
	fmt.Println("  -timeout <duration>      单次网络超时时间 (默认 3s)")
	fmt.Println("  -out <path>              将推荐结果保存至文件 (支持 .txt 或 .csv)")
	fmt.Println("  -infinite                是否开启无限扫描模式 (默认 false)")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  reality-scanner scan -addr 103.103.245.124 -radius 64 -out reality_best.txt")
	fmt.Println("  reality-scanner check apple.com")
	fmt.Println("  reality-scanner csv file.csv")
}
