package cmd

import (
	"context"
	"flag"
	"fmt"
	"time"

	"reality-scanner/internal/assets"
)

// ExecuteUpdate 执行规则数据更新
func ExecuteUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	var force bool
	fs.BoolVar(&force, "force", false, "强制重新下载所有规则文件（即使未过期）")
	if err := fs.Parse(args); err != nil {
		return
	}

	fmt.Println("=====================================================")
	fmt.Println("        正在检查并更新 Reality 规则数据库...")
	fmt.Println("=====================================================")

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	_ = assets.UpdateAssets(ctx, force, true)

	fmt.Println("\n[✓] 规则检查与更新流程执行完毕。")
}
