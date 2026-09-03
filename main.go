package main

import (
	"os"

	"reality-scanner/cmd"
)

func main() {
	// 清理系统可能存在干扰 TLS 握手探测的环境代理变量
	_ = os.Unsetenv("ALL_PROXY")
	_ = os.Unsetenv("HTTP_PROXY")
	_ = os.Unsetenv("HTTPS_PROXY")
	_ = os.Unsetenv("NO_PROXY")

	cmd.Execute()
}
