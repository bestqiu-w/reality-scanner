package assets

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// UpdateItem 待更新资源项
type UpdateItem struct {
	Name      string
	LocalPath string
	URLs      []string
}

var defaultUpdateItems = []UpdateItem{
	{
		Name:      "GeoIP 数据库 (Country.mmdb)",
		LocalPath: "data/Country.mmdb",
		URLs: []string{
			"https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb",
			"https://ghproxy.net/https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb",
		},
	},
	{
		Name:      "GFWList 规则库 (gfwlist.conf)",
		LocalPath: "data/gfwlist.conf",
		URLs: []string{
			"https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt",
			"https://ghproxy.net/https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt",
		},
	},
	{
		Name:      "CDN 识别特征库 (cdn_keywords.txt)",
		LocalPath: "data/cdn_keywords.txt",
		URLs: []string{
			"https://raw.githubusercontent.com/V2RaySSR/RealityChecker/main/data/cdn_keywords.txt",
			"https://ghproxy.net/https://raw.githubusercontent.com/V2RaySSR/RealityChecker/main/data/cdn_keywords.txt",
		},
	},
	{
		Name:      "热门网站列表 (hot_websites.txt)",
		LocalPath: "data/hot_websites.txt",
		URLs: []string{
			"https://raw.githubusercontent.com/V2RaySSR/RealityChecker/main/data/hot_websites.txt",
			"https://ghproxy.net/https://raw.githubusercontent.com/V2RaySSR/RealityChecker/main/data/hot_websites.txt",
		},
	},
}

// UpdateAssets 执行规则文件下载与更新
// force: 是否强制更新（即使本地文件较新也下载）
// verbose: 是否打印更新进度
func UpdateAssets(ctx context.Context, force bool, verbose bool) error {
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("创建 data 目录失败: %w", err)
	}

	for _, item := range defaultUpdateItems {
		// 检查本地文件是否存在且未过期（默认 7 天过期）
		if !force {
			info, err := os.Stat(item.LocalPath)
			if err == nil && time.Since(info.ModTime()) < 7*24*time.Hour {
				if verbose {
					fmt.Printf("   [=] %s 处于最新状态 (7天内)，跳过更新\n", item.Name)
				}
				continue
			}
		}

		if verbose {
			fmt.Printf("   [↓] 正在下载更新 %s...\n", item.Name)
		}

		err := downloadWithFallbacks(ctx, item.URLs, item.LocalPath)
		if err != nil {
			if verbose {
				fmt.Printf("   [!] %s 更新失败: %v (已自动保持使用现有/内嵌规则)\n", item.Name, err)
			}
		} else {
			if verbose {
				fmt.Printf("   [✓] %s 更新成功\n", item.Name)
			}
		}
	}

	return nil
}

// downloadWithFallbacks 依次尝试多个下载源（包含直连与镜像源）
func downloadWithFallbacks(ctx context.Context, urls []string, targetPath string) error {
	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	var lastErr error
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (reality-scanner updater)")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP状态异常: %d", resp.StatusCode)
			continue
		}

		tmpPath := targetPath + ".tmp"
		f, err := os.Create(tmpPath)
		if err != nil {
			resp.Body.Close()
			lastErr = err
			continue
		}

		_, err = io.Copy(f, resp.Body)
		resp.Body.Close()
		f.Close()

		if err != nil {
			_ = os.Remove(tmpPath)
			lastErr = err
			continue
		}

		// 原子替换
		_ = os.MkdirAll(filepath.Dir(targetPath), 0755)
		if err := os.Rename(tmpPath, targetPath); err != nil {
			_ = os.Remove(tmpPath)
			lastErr = err
			continue
		}

		return nil // 成功
	}

	return lastErr
}

// AutoBackgroundCheck 后台异步静默检查更新（绝不阻塞启动，绝不抛出致命异常）
func AutoBackgroundCheck() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		_ = UpdateAssets(ctx, false, false)
	}()
}
