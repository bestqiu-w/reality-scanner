# reality-scanner

**Reality 协议目标网站扫描与质量评估一体化工具**

> 整合并重构了 GitHub 开源项目 [RealiTLScanner](https://github.com/XTLS/RealiTLScanner) 与 [RealityChecker](https://github.com/V2RaySSR/RealityChecker)，修复所有历史遗留漏洞，支持全自动流式扫描、DNS 正向交叉一致性检验与全功能质量评估。

---

## ✨ 核心特性

- 🚀 **一体化全自动流水线**：一条命令即可自动从 VPS 邻近网段扫描开启 TLS 1.3 的服务，直接进入 Reality 过滤评估，免去中间繁琐的 CSV 导入导出。
- 🔍 **DNS 正向交叉一致性检验**：
  - 自动穿透查询公网权威 DNS（防本地 Fake-IP 干扰）；
  - 精准识别 **`直连 (1:1)`**、**`同C段邻居`** 与 **`套CDN裸露源站`**；
  - 自动剔除已欠费/注销的 **`无解析`** 僵尸域名，杜绝因域名失效导致节点被阻断。
- 📦 **纯单文件运行 (零外部依赖)**：
  - 核心 GeoIP 数据库、GFWList 规则库、CDN 特征库、热门网站列表通过 Go `//go:embed` 完整内嵌至二进制文件，无需携带外部数据文件夹。
  - 支持本地优先覆盖：若当前目录下存在 `data/` 目录，自动优先读取本地自定义规则。
- 🔄 **智能双轨更新引擎**：
  - 支持 `./reality-scanner update` 命令，自动从 GitHub 官方源（或国内镜像源）检查并更新规则；
  - 后台静默异步检测，即使离线或网络受阻也绝不阻塞运行、绝不崩溃。
- 🛡️ **彻底修复的历史漏洞与缺陷**：
  - **修复 BUG-01 (CSV 表头错位)**：智能自适应 CSV 列头，动态定位 `CERT_DOMAIN` / `DOMAIN` 与 `IP`，彻底解决老版本因列偏移导致的导入全量失效。
  - **修复 BUG-02 (证书 SAN 提取遗漏)**：全面支持提取 X.509 证书的主题备用名称（SAN `DNSNames`），杜绝因 CommonName 废弃导致的有效域名被误剔除，同时修复循环逻辑覆盖叶子证书问题。
  - **修复 BUG-03 (单 IP 扫描无限死循环)**：支持 `-radius`（默认 64）受控辐射扫描，非手动 `Ctrl+C` 也可优雅安全结束。
  - **修复 BUG-04 (网络阻塞导致崩溃强制退出)**：移除启动强行重试下载 GitHub Raw 逻辑，网络不通绝不崩溃，平滑使用内嵌数据。
  - **修复 BUG-05 (CDN 检测死代码重构)**：重新激活基于 CNAME、HTTP 强响应头、NS 记录与证书签发者的多维度 CDN 识别引擎。
  - **修复 BUG-06 (星级排序颠倒)**：调整为 5 星优质推荐在最上方（降序），延迟更低者优先。
  - **修复 BUG-07 (无阻塞 & 去广告)**：去除启动网络阻塞检查，剔除商业机场推广广告。
  - **修复 BUG-08 (VPS 邻近 IP 关联保护)**：探测出的 VPS 邻近 IP 始终与域名深度绑定，保证伪装目标与 VPS 同机房、同网段的最佳伪装效果。

---

## 🚀 一条龙快速上手指南

按照以下流程，即可完成从零安装 Go、项目编译、配置全局终端随处可用以及实战运行的全过程：

```
[步骤 1: 环境准备] ➔ [步骤 2: 项目编译] ➔ [步骤 3: 全局配置] ➔ [步骤 4: 可选别名] ➔ [步骤 5: 实战运行]
 (安装 Go 环境)      (本机/跨平台编译)     (随时随地可用)       (缩写为 rs)        (扫描与质量评估)
```

---

### 步骤 1：环境准备（安装 Go 语言）

本工具要求 **Go 1.21** 或更高版本。若您的电脑已安装 Go，可跳过此步；若尚未安装，请按对应系统选择安装方式：

#### 🍏 macOS
- **方式 A（推荐，使用 Homebrew）**：
  ```bash
  brew install go
  ```
- **方式 B（官方安装包）**：
  前往 Go 官网 [go.dev/dl](https://go.dev/dl/) 下载 `.pkg` 安装包双击安装（Apple Silicon M系列选 `darwin-arm64`，Intel 芯片选 `darwin-amd64`）。

#### 🪟 Windows
- **方式 A（官方安装包）**：
  前往 [go.dev/dl](https://go.dev/dl/) 下载 Windows 安装程序（`.msi`），双击一路点击“Next”完成安装。
- **方式 B（使用包管理器）**：
  在 PowerShell 中运行：`winget install GoLang.Go`

#### 🐧 Linux (Ubuntu / Debian / CentOS)
- **Ubuntu / Debian**：
  ```bash
  sudo apt update && sudo apt install -y golang-go
  ```
- **通用官方最新版解压安装法**：
  ```bash
  wget https://go.dev/dl/go1.22.6.linux-amd64.tar.gz
  sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.22.6.linux-amd64.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
  ```

#### 验证与国内模块加速
安装完成后在终端验证：
```bash
go version
# 预期输出类似：go version go1.22.x darwin/arm64
```
> 💡 **国内网络加速提示**：如果您在国内网络环境下，建议配置国内 Go 模块代理：
> ```bash
> go env -w GOPROXY=https://goproxy.cn,direct
> ```

---

### 步骤 2：项目编译

进入项目根目录：
```bash
git clone https://github.com/您的用户名/reality-scanner.git
cd reality-scanner
```

#### 本机快速编译（当前系统）
```bash
# macOS / Linux
go build -ldflags="-s -w" -o reality-scanner main.go
chmod +x reality-scanner

# Windows (PowerShell)
go build -ldflags="-s -w" -o reality-scanner.exe main.go
```

#### （可选进阶）跨平台交叉编译
得益于 Go 的交叉编译特性，您可以在当前电脑上一键编译出适合其他操作系统的可执行文件：

```bash
# 交叉编译 Windows 64位 (.exe)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o reality-scanner.exe main.go

# 交叉编译 macOS 通用二进制 (Universal Binary，一份文件兼容 M 系列芯片与 Intel 芯片)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o rs-arm64 main.go
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o rs-amd64 main.go
lipo -create -output reality-scanner rs-arm64 rs-amd64 && rm rs-arm64 rs-amd64

# 交叉编译 Linux 64位 (绝大多数 VPS 环境)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o reality-scanner-linux-amd64 main.go
```

> **编译参数解释**：
> - `CGO_ENABLED=0`：纯静态编译，生成物在任何同架构机器上均可直接运行，零依赖；
> - `-ldflags="-s -w"`：剥离符号表和调试信息，将文件体积缩减约 35%；
> - `//go:embed`：GeoIP 数据库与所有规则库均已内嵌，生成的可执行文件拷贝到任何地方都能独立完整运行。

---

### 步骤 3：配置全局环境（终端随处可用）

将编译好的程序配置到系统全局路径，使您无需每次切换目录，在任意路径下直接输入 `reality-scanner` 即可调用：

#### 🍏 macOS 用户
- **方法 A（系统命令目录拷贝，最推荐）**：
  ```bash
  sudo cp reality-scanner /usr/local/bin/
  ```
- **方法 B（创建软链接，源码重新编译时自动生效）**：
  ```bash
  sudo ln -sf "$(pwd)/reality-scanner" /usr/local/bin/reality-scanner
  ```
- **方法 C（免 sudo 权限，配置用户专属目录）**：
  ```bash
  mkdir -p ~/.local/bin && cp reality-scanner ~/.local/bin/
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
  ```

#### 🐧 Linux 用户 (VPS / 服务器)
```bash
# 直接安装至 /usr/local/bin
sudo cp reality-scanner /usr/local/bin/ && sudo chmod +x /usr/local/bin/reality-scanner
```

#### 🪟 Windows 用户 (PowerShell / CMD)
- **方法 A（PowerShell 一行命令配置用户 Path，最推荐）**：
  ```powershell
  # 1. 创建固定存放目录并将编译好的 exe 放进去
  New-Item -ItemType Directory -Force -Path "C:\Tools\reality-scanner"
  Copy-Item .\reality-scanner.exe "C:\Tools\reality-scanner\"

  # 2. 将该目录永久加入当前用户的 PATH 环境变量 (新开终端窗口即永久生效)
  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";C:\Tools\reality-scanner", "User")
  ```
- **方法 B（图形界面 GUI 配置）**：
  1. 将 `reality-scanner.exe` 放入固定目录（如 `C:\Tools\`）；
  2. 按快捷键 `Win + R`，输入 `sysdm.cpl` 回车打开系统属性；
  3. 点击 **“高级”** ➔ **“环境变量”** ➔ 在“用户变量”中双击 **`Path`** ➔ 点击 **“新建”** ➔ 填入 `C:\Tools` ➔ 确定保存。
- **方法 C（极速法）**：
  以管理员身份直接将 `reality-scanner.exe` 复制到 `C:\Windows\System32\` 目录（该目录默认在系统 PATH 中，即刻全局生效）。

---

### 步骤 4：（可选）配置极短命令别名（缩写为 `rs`）

如果您觉得输入完整的 `reality-scanner` 较长，可以配置一个超短别名 `rs`：

#### 🍏 macOS / 🐧 Linux 用户
```bash
# 如果当前使用的是 Zsh (macOS 默认)
echo "alias rs='reality-scanner'" >> ~/.zshrc && source ~/.zshrc

# 如果当前使用的是 Bash (Linux 常见默认)
echo "alias rs='reality-scanner'" >> ~/.bashrc && source ~/.bashrc
```
或直接创建极短软链接：
```bash
sudo ln -sf /usr/local/bin/reality-scanner /usr/local/bin/rs
```

#### 🪟 Windows 用户
直接在工具存放目录下将可执行文件复制一份为 `rs.exe`（在 CMD、PowerShell 与 Git Bash 下均可原生调用）：
```powershell
Copy-Item "C:\Tools\reality-scanner\reality-scanner.exe" "C:\Tools\reality-scanner\rs.exe"
```

---

### 步骤 5：实战运行与常用命令

新打开任意一个终端窗口，脱离项目根目录，即可随时使用：

```bash
# 1. 验证全局可用性（或使用别名 rs）
reality-scanner version

# 2. 一体化全自动扫描 VPS 邻近网段 (以 103.103.245.124 为中心，辐射 64 个邻近 IP，25 线程)
reality-scanner scan -addr 103.103.245.124 -radius 64 -thread 25 -out reality_results.txt

# 3. 扫描指定的 CIDR 网段
reality-scanner scan -addr 103.103.245.0/24 -thread 30

# 4. 单独对某个域名进行 Reality 质量合规诊断
reality-scanner check apple.com

# 5. 并发批量评估多个域名
reality-scanner batch apple.com tesla.com microsoft.com

# 6. 智能导入已有 CSV 文件进行质量评估 (兼容 5 列、11 列及任意格式)
reality-scanner csv file.csv

# 7. 检查并一键更新 GeoIP 数据库与规则文件 (支持国内镜像加速)
reality-scanner update
```

---

## 📖 命令行参数完整说明

### `scan` 命令参数列表

| 参数 | 类型 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `-addr` | string | (必填) | 扫描目标：可填单个 VPS IP、CIDR 掩码段（如 `/24`）或域名 |
| `-radius` | int | `64` | 当 `-addr` 为单 IP 时的双向辐射扫描半径（探测 IP 数量为 `2 * radius`） |
| `-thread` | int | `20` | 并发网络探测线程数 |
| `-port` | int | `443` | 探测的目标端口（TLS 默认 443） |
| `-timeout` | duration | `3s` | 单次 TLS 握手及探测超时时间 |
| `-out` | string | `""` | 将评估合格的推荐结果保存至文件（支持 `.txt` 或 `.csv`） |
| `-infinite` | bool | `false` | 是否开启无限辐射扫描模式（持续运行直至手动中断） |

---

## 📊 质量评估指标说明

| 指标 | 达标要求 | 说明 |
| :--- | :--- | :--- |
| **基础指标** | TLS 1.3 + X25519 + HTTP/2 + SNI 匹配 | Reality 协议的**硬性技术门槛**，有一项不满足即被判定为“不适合”。 |
| **DNS 匹配** | 直连 (1:1) / 同C段 为最佳 | 通过公网权威 DNS 交叉验证。直连目标赋予 ★★★★★，套 CDN 源站降权，无解析域名直接剔除。 |
| **握手耗时** | <= 200ms 为优秀 | 握手越快，连接延迟越低，越推荐。 |
| **证书天数** | >= 60天为充沛 | 证书剩余有效期越长，伪装目标长期有效性越好。 |
| **CDN 特征** | 无 CDN 为最佳 | 带有 CDN 特征的域名容易被重定向或二次检验，无 CDN 目标安全性最高。 |
| **热门网站** | 否 为最佳 | Apple、Google、Microsoft 等大厂高频域名容易受重点监测，小众合规目标评分更高。 |
| **推荐星级** | ★★★★★ 最高 | 5 星代表各项硬性指标全满、DNS 直连同服、无 CDN、非热门大厂且延迟低。 |

---

## 📜 开源许可证与致谢 (License & Acknowledgements)

本项目遵循 **[Mozilla Public License Version 2.0 (MPL-2.0)](LICENSE)** 协议开源。

### 核心项目致谢
本项目是在以下优秀的开源项目思想与代码启发下进行的深度融合、重构与漏洞修复，感谢原作者的贡献：

1. **[RealiTLScanner](https://github.com/XTLS/RealiTLScanner)** by [XTLS 团队 / RPRX](https://github.com/XTLS)
   - 协议：**MPL-2.0**
   - 启发：TLS 快速探测、受控辐射 IP 迭代及 Reality 证书捕获设计。
2. **[RealityChecker](https://github.com/V2RaySSR/RealityChecker)** by [V2RaySSR](https://github.com/V2RaySSR)
   - 启发：Reality 域名检测流水线（CDN 特征、大厂热门降权、GFW 状态评估等）。
3. **[Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip)** & **[Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)**
   - 协议：CC BY-SA 4.0 / GPL-3.0
   - 贡献：提供高质量的 GeoIP 数据库与 GFW 过滤规则集。
