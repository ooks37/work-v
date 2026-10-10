# 🚀 Work-V

> **v2.1.0**：稳定性与安全性修复版 — 修复了系统设置丢失、Agent 内核状态误判、
> 主控 WS 崩溃、订阅为空、安装脚本 Host 注入、流量错记等 20 余处问题，
> 详见 [CHANGELOG.md](CHANGELOG.md)。

> **极简、现代、开箱即用的分布式代理/VPN 主控与子节点管理系统。**
> 灵感源自 Komari 现代化探针与 Marzban，具备高颜值卡片流仪表盘、单行脚本纳管节点、全能自适应多端订阅与秒级流量熔断。

---

## ✨ 核心特性

- 🎨 **Komari 风格现代卡片流**：
  - 玻璃拟态深色质感，支持深浅色自适应。
  - 实时动效：各节点实时 CPU、内存占用、实时上行/下行速率（RX/TX）波形动画与心跳状态。
- ⚡ **Sing-box 现代核心驱动**：
  - **VLESS-Reality**：开箱即用，免域名、免申请证书，自动生成 x25519 密钥对与苹果/微软伪装。
  - **Hysteria 2 / TUIC**：超强 UDP 弱网加速，支持自签免配置与真实域名。
  - **Shadowsocks-2022**：纯单端口高速多用户协议。
- 🌐 **反向安全长连调度池 (NAT-Friendly)**：
  - 子节点 Agent 主动以 WebSocket + 专属 Token 连回主控。
  - **免配置端口映射**：无论子节点是 NAT 小鸡、动态 IP 还是无独立公网 IP，均可一键纳入纳管。
- 📱 **全能自适应订阅系统**：
  - 一个订阅链接走天下 (`/sub/:token`)，根据客户端 `User-Agent` 智能自适应返回：
    - **Clash / Mihomo (Clash Verge)** YAML 配置（含自动测速组与分流规则）
    - **Sing-box** 官方 JSON 订阅
    - **Shadowrocket (小火箭) / V2rayN** 通用 Base64 单节点链接
  - 原生支持客户端直接显示流量用量进度与到期倒计时。
- 🛡️ **生产级安全防御**：
  - 现代化安全登录框，Bcrypt 高强度密码加盐哈希。
  - 内置防暴力破解限流保护（5 分钟内连续 5 次失败自动封锁冷却）。
  - JWT 安全无状态鉴权与强安全响应头（X-Frame-Options, CSP, HSTS, CORS）。
- ⏱️ **秒级集中流量计费与熔断**：
  - Agent 毫秒级差量上报，支持设置节点独立流量倍率（如专线 1.5x）。
  - 超出配额或到期瞬间，主控全网广播 `USER_CUTOFF`，秒级剔除违规连接。
- 📦 **零依赖单二进制与 Docker 双部署**：
  - 纯 Go 编写（内嵌纯 Go SQLite 驱动，无 CGO 依赖），常驻内存极低（< 20MB）。
  - 支持 Docker 一键启动，也支持 Linux 原生一键二进制。

---

## 🏗️ 架构拓扑

```
                     ┌─────────────────────────────────────────┐
                     │          多端客户端 (Clients)            │
                     │  Clash Verge / Sing-box / Shadowrocket  │
                     └────────────────────┬────────────────────┘
                                          │
                  1. 拉取自适应订阅        │ 2. 节点代理翻墙流量
                                          ▼
┌─────────────────────────────────────────┴─────────────────────────────────────────┐
│                               Work-V 主控 (Master)                                │
│                                                                                   │
│  [Komari Web UI] ── [JWT 安全网关] ── [自适应订阅引擎] ── [配额秒级熔断] ── [SQLite]  │
│                                           │                                       │
│                                  [WebSocket 长连池]                                │
└───────────────────────────────────────────┬───────────────────────────────────────┘
                                            │ 反向长连 (Token Heartbeat / Sync)
                   ┌────────────────────────┴────────────────────────┐
                   ▼                                                 ▼
     ┌───────────────────────────┐                     ┌───────────────────────────┐
     │   节点 A (海外原生/香港)    │                     │    节点 B (NAT机/专线)     │
     │  [work-v-agent]           │                     │  [work-v-agent]           │
     │        │                  │                     │        │                  │
     │  [Sing-box 核心进程]       │                     │  [Sing-box 核心进程]       │
     └───────────────────────────┘                     └───────────────────────────┘
```

---

## 🚀 快速开始与一键部署

### 方式一：全环境自适应一键安装 (推荐，支持纯 IP 或自定义域名)

本脚本全面支持 Ubuntu / Debian / CentOS / Alpine / Rocky，自动检测系统架构 (amd64 / arm64)、低配小鸡 Swap 自动挂载、TCP BBR 加速与防火墙端口放行。

#### 1. 交互式部署向导 (自动引导选择纯 IP 或域名)
```bash
curl -fsSL https://raw.githubusercontent.com/ooks37/work-v/main/scripts/install.sh | bash
```
> 安装向导将自动询问是否绑定域名：
> - 若选择**纯 IP 模式**：安装完成后执行 `work-v default` 查看**随机安全入口**地址（宝塔风格，每次安装随机生成）。
> - 若选择**域名绑定模式**：输入您的域名（如 `panel.example.com`），脚本将自动配置主控并在系统中生成 Nginx 反代配置。

#### 2. 命令行静默部署 (可选纯 IP 或指定域名)
```bash
# 模式 A：纯 IP 直连部署 (无域名，开箱即用)
curl -fsSL https://raw.githubusercontent.com/ooks37/work-v/main/scripts/install.sh | bash -s -- --master

# 模式 B：自定义域名 + Nginx 自动反代部署
curl -fsSL https://raw.githubusercontent.com/ooks37/work-v/main/scripts/install.sh | bash -s -- --master --domain panel.example.com --nginx
```

---

### 方式二：Docker Compose 极速启动

1. 克隆项目或上传配置文件：
   ```bash
   git clone https://github.com/ooks37/work-v.git
   cd work-v
   ```

2. 一键启动服务：
   ```bash
   docker compose up -d
   ```

3. 访问 Web 控制台：
   - 浏览器打开：`http://<你的服务器IP>:8080/` 会看到安全入口提示页；入口路径用 `work-v default` 查询（默认安装会随机生成）
   - **默认管理员账号**：`admin`
   - **默认初始密码**：`admin123456`

---

### 方式三：原生 Linux 二进制部署

```bash
# 1. 编译二进制
go build -o work-v-master ./cmd/master

# 2. 启动主控 (支持 -domain 可选绑定域名)
# 纯 IP 模式：
./work-v-master -port 8080 -db ./data/work-v.db

# 域名模式：
./work-v-master -port 8080 -db ./data/work-v.db -domain panel.example.com
```

---

## 🛠️ 终端运维命令 (`work-v`)

主控部署完成后，系统已自动注册类似宝塔 `bt` 的运维指令 `work-v`：

```bash
# 打开交互式运维菜单
work-v

# 查看控制台访问入口与安全凭据
work-v default

# 绑定 / 修改外网访问域名 (输入 none 可清除域名恢复纯 IP 访问)
work-v domain panel.example.com
work-v domain none

# 安全入口与密码管理
work-v set-entry /my_secret_path   # 修改安全入口路径
work-v disable-entry               # 一键关闭安全入口限制
work-v passwd                      # 交互式修改管理员密码
work-v reset-admin                 # 重置管理员密码为默认值

# 服务与节点运维
work-v restart                     # 重启主控与从节点服务
work-v status                      # 查看运行状态与内存占用
work-v logs                        # 实时查看服务日志
```

---

## 🖥️ 纳管子节点 (一键部署)

1. 登录 Web 控制台，进入 **节点管理** -> 点击 **+ 添加节点**。
2. 填写节点名称（如 `香港01-BGP`）与客户端连接域名/IP，保存后系统会自动生成专属 Token。
3. 点击节点卡片上的 **📋 安装命令**，复制单行部署脚本并在目标服务器执行：
   ```bash
   curl -fsSL http://<你的主控IP>:8080/install.sh | bash -s -- --token <NODE_TOKEN> --server http://<你的主控IP>:8080
   ```
4. 目标服务器会自动安装 Sing-box 核心并自启守护服务，3 秒内自动点亮主控绿色在线指示灯！

> **NAT / 端口映射机器注意**：节点实际监听端口由主控下发（默认 `2083/tcp`、`2053/tcp`、`8445/tcp`、
> `8443/udp`、`8444/udp`），安装脚本会自动在防火墙放行这些端口。
> 公网映射请在云厂商/路由器侧把这些端口转发到该节点；`--port` 参数只用于额外的放行与记录，
> 不会改变节点监听端口。

---

## 👥 用户与订阅提取

1. 在 **用户订阅** 页面点击 **+ 创建用户**，设置用户名、流量配额（GB）与有效期天数。
2. 点击 **🔗 提取订阅**：
   - **通用单链接**：自动识别客户端 UA（推荐）
   - **Clash / Mihomo**：一键导入或拷贝 YAML 链接
   - **Sing-box**：官方 JSON 配置链接
   - **小火箭**：Base64 链接导入

---

## 🔒 安全性设计

- **防爆破防护**：内置 IP 级错误尝试限流器，5 分钟内连续 5 次失败自动锁停 300 秒。
- **密码存储**：强制采用行业金标准 `bcrypt` 算法加盐哈希，数据库明文零泄露风险。
- **免证书 Reality**：基于 x25519 密钥对与 TLS 伪装握手，无需向证书机构暴露节点存在，天然抗审查。
- **安全响应头**：内置 `X-Frame-Options`、`X-Content-Type-Options`、`CSP`，全面杜绝点击劫持与 MIME 嗅探。
- **安装脚本防注入**：`/install.sh` 会对请求 `Host` 头做严格白名单校验（域名/IP + 数字端口），
  并采用字面量替换，杜绝把客户端输入注入到以 root 执行的脚本中。
- **安全入口持久化**：安全入口开关以显式配置项 `safe_entry_enabled` 落库，
  `work-v disable-entry` 重启后依然生效。
- **纯 Go 自签证书**：Hysteria2 / TUIC / AnyTLS 所需的证书由节点本地用 ECDSA 自签生成（不依赖 openssl）；
  证书不可用时只跳过这些入站，Reality 不受影响。
- **Token 与配置文件保护**：节点 Token 在日志中脱敏，`sing-box.json`（含 Reality 私钥与用户 UUID）权限为 `0600`。

> ⚠️ 部署建议：节点安装脚本与 Agent 二进制默认通过主控的 HTTP 端口分发，
> 生产环境请务必配置 HTTPS 反向代理（`--nginx` + certbot），避免明文分发与 Token 泄露风险。

---

## 📜 许可证

本项目采用 [MIT License](LICENSE) 开源许可。
