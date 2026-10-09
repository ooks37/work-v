# 更新日志

## v2.1.0 — 稳定性 / 安全性修复版

本版针对一次完整代码审计发现的问题做修复，全部修复点均补了回归测试
(`go build ./...`、`go vet ./...`、`go test ./...` 全绿)。

### 严重 (会导致配置丢失、进程崩溃或功能不可用)

1. **修复系统设置"改第二次就丢"** — `internal/master/model/db.go`
   `SetSetting` 误把 `os.Getenv("TZ")` 写进 `updated_at` 时间列，导致该行之后无法被 GORM 扫描。
   表现为域名、JWT 密钥等设置第二次修改后读取为空（Docker 环境因为显式设置 `TZ` 必现）。
   同时新增 `repairSystemSettings`，启动时自动修复历史脏数据。

2. **修复 Agent 重载配置后"内核已停止"** — `internal/agent/runner/runner.go`
   旧进程的 watcher 协程会把新进程的运行状态改成未运行，导致面板状态错误，
   且 `ApplyConfig` 的幂等判断永久失效（每次下发配置都重启内核、切断所有用户连接）。

3. **修复主控 `send on closed channel` 崩溃** — `internal/master/hub/hub.go`
   配置下发与节点重连撞车时会 panic 并打挂主控进程。现在发送全程持锁，无法再命中已关闭通道。

4. **修复 `-domain` 命令不退出** — `cmd/master/main.go`
   该命令会继续在前台启动 HTTP 服务：主控运行时抢端口失败以退出码 1 结束，
   而 `work-v`/`install.sh` 都是 `set -e`，后续 systemd 改写与重启全部不执行。

5. **修复 `work-v disable-entry` 重启后失效** — `cmd/master/main.go`、`model/db.go`
   改用显式开关 `safe_entry_enabled`，不再用"路径为空"表示关闭。
   Web 端"安全入口"接口同步修复。

6. **修复订阅对未落库入站的节点返回空** — `internal/master/sub/sub.go`
   `work-v add-node` 建的节点没有 `InboundsJSON`，订阅里一个节点都不出现（面板却显示正常）。
   现在与面板一致，回落到默认入站配置。

### 高 (计费 / 安全 / 协议)

7. **节点安装脚本接口的 Host 注入** — `internal/master/server.go`
   新增 `sanitizeHost` 严格校验，并改用 `ReplaceAllLiteralString`（原实现会把 `$1` 当捕获组）。

8. **流量不再错记到第一个用户** — `internal/agent/runner/runner.go`
   无法归属的连接/全局流量不再硬塞给 `activeUsers[0]`，避免用户被他人流量拖到超额熔断。

9. **sing-box 重启后重置流量快照** — `internal/agent/runner/runner.go`
   修复重载后累计计数器归零导致增量判断长期失效（漏计费）。

10. **删除节点时主动断开长连** — `internal/master/api/handlers.go`、`hub.KickNode`
    被删节点不会再带着最后一份配置继续为用户服务。

11. **证书改为纯 Go 自签生成** — `internal/agent/runner/runner.go`
    不再依赖 `openssl`；证书确实不可用时只跳过 Hysteria2 / TUIC / AnyTLS，
    而不是让整份配置（含 VLESS）校验失败。修复 AnyTLS 服务端缺少证书的非法配置。

12. **`install.sh --entry` 真正生效** — 之前只解析不写入，用户以为改了安全入口其实没有。

### 其他

- 节点 Token 日志脱敏；配置文件 `sing-box.json` 权限收紧为 `0600`。
- 登录 Cookie 增加 `SameSite=Lax`，HTTPS 反代场景自动带 `Secure`。
- 登录失败限流表增加过期清理，避免被大量源 IP 撑爆内存。
- 配置下发新增 `config_ack` 回执，主控日志可看到节点是否真正应用成功。
- Agent 上报的版本号改为真实版本（此前是 Go 运行时版本）；`uptime` 改为系统开机时长。
- Agent 所有 WebSocket 写操作串行化（此前配置回执与心跳并发写会触发 gorilla 的并发写限制）。
- `-add-node`/`-entry` 在纯 IP 模式下打印可用的内网地址，不再硬编码 `127.0.0.1`。
- `-set-password` 不再回显明文；`-set-password`/`-reset-admin` 增加"管理员记录不存在"的失败提示。
- 安装脚本 `read_input` 改用 `printf -v`，消除 `eval` 注入面；节点安装时自动放行协议所需端口。
- NAT 机器上 `--port` 的行为改为如实说明（仅防火墙放行/记录，节点监听端口由主控下发）。

### 已知限制 (本版未改动)

- 节点安装脚本与 agent 二进制仍通过明文 HTTP 分发，`--token` 出现在命令行与 systemd unit 中，
  建议尽快部署 HTTPS 反代。
- 主控"一键升级 sing-box"仍未做哈希/签名校验。
- API 仍无 CSRF token（已依赖 `SameSite=Lax` 与 Bearer 头）。
- SQLite 连接池仍为单连接（`SetMaxOpenConns(1)`），高写入场景会是瓶颈。
