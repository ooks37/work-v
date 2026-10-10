package runner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"work-v/internal/common"
)

type connTrafficSnap struct {
	Upload   int64
	Download int64
	UserUUID string
}

type SingboxRunner struct {
	mu            sync.Mutex
	singboxPath   string
	configDir     string
	clashSecret   string
	cmd           *exec.Cmd
	pidFile       string
	exited        chan struct{} // 当前内核进程的收尸信号 (由 watcher 关闭)
	running       bool
	currentHash   string
	activeUsers   []common.UserProfile
	lastConns     map[string]connTrafficSnap // connID -> snap
	totalUpSnap   int64
	totalDownSnap int64
	logMu         sync.Mutex
	logs          []string
}

func NewSingboxRunner(singboxPath, configDir string) *SingboxRunner {
	if singboxPath == "" {
		singboxPath = "sing-box"
	}
	if configDir == "" {
		configDir = "config"
	}
	_ = os.MkdirAll(configDir, 0755)

	secretBytes := make([]byte, 16)
	_, _ = rand.Read(secretBytes)

	return &SingboxRunner{
		singboxPath: singboxPath,
		configDir:   configDir,
		pidFile:     filepath.Join(configDir, "sing-box.pid"),
		clashSecret: hex.EncodeToString(secretBytes),
		lastConns:   make(map[string]connTrafficSnap),
		logs:        make([]string, 0, 150),
	}
}

func (r *SingboxRunner) IsRunning() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.running
}

func (r *SingboxRunner) GetPid() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil && r.cmd.Process != nil && r.running {
		return r.cmd.Process.Pid
	}
	return 0
}

// realityHandshake 生成 Reality 拨号目标 {server, server_port}。
//
// 致命点 (实测确认): sing-box 的 handshake 由 ServerOptions{server, server_port} 两个独立字段组成,
// 若把 "gateway.icloud.com:443" 整串写进 server, server_port 就是 0,
// sing-box 会把整串当成域名去解析 -> NXDOMAIN -> vless-reality / gRPC-Reality 全部握手失败,
// 而 sing-box check 并不校验该拨号目标, 语法校验永远是绿的, 缺陷极难发现。
func realityHandshake(dest string) map[string]any {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		dest = "gateway.icloud.com:443"
	}
	host, port := dest, 443
	if h, p, err := net.SplitHostPort(dest); err == nil {
		host = h
		if pn, convErr := strconv.Atoi(p); convErr == nil && pn > 0 && pn <= 65535 {
			port = pn
		}
	} else {
		log.Printf("[Sing-box] ⚠️ Reality dest %q 未包含端口, 已按 443 处理", dest)
	}
	return map[string]any{"server": host, "server_port": port}
}

// ApplyConfig 动态渲染 sing-box 配置文件并热启动/重载
func (r *SingboxRunner) ApplyConfig(payload *common.NodeConfigPayload) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if payload.ConfigHash == r.currentHash && r.running {
		return nil // 配置无变化且正在运行
	}

	configFile := filepath.Join(r.configDir, "sing-box.json")
	tmpFile := filepath.Join(r.configDir, fmt.Sprintf(".sing-box.%d.tmp", time.Now().UnixNano()))
	sbJSON, err := generateSingboxJSON(payload, r.configDir, r.clashSecret)
	if err != nil {
		return fmt.Errorf("生成 sing-box 配置失败: %w", err)
	}

	// 该文件含 Reality 私钥与全部用户 UUID, 仅限属主可读
	if err := os.WriteFile(tmpFile, sbJSON, 0600); err != nil {
		return fmt.Errorf("写入临时配置文件失败: %w", err)
	}

	// 校验配置合法性
	checkCmd := exec.Command(r.singboxPath, "check", "-c", tmpFile)
	if out, err := checkCmd.CombinedOutput(); err != nil {
		_ = os.Remove(tmpFile)
		log.Printf("[Sing-box] ⚠️ 新配置语法校验未通过，维持原配置运行: %v (输出: %s)", err, string(out))
		return fmt.Errorf("sing-box 配置语法校验未通过: %w", err)
	}

	// 原子替换。绝不做"降级为 0644 直接覆盖"的兜底: 那既会把含 Reality 私钥与用户 UUID
	// 的配置降权给同机其他用户读, 又可能让内核读到半截文件。
	if err := os.Rename(tmpFile, configFile); err != nil {
		_ = os.Remove(tmpFile)
		return fmt.Errorf("替换 sing-box 配置文件失败: %w", err)
	}

	// 重新启动 Sing-box 进程; 只有真正启动成功后才认为新配置生效
	if err := r.restartProcess(configFile); err != nil {
		return err
	}
	// 用户名单必须在配置生效后才切换: 否则启动失败时运行中的内核仍是旧名单,
	// 被移除用户的流量会变成"无法归属"而漏计, 计费口径错乱。
	r.activeUsers = payload.Users
	r.currentHash = payload.ConfigHash

	// 异步放行入站端口，避免操作系统防火墙 (ufw / iptables) 丢弃 5 位数随机端口流量导致客户端超时
	go ensureFirewallPorts(payload.Inbounds)
	return nil
}

// ensureFirewallPorts 自动放行入站端口 (支持 ufw / iptables，规避 5 位数随机端口连接超时)
func ensureFirewallPorts(inbounds []common.InboundConfig) {
	if runtime.GOOS != "linux" {
		return
	}
	for _, in := range inbounds {
		if !in.Enabled || in.ListenPort <= 0 || in.ListenPort > 65535 {
			continue
		}
		portStr := strconv.Itoa(in.ListenPort)
		_ = exec.Command("ufw", "allow", portStr+"/tcp").Run()
		_ = exec.Command("ufw", "allow", portStr+"/udp").Run()
		if err := exec.Command("iptables", "-C", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT").Run(); err != nil {
			_ = exec.Command("iptables", "-I", "INPUT", "-p", "tcp", "--dport", portStr, "-j", "ACCEPT").Run()
		}
		if err := exec.Command("iptables", "-C", "INPUT", "-p", "udp", "--dport", portStr, "-j", "ACCEPT").Run(); err != nil {
			_ = exec.Command("iptables", "-I", "INPUT", "-p", "udp", "--dport", portStr, "-j", "ACCEPT").Run()
		}
	}
}

type rollingLogWriter struct {
	runner *SingboxRunner
}

func (w *rollingLogWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	text := strings.TrimSpace(string(p))
	if text != "" {
		w.runner.appendLog(text)
	}
	os.Stdout.Write(p)
	return n, nil
}

func (r *SingboxRunner) appendLog(msg string) {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	lines := strings.Split(msg, "\n")
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		r.logs = append(r.logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), l))
	}
	if len(r.logs) > 150 {
		r.logs = r.logs[len(r.logs)-150:]
	}
}

// GetRecentLogs 获取最近内核运行日志
func (r *SingboxRunner) GetRecentLogs() []string {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	res := make([]string, len(r.logs))
	copy(res, r.logs)
	return res
}

// Restart 手动重启 Sing-box 内核进程
func (r *SingboxRunner) Restart() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	configFile := filepath.Join(r.configDir, "sing-box.json")
	if _, err := os.Stat(configFile); err != nil {
		return fmt.Errorf("配置文件不存在: %w", err)
	}
	return r.restartProcess(configFile)
}

func (r *SingboxRunner) restartProcess(configFile string) error {
	if r.cmd != nil && r.cmd.Process != nil && r.running {
		log.Println("[Sing-box] 正在重启进程以加载新配置...")
		// 只负责杀进程组。绝不能在这里再调 cmd.Wait():
		// 后台 watcher 已经在 Wait 同一个 *exec.Cmd, 两个 Wait 并发会竞争写 ProcessState
		// (Go 的 exec.Cmd 明确要求只 Wait 一次), 严重时会把 mu 永久锁死。
		// 这里改为等待 watcher 发出的收尸信号。
		done := r.exited
		killProcessGroup(r.cmd.Process.Pid)
		if done != nil {
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				log.Println("[Sing-box] ⚠️ 等待旧内核退出超时, 继续启动新内核")
			}
		}
		r.running = false
	}

	// 首次启动 (或上次异常退出) 时先清理遗留孤儿, 否则新内核绑不上端口
	reapStaleProcess(r.pidFile, r.singboxPath)

	// 进程被替换意味着 Clash API 的连接表与累计计数器都已归零, 必须同步清空本地快照,
	// 否则新进程的 total 永远小于旧快照, 增量判断长期失效 (漏计费)。
	r.lastConns = make(map[string]connTrafficSnap)
	r.totalUpSnap = 0
	r.totalDownSnap = 0

	cmd := exec.Command(r.singboxPath, "run", "-c", configFile)
	logW := &rollingLogWriter{runner: r}
	cmd.Stdout = io.MultiWriter(os.Stdout, logW)
	cmd.Stderr = io.MultiWriter(os.Stderr, logW)
	setProcessGroup(cmd) // 自成进程组: 退出/重启时可整组回收, 不留孤儿

	if err := cmd.Start(); err != nil {
		r.running = false
		r.appendLog("进程启动失败: " + err.Error())
		return fmt.Errorf("启动 sing-box 进程失败: %w", err)
	}
	r.cmd = cmd
	r.running = true
	writePidFile(r.pidFile, cmd.Process.Pid)
	r.appendLog(fmt.Sprintf("Sing-box 进程启动成功, PID=%d", cmd.Process.Pid))
	log.Printf("[Sing-box] 进程启动成功, PID=%d", cmd.Process.Pid)

	// 后台等待协程: 只允许"自己这一轮"的进程修改运行状态。
	// 历史实现无条件置 running=false, 旧进程被 kill 后其 watcher 会在新进程启动完成之后把
	// 状态改回未运行 -> 面板显示"内核已停止", 且 ApplyConfig 的幂等短路永久失效,
	// 于是每次下发配置都要重启内核、切断全部用户连接。
	exited := make(chan struct{})
	r.exited = exited
	go func(c *exec.Cmd) {
		_ = c.Wait()
		r.mu.Lock()
		if r.cmd == c {
			r.running = false
		}
		r.mu.Unlock()
		close(exited)
		r.appendLog("Sing-box 进程已退出")
		log.Printf("[Sing-box] 进程已退出 (PID=%d)", c.Process.Pid)
	}(cmd)

	return nil
}

// Stop 停止内核进程。agent 收到退出信号时必须调用:
// 否则 sing-box 会成为孤儿进程继续占住 2083/2053/8443/8444 端口,
// 导致下一次启动的内核绑定失败 (实测确认的问题)。
func (r *SingboxRunner) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd != nil && r.cmd.Process != nil {
		log.Printf("[Sing-box] 正在停止内核进程 (PID=%d)...", r.cmd.Process.Pid)
		// 只负责杀进程组, 收尸交给后台 watcher 的 cmd.Wait, 避免并发 Wait 竞争
		killProcessGroup(r.cmd.Process.Pid)
	}
	r.running = false
	_ = os.Remove(r.pidFile)
}

// CutoffUser 针对违规/超额用户，定向精准剔除其连接 (避免无差别断开全服所有用户)
func (r *SingboxRunner) CutoffUser(userUUID string) {
	r.mu.Lock()
	secret := r.clashSecret
	r.mu.Unlock()

	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:9090/connections", nil)
	if err != nil {
		return
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data struct {
		Connections []struct {
			ID       string `json:"id"`
			Metadata struct {
				User string `json:"user"`
			} `json:"metadata"`
			Chains []string `json:"chains"`
		} `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return
	}

	killedCount := 0
	for _, c := range data.Connections {
		matched := false
		if c.Metadata.User == userUUID {
			matched = true
		} else {
			for _, ch := range c.Chains {
				if strings.Contains(ch, userUUID) {
					matched = true
					break
				}
			}
		}

		if matched {
			delReq, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("http://127.0.0.1:9090/connections/%s", c.ID), nil)
			if secret != "" {
				delReq.Header.Set("Authorization", "Bearer "+secret)
			}
			_, _ = client.Do(delReq)
			killedCount++
		}
	}
	log.Printf("[Sing-box] 定向清理超额用户 %s 活跃连接: 已安全剔除 %d 个连接", userUUID, killedCount)
}

// CollectTraffic 获取各用户周期内的真实流量增量 (对接 Sing-box Clash API 连接池)
func (r *SingboxRunner) CollectTraffic() []common.UserDeltaTraffic {
	r.mu.Lock()
	secret := r.clashSecret
	activeUsers := r.activeUsers
	r.mu.Unlock()

	if len(activeUsers) == 0 {
		return nil
	}

	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:9090/connections", nil)
	if err != nil {
		return nil
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var data struct {
		DownloadTotal int64 `json:"downloadTotal"`
		UploadTotal   int64 `json:"uploadTotal"`
		Connections   []struct {
			ID       string `json:"id"`
			Upload   int64  `json:"upload"`
			Download int64  `json:"download"`
			Metadata struct {
				User string `json:"user"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	userDeltas := make(map[string]*common.UserDeltaTraffic)
	currConnIDs := make(map[string]bool)
	unattributed := 0

	for _, c := range data.Connections {
		currConnIDs[c.ID] = true
		lastSnap, exists := r.lastConns[c.ID]

		var deltaUp, deltaDown int64
		if exists {
			deltaUp = c.Upload - lastSnap.Upload
			deltaDown = c.Download - lastSnap.Download
		} else {
			// 首次见到该连接: 只建立基线, 不能把"连接自建立以来的累计流量"当作本轮增量。
			// 历史实现直接取 c.Upload/c.Download: agent 重启(尤其内核仍在运行)后第一轮
			// 会把连接的全部历史流量重复上报, 用户瞬间超额被熔断。
			deltaUp, deltaDown = 0, 0
		}

		if deltaUp < 0 {
			deltaUp = 0
		}
		if deltaDown < 0 {
			deltaDown = 0
		}

		// 只按连接元数据归属流量。历史实现在识别不出用户时把流量记给 activeUsers[0],
		// 会让排在第一位的用户替所有人(以及内部连接)背流量, 被误判超额熔断。
		targetUUID := ""
		if c.Metadata.User != "" {
			for _, u := range activeUsers {
				if u.UUID == c.Metadata.User || u.Username == c.Metadata.User {
					targetUUID = u.UUID
					break
				}
			}
		}
		if targetUUID == "" {
			unattributed++
		}

		r.lastConns[c.ID] = connTrafficSnap{
			Upload:   c.Upload,
			Download: c.Download,
			UserUUID: targetUUID,
		}

		if (deltaUp > 0 || deltaDown > 0) && targetUUID != "" {
			if _, ok := userDeltas[targetUUID]; !ok {
				userDeltas[targetUUID] = &common.UserDeltaTraffic{UUID: targetUUID}
			}
			userDeltas[targetUUID].Up += deltaUp
			userDeltas[targetUUID].Down += deltaDown
		}
	}

	for id := range r.lastConns {
		if !currConnIDs[id] {
			delete(r.lastConns, id)
		}
	}

	if unattributed > 0 {
		log.Printf("[Sing-box] 本轮有 %d 个连接无法归属到具体用户, 其流量未计入任何配额", unattributed)
	}

	// 全局增量兜底
	if data.UploadTotal > r.totalUpSnap || data.DownloadTotal > r.totalDownSnap {
		globalDeltaUp := data.UploadTotal - r.totalUpSnap
		globalDeltaDown := data.DownloadTotal - r.totalDownSnap
		r.totalUpSnap = data.UploadTotal
		r.totalDownSnap = data.DownloadTotal

		// 只推进快照, 绝不把无法归属的增量硬塞给某个用户
		if len(userDeltas) == 0 && (globalDeltaUp > 0 || globalDeltaDown > 0) {
			log.Printf("[Sing-box] 本轮有 %d 字节全局流量无法归属到任何用户, 已跳过计费", globalDeltaUp+globalDeltaDown)
		}
	}

	result := make([]common.UserDeltaTraffic, 0, len(userDeltas))
	for _, dt := range userDeltas {
		if dt.Up > 0 || dt.Down > 0 {
			result = append(result, *dt)
		}
	}
	return result
}

// getOrCreateCert 返回可用的证书路径。第三个返回值表示证书是否真的可用:
// 历史实现忽略 openssl 的错误并无条件返回路径, 于是缺少 openssl / 目录不可写时,
// 配置里会引用不存在的证书文件 -> sing-box check 失败 -> 整份配置(含 VLESS)都下发不了。
func getOrCreateCert(configDir string) (certPath string, keyPath string, ok bool) {
	// 1. 检查节点本地证书
	localCert := filepath.Join(configDir, "cert.pem")
	localKey := filepath.Join(configDir, "key.pem")
	if fileExists(localCert) && fileExists(localKey) {
		return localCert, localKey, true
	}

	// 2. 检查系统通用 Let's Encrypt 证书目录
	matches, _ := filepath.Glob("/etc/letsencrypt/live/*/fullchain.pem")
	if len(matches) > 0 {
		dir := filepath.Dir(matches[0])
		kp := filepath.Join(dir, "privkey.pem")
		if fileExists(kp) {
			return matches[0], kp, true
		}
	}

	// 3. 自动生成自签证书 (纯 Go 实现, 不依赖节点是否安装 openssl)
	_ = os.MkdirAll(configDir, 0755)
	if err := ensureSelfSignedCert(localCert, localKey); err != nil {
		log.Printf("[Sing-box] ⚠️ 自签证书生成失败(目录不可写?): %v", err)
		return "", "", false
	}
	return localCert, localKey, true
}

// ensureSelfSignedCert 生成 ECDSA P-256 自签证书。
// 不依赖 openssl 命令行: 精简系统上它通常不存在, 而证书缺失会让整份 sing-box 配置校验失败。
func ensureSelfSignedCert(certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "gateway.icloud.com", Organization: []string{"Work-V"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"gateway.icloud.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	if err := writePEM(certPath, "CERTIFICATE", der); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER)
}

func writePEM(path, blockType string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// formatRealityKey 确保 Reality 密钥为 Base64 URL 格式 (兼容历史 64 字节 Hex 格式)
func formatRealityKey(k string) string {
	if len(k) == 64 {
		if b, err := hex.DecodeString(k); err == nil && len(b) == 32 {
			return base64.RawURLEncoding.EncodeToString(b)
		}
	}
	return k
}

// generateSingboxJSON 将通用的 NodeConfigPayload 转换为官方标准的 Sing-box json
func generateSingboxJSON(payload *common.NodeConfigPayload, configDir string, secretOptional ...string) ([]byte, error) {
	clashSecret := ""
	if len(secretOptional) > 0 {
		clashSecret = secretOptional[0]
	}
	inbounds := make([]map[string]any, 0)
	certPath, keyPath, certOK := getOrCreateCert(configDir)
	if !certOK {
		log.Println("[Sing-box] ⚠️ 未取得可用证书, 本次将跳过 Hysteria2 / TUIC / AnyTLS 入站(Reality 不受影响)")
	}

	for _, in := range payload.Inbounds {
		if !in.Enabled {
			continue
		}

		switch in.Type {
		case "vless":
			// 组装用户列表 (Vision)
			users := make([]map[string]any, 0)
			for _, u := range payload.Users {
				if u.Status == "active" {
					users = append(users, map[string]any{
						"name": u.Username,
						"uuid": u.UUID,
						"flow": "xtls-rprx-vision",
					})
				}
			}

			privKey := formatRealityKey(fmt.Sprintf("%v", in.Options["private_key"]))
			shortID, _ := in.Options["short_id"].(string)
			serverName, _ := in.Options["server_name"].(string)
			dest, _ := in.Options["dest"].(string)
			if serverName == "" {
				serverName = "gateway.icloud.com"
			}
			if dest == "" {
				dest = "gateway.icloud.com:443"
			}

			inbound := map[string]any{
				"type":        "vless",
				"tag":         in.Tag,
				"listen":      "::",
				"listen_port": in.ListenPort,
				"users":       users,
				"tls": map[string]any{
					"enabled":     true,
					"server_name": serverName,
					"reality": map[string]any{
						"enabled":     true,
						"handshake":   realityHandshake(dest),
						"private_key": privKey,
						"short_id":    []string{shortID},
					},
				},
			}
			inbounds = append(inbounds, inbound)

		case "grpc-reality":
			users := make([]map[string]any, 0)
			for _, u := range payload.Users {
				if u.Status == "active" {
					users = append(users, map[string]any{
						"name": u.Username,
						"uuid": u.UUID,
					})
				}
			}

			privKey := formatRealityKey(fmt.Sprintf("%v", in.Options["private_key"]))
			shortID, _ := in.Options["short_id"].(string)
			serverName, _ := in.Options["server_name"].(string)
			svcName, _ := in.Options["service_name"].(string)
			dest, _ := in.Options["dest"].(string)
			if serverName == "" {
				serverName = "gateway.icloud.com"
			}
			if svcName == "" {
				svcName = "grpc-service"
			}
			if dest == "" {
				dest = "gateway.icloud.com:443"
			}

			inbound := map[string]any{
				"type":        "vless",
				"tag":         in.Tag,
				"listen":      "::",
				"listen_port": in.ListenPort,
				"users":       users,
				"transport": map[string]any{
					"type":         "grpc",
					"service_name": svcName,
				},
				"tls": map[string]any{
					"enabled":     true,
					"server_name": serverName,
					"reality": map[string]any{
						"enabled":     true,
						"handshake":   realityHandshake(dest),
						"private_key": privKey,
						"short_id":    []string{shortID},
					},
				},
			}
			inbounds = append(inbounds, inbound)

		case "hysteria2":
			if !certOK {
				log.Printf("[Sing-box] 跳过 %s 入站: 证书不可用", in.Tag)
				continue
			}
			users := make([]map[string]any, 0)
			for _, u := range payload.Users {
				if u.Status == "active" {
					users = append(users, map[string]any{
						"name":     u.Username,
						"password": u.Password,
					})
				}
			}

			inbound := map[string]any{
				"type":        "hysteria2",
				"tag":         in.Tag,
				"listen":      "::",
				"listen_port": in.ListenPort,
				"users":       users,
				"tls": map[string]any{
					"enabled":          true,
					"certificate_path": certPath,
					"key_path":         keyPath,
				},
			}
			inbounds = append(inbounds, inbound)

		case "tuic":
			if !certOK {
				log.Printf("[Sing-box] 跳过 %s 入站: 证书不可用", in.Tag)
				continue
			}
			users := make([]map[string]any, 0)
			for _, u := range payload.Users {
				if u.Status == "active" {
					users = append(users, map[string]any{
						"name":     u.Username,
						"uuid":     u.UUID,
						"password": u.Password,
					})
				}
			}

			inbound := map[string]any{
				"type":               "tuic",
				"tag":                in.Tag,
				"listen":             "::",
				"listen_port":        in.ListenPort,
				"users":              users,
				"congestion_control": "bbr",
				"zero_rtt_handshake": false,
				"heartbeat":          "10s",
				"tls": map[string]any{
					"enabled":          true,
					"alpn":             []string{"h3"},
					"certificate_path": certPath,
					"key_path":         keyPath,
				},
			}
			inbounds = append(inbounds, inbound)

		case "anytls":
			if !certOK {
				log.Printf("[Sing-box] 跳过 %s 入站: 证书不可用", in.Tag)
				continue
			}
			users := make([]map[string]any, 0)
			for _, u := range payload.Users {
				if u.Status == "active" {
					users = append(users, map[string]any{
						"name":     u.Username,
						"password": u.Password,
					})
				}
			}

			// 服务端 TLS 必须提供证书; insecure 只是客户端选项, 放在服务端会导致配置校验失败
			inbound := map[string]any{
				"type":        "anytls",
				"tag":         in.Tag,
				"listen":      "::",
				"listen_port": in.ListenPort,
				"users":       users,
				"tls": map[string]any{
					"enabled":          true,
					"certificate_path": certPath,
					"key_path":         keyPath,
				},
			}
			inbounds = append(inbounds, inbound)

		case "shadowsocks":
			method, _ := in.Options["method"].(string)
			if method == "" {
				method = "2022-blake3-aes-128-gcm"
			}
			ssPassword, _ := in.Options["password"].(string)
			if ssPassword == "" {
				ssPassword = "d29ya3YxMjM0NTY3ODkwMQ=="
			}
			users := make([]map[string]any, 0)
			for _, u := range payload.Users {
				if u.Status == "active" {
					pwd := u.Password
					if pwd == "" {
						pwd = ssPassword
					}
					users = append(users, map[string]any{
						"name":     u.Username,
						"password": pwd,
					})
				}
			}
			inbound := map[string]any{
				"type":        "shadowsocks",
				"tag":         in.Tag,
				"listen":      "::",
				"listen_port": in.ListenPort,
				"method":      method,
				"password":    ssPassword,
			}
			if len(users) > 0 {
				inbound["users"] = users
			}
			inbounds = append(inbounds, inbound)

		case "vless-ws":
			users := make([]map[string]any, 0)
			for _, u := range payload.Users {
				if u.Status == "active" {
					users = append(users, map[string]any{
						"name": u.Username,
						"uuid": u.UUID,
					})
				}
			}
			wsPath, _ := in.Options["path"].(string)
			if wsPath == "" {
				wsPath = "/ws"
			}
			serverName, _ := in.Options["server_name"].(string)
			tlsOpt := map[string]any{
				"enabled":          true,
				"certificate_path": certPath,
				"key_path":         keyPath,
			}
			if serverName != "" {
				tlsOpt["server_name"] = serverName
			}
			inbound := map[string]any{
				"type":        "vless",
				"tag":         in.Tag,
				"listen":      "::",
				"listen_port": in.ListenPort,
				"users":       users,
				"transport": map[string]any{
					"type": "ws",
					"path": wsPath,
				},
				"tls": tlsOpt,
			}
			inbounds = append(inbounds, inbound)

		case "vmess-ws", "vmess":
			users := make([]map[string]any, 0)
			for _, u := range payload.Users {
				if u.Status == "active" {
					users = append(users, map[string]any{
						"name": u.Username,
						"uuid": u.UUID,
					})
				}
			}
			wsPath, _ := in.Options["path"].(string)
			if wsPath == "" {
				wsPath = "/vmess"
			}
			serverName, _ := in.Options["server_name"].(string)
			tlsOpt := map[string]any{
				"enabled":          true,
				"certificate_path": certPath,
				"key_path":         keyPath,
			}
			if serverName != "" {
				tlsOpt["server_name"] = serverName
			}
			inbound := map[string]any{
				"type":        "vmess",
				"tag":         in.Tag,
				"listen":      "::",
				"listen_port": in.ListenPort,
				"users":       users,
				"transport": map[string]any{
					"type": "ws",
					"path": wsPath,
				},
				"tls": tlsOpt,
			}
			inbounds = append(inbounds, inbound)

		case "trojan":
			users := make([]map[string]any, 0)
			for _, u := range payload.Users {
				if u.Status == "active" {
					users = append(users, map[string]any{
						"name":     u.Username,
						"password": u.UUID,
					})
				}
			}
			serverName, _ := in.Options["server_name"].(string)
			tlsOpt := map[string]any{
				"enabled":          true,
				"certificate_path": certPath,
				"key_path":         keyPath,
			}
			if serverName != "" {
				tlsOpt["server_name"] = serverName
			}
			inbound := map[string]any{
				"type":        "trojan",
				"tag":         in.Tag,
				"listen":      "::",
				"listen_port": in.ListenPort,
				"users":       users,
				"tls":         tlsOpt,
			}
			inbounds = append(inbounds, inbound)
		}
	}

	config := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": "127.0.0.1:9090",
				"secret":              clashSecret,
			},
		},
		"inbounds": inbounds,
		"outbounds": []map[string]any{
			{
				"type": "direct",
				"tag":  "direct",
			},
			{
				"type": "block",
				"tag":  "block",
			},
		},
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(config); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
