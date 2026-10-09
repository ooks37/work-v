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
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
	running       bool
	currentHash   string
	activeUsers   []common.UserProfile
	lastConns     map[string]connTrafficSnap // connID -> snap
	totalUpSnap   int64
	totalDownSnap int64
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
		clashSecret: hex.EncodeToString(secretBytes),
		lastConns:   make(map[string]connTrafficSnap),
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

// ApplyConfig 动态渲染 sing-box 配置文件并热启动/重载
func (r *SingboxRunner) ApplyConfig(payload *common.NodeConfigPayload) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.activeUsers = payload.Users

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

	// 原子替换
	if err := os.Rename(tmpFile, configFile); err != nil {
		_ = os.WriteFile(configFile, sbJSON, 0644)
		_ = os.Remove(tmpFile)
	}

	r.currentHash = payload.ConfigHash

	// 重新启动 Sing-box 进程
	return r.restartProcess(configFile)
}

func (r *SingboxRunner) restartProcess(configFile string) error {
	if r.cmd != nil && r.cmd.Process != nil && r.running {
		log.Println("[Sing-box] 正在重启进程以加载新配置...")
		_ = r.cmd.Process.Kill()
		_ = r.cmd.Wait()
		r.running = false
	}

	// 进程被替换意味着 Clash API 的连接表与累计计数器都已归零, 必须同步清空本地快照,
	// 否则新进程的 total 永远小于旧快照, 增量判断长期失效 (漏计费)。
	r.lastConns = make(map[string]connTrafficSnap)
	r.totalUpSnap = 0
	r.totalDownSnap = 0

	cmd := exec.Command(r.singboxPath, "run", "-c", configFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		r.running = false
		return fmt.Errorf("启动 sing-box 进程失败: %w", err)
	}
	r.cmd = cmd
	r.running = true
	log.Printf("[Sing-box] 进程启动成功, PID=%d", cmd.Process.Pid)

	// 后台等待协程: 只允许"自己这一轮"的进程修改运行状态。
	// 历史实现无条件置 running=false, 旧进程被 kill 后其 watcher 会在新进程启动完成之后把
	// 状态改回未运行 -> 面板显示"内核已停止", 且 ApplyConfig 的幂等短路永久失效,
	// 于是每次下发配置都要重启内核、切断全部用户连接。
	go func(c *exec.Cmd) {
		_ = c.Wait()
		r.mu.Lock()
		if r.cmd == c {
			r.running = false
		}
		r.mu.Unlock()
		log.Printf("[Sing-box] 进程已退出 (PID=%d)", c.Process.Pid)
	}(cmd)

	return nil
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
			deltaUp = c.Upload
			deltaDown = c.Download
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
						"enabled": true,
						"handshake": map[string]any{
							"server": dest,
						},
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
						"enabled": true,
						"handshake": map[string]any{
							"server": dest,
						},
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
