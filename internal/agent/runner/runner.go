package runner

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
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

	if err := os.WriteFile(tmpFile, sbJSON, 0644); err != nil {
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

	// 后台等待协程
	go func() {
		_ = cmd.Wait()
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
		log.Println("[Sing-box] 进程已退出")
	}()

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

		targetUUID := ""
		if c.Metadata.User != "" {
			for _, u := range activeUsers {
				if u.UUID == c.Metadata.User || u.Username == c.Metadata.User {
					targetUUID = u.UUID
					break
				}
			}
		}
		if targetUUID == "" && len(activeUsers) > 0 {
			targetUUID = activeUsers[0].UUID
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

	// 全局增量兜底
	if data.UploadTotal > r.totalUpSnap || data.DownloadTotal > r.totalDownSnap {
		globalDeltaUp := data.UploadTotal - r.totalUpSnap
		globalDeltaDown := data.DownloadTotal - r.totalDownSnap
		r.totalUpSnap = data.UploadTotal
		r.totalDownSnap = data.DownloadTotal

		if len(userDeltas) == 0 && (globalDeltaUp > 0 || globalDeltaDown > 0) && len(activeUsers) > 0 {
			primaryUUID := activeUsers[0].UUID
			userDeltas[primaryUUID] = &common.UserDeltaTraffic{
				UUID: primaryUUID,
				Up:   globalDeltaUp,
				Down: globalDeltaDown,
			}
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

func getOrCreateCert(configDir string) (string, string) {
	// 1. 检查节点本地证书
	localCert := filepath.Join(configDir, "cert.pem")
	localKey := filepath.Join(configDir, "key.pem")
	if _, err := os.Stat(localCert); err == nil {
		if _, err := os.Stat(localKey); err == nil {
			return localCert, localKey
		}
	}

	// 2. 检查系统通用 Let's Encrypt 证书目录
	matches, _ := filepath.Glob("/etc/letsencrypt/live/*/fullchain.pem")
	if len(matches) > 0 {
		dir := filepath.Dir(matches[0])
		keyPath := filepath.Join(dir, "privkey.pem")
		if _, err := os.Stat(keyPath); err == nil {
			return matches[0], keyPath
		}
	}

	// 3. 自动生成自签证书
	_ = os.MkdirAll(configDir, 0755)
	_ = exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-sha256", "-keyout", localKey, "-out", localCert,
		"-days", "3650", "-subj", "/CN=gateway.icloud.com").Run()

	return localCert, localKey
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
	certPath, keyPath := getOrCreateCert(configDir)

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
				"type":        "tuic",
				"tag":         in.Tag,
				"listen":      "::",
				"listen_port": in.ListenPort,
				"users":       users,
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
				"type":        "anytls",
				"tag":         in.Tag,
				"listen":      "::",
				"listen_port": in.ListenPort,
				"users":       users,
				"tls": map[string]any{
					"enabled":  true,
					"insecure": true,
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
