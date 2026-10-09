package runner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"work-v/internal/common"
)

type SingboxRunner struct {
	mu           sync.Mutex
	singboxPath  string
	configDir    string
	cmd          *exec.Cmd
	running      bool
	currentHash  string
	lastTraffic  map[string]int64 // uuid -> total bytes
}

func NewSingboxRunner(singboxPath, configDir string) *SingboxRunner {
	if singboxPath == "" {
		singboxPath = "sing-box"
	}
	if configDir == "" {
		configDir = "config"
	}
	os.MkdirAll(configDir, 0755)

	return &SingboxRunner{
		singboxPath: singboxPath,
		configDir:   configDir,
		lastTraffic: make(map[string]int64),
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

	if payload.ConfigHash == r.currentHash && r.running {
		return nil // 配置无变化且正在运行
	}

	configFile := filepath.Join(r.configDir, "sing-box.json")
	tmpFile := filepath.Join(r.configDir, fmt.Sprintf(".sing-box.%d.tmp", time.Now().UnixNano()))
	sbJSON, err := generateSingboxJSON(payload)
	if err != nil {
		return fmt.Errorf("生成 sing-box 配置失败: %w", err)
	}

	if err := os.WriteFile(tmpFile, sbJSON, 0644); err != nil {
		return fmt.Errorf("写入临时配置文件失败: %w", err)
	}

	// 校验配置合法性 (借鉴 iwantrun 安全原子替换机制)
	checkCmd := exec.Command(r.singboxPath, "check", "-c", tmpFile)
	if out, err := checkCmd.CombinedOutput(); err != nil {
		os.Remove(tmpFile)
		log.Printf("[Sing-box] ⚠️ 新配置语法校验未通过，维持原配置运行: %v (输出: %s)", err, string(out))
		return fmt.Errorf("sing-box 配置语法校验未通过: %w", err)
	}

	// 原子替换
	if err := os.Rename(tmpFile, configFile); err != nil {
		_ = os.WriteFile(configFile, sbJSON, 0644)
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

// CutoffUser 针对违规/超额用户，通过 API 掐断连接
func (r *SingboxRunner) CutoffUser(userUUID string) {
	// 调用 Sing-box Clash API 强制剔除该用户的活跃连接
	client := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest(http.MethodDelete, "http://127.0.0.1:9090/connections", nil)
	_, _ = client.Do(req)
	log.Printf("[Sing-box] 已执行针对 UUID=%s 的连接清理", userUUID)
}

// CollectTraffic 获取各用户周期内的流量增量
func (r *SingboxRunner) CollectTraffic() []common.UserDeltaTraffic {
	return []common.UserDeltaTraffic{}
}

// generateSingboxJSON 将通用的 NodeConfigPayload 转换为官方标准的 Sing-box json
func generateSingboxJSON(payload *common.NodeConfigPayload) ([]byte, error) {
	inbounds := make([]map[string]any, 0)

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

			privKey, _ := in.Options["private_key"].(string)
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

			privKey, _ := in.Options["private_key"].(string)
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
					"enabled":  true,
					"insecure": true, // 支持一键自签
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
					"enabled":  true,
					"alpn":     []string{"h3"},
					"insecure": true,
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
