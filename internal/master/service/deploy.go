package service

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"work-v/internal/master/model"

	"golang.org/x/crypto/ssh"
)

// AutoDeployRequest SSH 自动纳管参数 (面板"自动部署"模式提交)
type AutoDeployRequest struct {
	Host     string
	Port     int
	User     string
	Password string
	BaseURL  string // 主控对外地址, 目标机必须能访问 (例如 https://yx.example.com)
}

// 按节点缓存安装输出, 节流写库, 供前端轮询查看进度
var (
	deployMu  sync.Mutex
	deployBuf = map[uint]*strings.Builder{}
)

// BuildAutoDeployCommand 生成目标机上执行的纳管命令 (复用 /install.sh, 与手动模式完全一致)
func BuildAutoDeployCommand(baseURL, token string) string {
	return fmt.Sprintf("curl -fsSL %s/install.sh | bash -s -- --token %s --server %s", baseURL, token, baseURL)
}

func deployAppend(nodeID uint, s string) {
	deployMu.Lock()
	b, ok := deployBuf[nodeID]
	if !ok {
		b = &strings.Builder{}
		deployBuf[nodeID] = b
	}
	b.WriteString(s)
	deployMu.Unlock()
}

func deploySnapshot(nodeID uint) string {
	deployMu.Lock()
	defer deployMu.Unlock()
	if b, ok := deployBuf[nodeID]; ok {
		return b.String()
	}
	return ""
}

func deployFlush(nodeID uint) {
	out := deploySnapshot(nodeID)
	_ = model.DB.Model(&model.Node{}).Where("id = ?", nodeID).Update("deploy_log", out).Error
}

func deploySetStatus(nodeID uint, status string) {
	_ = model.DB.Model(&model.Node{}).Where("id = ?", nodeID).Update("deploy_status", status).Error
}

// deployDrop 部署结束后释放内存缓冲 (日志已落库, 由前端按需读取)
func deployDrop(nodeID uint) {
	deployMu.Lock()
	delete(deployBuf, nodeID)
	deployMu.Unlock()
}

// maskTokenInCmd 日志里不回显完整节点 Token (审计: 部署日志会被面板展示)
func maskTokenInCmd(cmd, token string) string {
	if token == "" {
		return cmd
	}
	short := token
	if len(short) > 12 {
		short = short[:12] + "***"
	}
	return strings.ReplaceAll(cmd, token, short)
}

// isRootSession 判断远程账号是否为 root (安装脚本需要 root)
func isRootSession(client *ssh.Client) bool {
	session, err := client.NewSession()
	if err != nil {
		return false
	}
	defer session.Close()
	out, err := session.Output("id -u")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "0"
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// verifyRemoteService 确认远端 agent 服务已运行
func verifyRemoteService(client *ssh.Client, out writerFunc) error {
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout = out
	session.Stderr = out
	fmt.Fprint(out, "\n[Work-V] 校验远端 work-v-agent 服务状态...\n")
	return session.Run("systemctl is-active --quiet work-v-agent")
}

// AutoDeployNode 通过 SSH 在目标服务器上执行一键纳管脚本。
// 异步执行: 调用后立即返回, 进度写入 node.deploy_log / deploy_status, 由前端轮询。
func AutoDeployNode(nodeID uint, req AutoDeployRequest) {
	go func() {
		deployMu.Lock()
		deployBuf[nodeID] = &strings.Builder{}
		deployMu.Unlock()

		start := time.Now()
		deploySetStatus(nodeID, "running")
		deployAppend(nodeID, fmt.Sprintf("[Work-V] 开始自动部署: %s@%s:%d\n", req.User, req.Host, req.Port))
		defer deployDrop(nodeID)

		stop := make(chan struct{})
		go func() {
			ticker := time.NewTicker(1500 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stop:
					return
				case <-ticker.C:
					deployFlush(nodeID)
				}
			}
		}()

		fail := func(format string, a ...any) {
			deployAppend(nodeID, "\n"+fmt.Sprintf(format, a...)+"\n")
			deploySetStatus(nodeID, "failed")
			close(stop)
			deployFlush(nodeID)
			log.Printf("[AutoDeploy] 节点 %d 自动部署失败: %s", nodeID, fmt.Sprintf(format, a...))
		}

		var node model.Node
		if err := model.DB.First(&node, nodeID).Error; err != nil {
			fail("节点不存在: %v", err)
			return
		}

		if req.BaseURL == "" {
			fail("主控对外地址为空, 请先在主控配置域名 (work-v domain <域名>)")
			return
		}
		if req.User == "" {
			req.User = "root"
		}
		if req.Port <= 0 || req.Port > 65535 {
			req.Port = 22
		}

		auths := []ssh.AuthMethod{}
		if req.Password != "" {
			auths = append(auths, ssh.Password(req.Password))
			// 部分云镜像走 keyboard-interactive, 一并支持
			auths = append(auths, ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = req.Password
				}
				return answers, nil
			}))
		}
		if len(auths) == 0 {
			fail("未提供 SSH 密码")
			return
		}

		cfg := &ssh.ClientConfig{
			User:            req.User,
			Auth:            auths,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         20 * time.Second,
		}

		addr := fmt.Sprintf("%s:%d", req.Host, req.Port)
		deployAppend(nodeID, "[Work-V] 正在建立 SSH 连接 "+addr+" ...\n")
		client, err := ssh.Dial("tcp", addr, cfg)
		if err != nil {
			fail("SSH 连接失败: %v", err)
			return
		}
		defer client.Close()
		deployAppend(nodeID, "[Work-V] SSH 连接成功\n")

		if !isRootSession(client) {
			fail("远程账号 %s 不是 root; 安装脚本需要 root 权限, 请改用 root 账号", req.User)
			return
		}

		cmd := BuildAutoDeployCommand(req.BaseURL, node.Token)
		deployAppend(nodeID, "[Work-V] 执行纳管命令: "+maskTokenInCmd(cmd, node.Token)+"\n\n")

		session, err := client.NewSession()
		if err != nil {
			fail("创建 SSH 会话失败: %v", err)
			return
		}
		defer session.Close()

		outW := writerFunc(func(p []byte) (int, error) {
			deployAppend(nodeID, string(p))
			return len(p), nil
		})
		session.Stdout = outW
		session.Stderr = outW

		done := make(chan error, 1)
		go func() { done <- session.Run(cmd) }()

		select {
		case err := <-done:
			deployFlush(nodeID)
			if err != nil {
				fail("安装脚本执行失败: %v", err)
				return
			}
			if err := verifyRemoteService(client, outW); err != nil {
				fail("安装完成但远端 work-v-agent 服务未运行: %v", err)
				return
			}
			deployAppend(nodeID, fmt.Sprintf("\n[Work-V] 自动部署完成, 用时 %s\n", time.Since(start).Round(time.Second)))
			deploySetStatus(nodeID, "success")
			close(stop)
			deployFlush(nodeID)

			updates := map[string]any{"deploy_host": req.Host}
			if node.Address == "" || node.Address == "自动探测" {
				updates["address"] = req.Host
			}
			_ = model.DB.Model(&model.Node{}).Where("id = ?", nodeID).Updates(updates).Error
			log.Printf("[AutoDeploy] 节点 %d (%s) 自动部署完成", nodeID, node.Name)

		case <-time.After(15 * time.Minute):
			_ = client.Close()
			fail("安装超时 (15 分钟) 已中断; 可在目标机执行 journalctl -u work-v-agent -n 50 排查")
		}
	}()
}
