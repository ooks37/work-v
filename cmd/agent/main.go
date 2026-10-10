package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"work-v/internal/agent/client"
	"work-v/internal/agent/runner"
)

func main() {
	server := flag.String("server", "", "主控服务器地址 (例如 http://master.example.com:8080)")
	// 令牌优先取环境变量 WORKV_TOKEN (由 systemd EnvironmentFile 注入 0600 文件)。
	// 这样令牌不会出现在 /proc/<pid>/cmdline 里被同机其他用户读到。
	token := flag.String("token", os.Getenv("WORKV_TOKEN"), "节点接入令牌")
	singboxPath := flag.String("singbox", "sing-box", "sing-box 二进制路径")
	configDir := flag.String("config-dir", "config", "配置文件保存目录")
	flag.Parse()

	if *server == "" || *token == "" {
		log.Fatal("❌ 必须提供 --server 与 --token 参数")
	}

	log.Println("==================================================")
	log.Println("           Work-V Node Agent (子节点)             ")
	log.Println("==================================================")
	log.Printf("[Agent] 主控地址: %s", *server)
	log.Printf("[Agent] 节点令牌: %s", maskToken(*token))

	// 初始化 Sing-box 守护进程
	sbRunner := runner.NewSingboxRunner(*singboxPath, *configDir)

	// 初始化反向长连客户端
	agentClient := client.NewAgentClient(*server, *token, sbRunner)

	// 后台启动长连
	go agentClient.Start()

	// 捕获系统退出信号优雅终止
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	// 关键: 必须显式停掉内核进程, 否则 sing-box 会成为孤儿占住协议端口,
	// 下次启动时新内核绑定失败, 表现为"节点在线但连不上"。
	sbRunner.Stop()
	log.Println("[Agent] 正在关闭...")
}

// maskToken 日志里不回显完整节点令牌
func maskToken(t string) string {
	if len(t) <= 12 {
		return "***"
	}
	return t[:12] + "***"
}
