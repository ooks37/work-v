package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"work-v/internal/master"
	"work-v/internal/master/hub"
	"work-v/internal/master/middleware"
	"work-v/internal/master/model"
	"work-v/internal/master/service"
)

//go:embed dist/*
var embeddedWeb embed.FS

func main() {
	port := flag.Int("port", 8080, "Web 服务监听端口")
	dbPath := flag.String("db", "data/work-v.db", "SQLite 数据库路径")
	jwtSecret := flag.String("jwt-secret", "", "自定义 JWT 密钥")
	flag.Parse()

	log.Println("==================================================")
	log.Println("           Work-V VPN/Proxy Master Hub            ")
	log.Println("==================================================")

	if *jwtSecret != "" {
		middleware.SetJWTSecret(*jwtSecret)
	}

	// 1. 初始化数据库
	_, err := model.InitDB(*dbPath)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}

	// 2. 注入 Hub 回调 (流量记账与配置提供)
	hub.GlobalHub.SetCallbacks(service.RecordTraffic, service.BuildNodeConfigPayload)

	// 3. 启动后台到期与熔断监控
	service.StartQuotaWatchdog()

	// 4. 准备前端静态资源文件系统
	subFS, err := fs.Sub(embeddedWeb, "dist")
	var httpFS http.FileSystem
	if err == nil {
		httpFS = http.FS(subFS)
	}

	// 5. 初始化路由与启动 HTTP
	r := master.SetupRouter(httpFS)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("[Work-V] 服务启动监听: %s (Web 控制台 & Agent 连接点)", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}
