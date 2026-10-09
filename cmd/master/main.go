package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"work-v/internal/master"
	"work-v/internal/master/hub"
	"work-v/internal/master/middleware"
	"work-v/internal/master/model"
	"work-v/internal/master/service"

	"golang.org/x/crypto/bcrypt"
)

//go:embed dist/*
var embeddedWeb embed.FS

func main() {
	port := flag.Int("port", 8080, "Web 服务监听端口")
	dbPath := flag.String("db", "data/work-v.db", "SQLite 数据库路径")
	jwtSecret := flag.String("jwt-secret", "", "自定义 JWT 密钥")
	showEntry := flag.Bool("entry", false, "查看当前安全入口与管理员访问地址 (类似宝塔 bt default)")
	setEntry := flag.String("set-entry", "", "修改安全入口路径 (如 /my_secret)")
	resetAdmin := flag.Bool("reset-admin", false, "重置管理员密码为默认值 admin123456")
	flag.Parse()

	// 1. 初始化数据库
	_, err := model.InitDB(*dbPath)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}

	// 2. 处理命令行安全入口查询
	if *showEntry {
		var safeSetting model.SystemSetting
		safePath := "/safe_entry"
		if err := model.DB.Where("key = ?", "safe_path").First(&safeSetting).Error; err == nil && safeSetting.Value != "" {
			safePath = safeSetting.Value
		}
		var admin model.Admin
		model.DB.First(&admin)

		fmt.Println("==================================================")
		fmt.Println("         Work-V 控制台安全入口与凭据信息          ")
		fmt.Println("==================================================")
		fmt.Printf("• 安全入口路径: %s\n", safePath)
		fmt.Printf("• 外网域名入口: https://qweqwe.shangxinci.com%s\n", safePath)
		fmt.Printf("• 默认管理账号: %s\n", admin.Username)
		fmt.Println("• 如需修改入口: work-v-master -set-entry /new_path")
		fmt.Println("• 如需重置密码: work-v-master -reset-admin")
		fmt.Println("==================================================")
		os.Exit(0)
	}

	// 3. 处理命令行修改安全入口
	if *setEntry != "" {
		newPath := strings.TrimSpace(*setEntry)
		if !strings.HasPrefix(newPath, "/") {
			newPath = "/" + newPath
		}
		model.DB.Save(&model.SystemSetting{
			Key:       "safe_path",
			Value:     newPath,
			UpdatedAt: time.Now(),
		})
		fmt.Println("==================================================")
		fmt.Printf("✅ 安全入口已成功更新为: %s\n", newPath)
		fmt.Printf("外网访问地址: http://qweqwe.shangxinci.com%s\n", newPath)
		fmt.Println("==================================================")
		os.Exit(0)
	}

	// 4. 处理重置管理员密码
	if *resetAdmin {
		hash, _ := bcrypt.GenerateFromPassword([]byte("admin123456"), bcrypt.DefaultCost)
		model.DB.Model(&model.Admin{}).Where("username = ?", "admin").Update("password_hash", string(hash))
		fmt.Println("==================================================")
		fmt.Println("✅ 管理员密码已重置为: admin123456")
		fmt.Println("==================================================")
		os.Exit(0)
	}

	log.Println("==================================================")
	log.Println("           Work-V VPN/Proxy Master Hub            ")
	log.Println("==================================================")

	if *jwtSecret != "" {
		middleware.SetJWTSecret(*jwtSecret)
	}

	// 初始化安全路径配置
	var safeSetting model.SystemSetting
	if err := model.DB.Where("key = ?", "safe_path").First(&safeSetting).Error; err == nil && safeSetting.Value != "" {
		middleware.SetSafePath(safeSetting.Value)
	} else {
		middleware.SetSafePath("/safe_entry")
		model.DB.Save(&model.SystemSetting{Key: "safe_path", Value: "/safe_entry"})
	}
	enabled, safePath := middleware.GetSafePath()
	if enabled {
		log.Printf("[Work-V 安全防护] 类似宝塔安全入口已启用: %s (未授权访问将展示安全拦截页)", safePath)
	}

	// 注入 Hub 回调 (流量记账与配置提供)
	hub.GlobalHub.SetCallbacks(service.RecordTraffic, service.BuildNodeConfigPayload)

	// 启动后台到期与熔断监控
	service.StartQuotaWatchdog()

	// 准备前端静态资源文件系统
	subFS, err := fs.Sub(embeddedWeb, "dist")
	var httpFS http.FileSystem
	if err == nil {
		httpFS = http.FS(subFS)
	}

	// 初始化路由与启动 HTTP
	r := master.SetupRouter(httpFS)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("[Work-V] 服务启动监听: %s (Web 控制台 & Agent 连接点)", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("服务启动失败: %v", err)
	}
}
