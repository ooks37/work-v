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

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//go:embed dist/*
var embeddedWeb embed.FS

func main() {
	port := flag.Int("port", 8080, "Web 服务监听端口")
	dbPath := flag.String("db", "data/work-v.db", "SQLite 数据库路径")
	jwtSecret := flag.String("jwt-secret", "", "自定义 JWT 密钥")
	domainFlag := flag.String("domain", "", "配置主控外网访问域名 (例如 vpn.example.com，传空则为纯 IP 模式)")
	showEntry := flag.Bool("entry", false, "查看当前安全入口与管理员访问地址 (类似宝塔 bt default)")
	setEntry := flag.String("set-entry", "", "修改安全入口路径 (如 /my_secret)")
	disableEntry := flag.Bool("disable-entry", false, "关闭安全入口拦截")
	resetAdmin := flag.Bool("reset-admin", false, "重置管理员密码为默认值 admin123456")
	setPass := flag.String("set-password", "", "修改管理员密码为指定值")
	listNodes := flag.Bool("nodes", false, "查看所有受控节点列表与状态")
	addNode := flag.String("add-node", "", "添加新节点并生成一键纳管命令 (参数为节点名称)")
	flag.Parse()

	// 1. 初始化数据库
	_, err := model.InitDB(*dbPath)
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}

	if *domainFlag != "" {
		d := strings.TrimSpace(*domainFlag)
		if d == "none" || d == "clear" || d == "reset" {
			_ = model.SetSetting("master_domain", "")
			log.Printf("[Work-V] 主控访问域名已清除，恢复为纯 IP 直连模式")
		} else {
			d = strings.TrimPrefix(d, "http://")
			d = strings.TrimPrefix(d, "https://")
			d = strings.TrimRight(d, "/")
			_ = model.SetSetting("master_domain", d)
			log.Printf("[Work-V] 主控访问域名已配置为: https://%s", d)
		}
	}

	getBaseURL := func() string {
		d := model.GetSetting("master_domain", "")
		if d != "" {
			return "https://" + d
		}
		return fmt.Sprintf("http://127.0.0.1:%d", *port)
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
		d := model.GetSetting("master_domain", "")

		fmt.Println("==================================================")
		fmt.Println("         Work-V 控制台安全入口与凭据信息          ")
		fmt.Println("==================================================")
		fmt.Printf("• 安全入口路径: %s\n", safePath)
		if d != "" {
			fmt.Printf("• 域名外网入口: https://%s%s (若未配置SSL反代: http://%s:%d%s)\n", d, safePath, d, *port, safePath)
			fmt.Printf("• 本机回环入口: http://127.0.0.1:%d%s\n", *port, safePath)
		} else {
			fmt.Printf("• 控制台外网入口: http://<你的服务器公网IP>:%d%s\n", *port, safePath)
			fmt.Printf("• 本机回环入口: http://127.0.0.1:%d%s\n", *port, safePath)
		}
		fmt.Printf("• 默认管理账号: %s\n", admin.Username)
		fmt.Println("• 如需绑定域名: work-v domain <你的域名>")
		fmt.Println("• 如需清除域名: work-v domain none")
		fmt.Println("• 如需修改入口: work-v-master -set-entry /new_path")
		fmt.Println("• 如需关闭入口: work-v-master -disable-entry")
		fmt.Println("• 如需修改密码: work-v-master -set-password <新密码>")
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
		baseURL := getBaseURL()
		fmt.Println("==================================================")
		fmt.Printf("✅ 安全入口已成功更新为: %s\n", newPath)
		fmt.Printf("外网访问地址: %s%s\n", baseURL, newPath)
		fmt.Println("==================================================")
		os.Exit(0)
	}

	// 3.1 处理关闭安全入口拦截
	if *disableEntry {
		model.DB.Save(&model.SystemSetting{
			Key:       "safe_path",
			Value:     "",
			UpdatedAt: time.Now(),
		})
		baseURL := getBaseURL()
		fmt.Println("==================================================")
		fmt.Printf("✅ 安全入口已关闭！当前可直接通过 %s/ 访问面板\n", baseURL)
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

	// 4.1 处理自定义修改管理员密码
	if *setPass != "" {
		pwd := strings.TrimSpace(*setPass)
		if len(pwd) < 6 {
			fmt.Println("❌ 密码长度不能少于 6 位")
			os.Exit(1)
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
		model.DB.Model(&model.Admin{}).Where("username = ?", "admin").Update("password_hash", string(hash))
		fmt.Println("==================================================")
		fmt.Printf("✅ 管理员 admin 密码已成功修改为: %s\n", pwd)
		fmt.Println("==================================================")
		os.Exit(0)
	}

	// 5. 处理列出所有节点
	if *listNodes {
		var nodes []model.Node
		model.DB.Order("id asc").Find(&nodes)
		fmt.Println("================================================================================")
		fmt.Printf("%-4s %-16s %-10s %-16s %-8s %-18s\n", "ID", "节点名称", "状态", "IP/地址", "CPU/内存", "最后活跃时间")
		fmt.Println("--------------------------------------------------------------------------------")
		if len(nodes) == 0 {
			fmt.Println("暂无受控节点。使用 work-v add-node <名称> 添加从属节点")
		} else {
			for _, n := range nodes {
				statusStr := "🔴 离线"
				if n.Status == "online" {
					statusStr = "🟢 在线"
				}
				lastSeen := "从未连接"
				if n.LastSeenAt != nil {
					lastSeen = n.LastSeenAt.Format("2006-01-02 15:04:05")
				}
				perfStr := fmt.Sprintf("%.1f%%", n.CPUPercent)
				fmt.Printf("%-4d %-16s %-10s %-16s %-8s %-18s\n", n.ID, n.Name, statusStr, n.Address, perfStr, lastSeen)
			}
		}
		fmt.Println("================================================================================")
		os.Exit(0)
	}

	// 6. 处理快捷添加节点
	if *addNode != "" {
		nodeName := strings.TrimSpace(*addNode)
		token := strings.ReplaceAll(uuid.New().String(), "-", "")
		newNode := model.Node{
			Name:    nodeName,
			Token:   token,
			Address: "127.0.0.1",
			Rate:    1.0,
			Status:  "offline",
		}
		if err := model.DB.Create(&newNode).Error; err != nil {
			fmt.Printf("❌ 创建节点失败: %v\n", err)
			os.Exit(1)
		}
		baseURL := getBaseURL()
		fmt.Println("================================================================================")
		fmt.Printf("✅ 从属节点【%s】创建成功！(Node ID: %d)\n", nodeName, newNode.ID)
		fmt.Printf("• 节点专属 Token: %s\n", token)
		fmt.Println("• 在目标副节点服务器终端直接执行以下一键纳管指令即可自动接入：")
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("curl -fsSL %s/install.sh | bash -s -- --token %s\n", baseURL, token)
		fmt.Println("================================================================================")
		os.Exit(0)
	}

	log.Println("==================================================")
	log.Println("           Work-V VPN/Proxy Master Hub            ")
	log.Println("==================================================")

	if *jwtSecret != "" {
		middleware.SetJWTSecret(*jwtSecret)
		_ = model.SetSetting("jwt_secret", *jwtSecret)
	} else {
		middleware.SetJWTSecret(model.GetSetting("jwt_secret", ""))
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
