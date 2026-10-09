package master

import (
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"work-v/internal/master/api"
	"work-v/internal/master/hub"
	"work-v/internal/master/middleware"
	"work-v/internal/master/sub"

	"github.com/gin-gonic/gin"
	qrcode "github.com/skip2/go-qrcode"
)

//go:embed install.sh
var defaultInstallScript string

// SetupRouter 注册 Master 全部路由规则
func SetupRouter(webDistFS http.FileSystem) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	_ = r.SetTrustedProxies([]string{"127.0.0.1", "::1"})
	r.Use(gin.Recovery())
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.SecurityHeaders())
	r.Use(middleware.SafeEntranceFilter())

	// 1. Agent 反向长连通道 (免鉴权，通过长连协议首包 Token 认证)
	r.GET("/ws/agent", func(c *gin.Context) {
		hub.GlobalHub.HandleWebSocket(c.Writer, c.Request)
	})

	// 2. 外部多端自适应订阅接口
	r.GET("/sub/:token", sub.HandleSubscription)

	// 3. 节点一键智能安装脚本动态分发
	r.GET("/install.sh", handleAgentInstallScript)
	r.GET("/api/v1/install.sh", handleAgentInstallScript)

	// 4. 二进制产物、CLI 工具与安装脚本分发
	r.GET("/download/:filename", func(c *gin.Context) {
		filename := c.Param("filename")
		if strings.Contains(filename, "..") || strings.Contains(filename, "/") {
			c.String(http.StatusBadRequest, "Invalid filename")
			return
		}
		if filename == "install.sh" {
			handleAgentInstallScript(c)
			return
		}
		candidates := []string{
			filepath.Join(".", filename),
			filepath.Join("/opt/work-v-master", filename),
		}
		if strings.HasPrefix(filename, "agent-") || strings.HasPrefix(filename, "work-v-agent") {
			candidates = append(candidates,
				filepath.Join("/opt/work-v-master", "work-v-agent"),
				filepath.Join("/opt/work-v-master", "work-v-agent-linux"),
				filepath.Join(".", "work-v-agent"),
				filepath.Join(".", "work-v-agent-linux"),
			)
		}
		if strings.HasPrefix(filename, "master-") || strings.HasPrefix(filename, "work-v-master") {
			candidates = append(candidates,
				filepath.Join("/opt/work-v-master", "work-v-master"),
				filepath.Join("/opt/work-v-master", "work-v-master-linux"),
				filepath.Join(".", "work-v-master"),
				filepath.Join(".", "work-v-master-linux"),
			)
		}
		if filename == "work-v" || filename == "bt-v" {
			candidates = append(candidates,
				filepath.Join("/opt/work-v-master", "scripts", "work-v"),
				filepath.Join(".", "scripts", "work-v"),
				filepath.Join("/usr/local/bin", "work-v"),
			)
		}
		for _, p := range candidates {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				c.File(p)
				return
			}
		}
		c.String(http.StatusNotFound, "File not found")
	})

	// 5. 原生离线二维码生成接口 (纯本地零外网依赖，杜绝被墙与隐私泄露)
	r.GET("/api/v1/qrcode", func(c *gin.Context) {
		text := c.Query("text")
		if text == "" {
			c.String(http.StatusBadRequest, "text query parameter is required")
			return
		}
		png, err := qrcode.Encode(text, qrcode.Medium, 256)
		if err != nil {
			c.String(http.StatusInternalServerError, "failed to generate qrcode")
			return
		}
		c.Header("Cache-Control", "public, max-age=86400")
		c.Data(http.StatusOK, "image/png", png)
	})

	// 6. REST API 分组
	v1 := r.Group("/api/v1")
	{
		// 认证公开接口
		auth := v1.Group("/auth")
		{
			auth.POST("/login", api.HandleLogin)
		}

		// 管理员受保护接口
		admin := v1.Group("/admin")
		admin.Use(middleware.AdminAuthRequired())
		{
			admin.POST("/change-password", api.HandleChangePassword)
			admin.GET("/dashboard", api.HandleGetDashboard)

			// 安全入口设置
			admin.GET("/safe-entrance", api.HandleGetSafeEntrance)
			admin.POST("/safe-entrance", api.HandleSetSafeEntrance)

			// 节点管理
			admin.GET("/nodes", api.HandleGetNodes)
			admin.POST("/nodes", api.HandleCreateNode)
			admin.PUT("/nodes/:id", api.HandleUpdateNode)
			admin.DELETE("/nodes/:id", api.HandleDeleteNode)
			admin.POST("/nodes/:id/sync", api.HandleSyncNode)
			admin.GET("/nodes/:id/links", api.HandleGetNodeLinks)

			// sing-box 内核管理与在线升级 (借鉴 iwantrun 最佳实践)
			admin.GET("/singbox/version", api.HandleGetSingboxVersion)
			admin.POST("/singbox/upgrade", api.HandleUpgradeSingbox)

			// 系统开放端口与综合诊断
			admin.GET("/system/ports", api.HandleGetOpenPorts)
			admin.GET("/system/diagnostic", api.HandleGetDiagnostic)

			// 用户管理
			admin.GET("/users", api.HandleGetUsers)
			admin.POST("/users", api.HandleCreateUser)
			admin.PUT("/users/:id", api.HandleUpdateUser)
			admin.DELETE("/users/:id", api.HandleDeleteUser)
		}
	}

	// 5. 前端静态文件托管 (SPA 支持)
	if webDistFS != nil {
		fileServer := http.FileServer(webDistFS)
		r.NoRoute(func(c *gin.Context) {
			path := c.Request.URL.Path
			// 如果是 API 或子路径找不到返回 404
			if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/ws/") || strings.HasPrefix(path, "/sub/") {
				c.JSON(http.StatusNotFound, gin.H{"error": "API route not found"})
				return
			}
			// 否则尝试静态资源， fallback 到 index.html
			f, err := webDistFS.Open(strings.TrimPrefix(path, "/"))
			if err == nil {
				f.Close()
				fileServer.ServeHTTP(c.Writer, c.Request)
				return
			}
			c.Request.URL.Path = "/"
			fileServer.ServeHTTP(c.Writer, c.Request)
		})
	}

	return r
}

// handleAgentInstallScript 动态生成并返回主副节点智能自适应安装脚本
func handleAgentInstallScript(c *gin.Context) {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := c.Request.Host
	masterURL := fmt.Sprintf("%s://%s", scheme, host)

	// 优先从本地/安装目录读取最新 install.sh，若无则使用编译期内置嵌入的 defaultInstallScript
	script := defaultInstallScript
	candidates := []string{
		"scripts/install.sh",
		"/opt/work-v-master/scripts/install.sh",
		"install.sh",
	}
	for _, p := range candidates {
		if content, err := os.ReadFile(p); err == nil && len(content) > 0 {
			script = string(content)
			break
		}
	}

	// 动态注入主控端地址
	script = strings.Replace(script, `DEFAULT_SERVER="https://qweqwe.shangxinci.com"`, fmt.Sprintf(`DEFAULT_SERVER="%s"`, masterURL), 1)

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.String(http.StatusOK, script)
}

