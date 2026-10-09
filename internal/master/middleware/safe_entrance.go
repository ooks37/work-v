package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

const (
	SafeCookieName = "workv_entrance_token"
	SafeCookieVal  = "workv_authorized_entry_pass"
)

type SafeEntranceConfig struct {
	mu       sync.RWMutex
	Enabled  bool
	SafePath string // 例如 "/safe_entry"
}

var GlobalSafeEntrance = &SafeEntranceConfig{
	Enabled:  true,
	SafePath: "/safe_entry",
}

// SetSafePath 设置安全入口路径 (如果传空则关闭安全路径保护)
func SetSafePath(path string) {
	GlobalSafeEntrance.mu.Lock()
	defer GlobalSafeEntrance.mu.Unlock()

	path = strings.TrimSpace(path)
	if path == "" || path == "/" {
		GlobalSafeEntrance.Enabled = false
		GlobalSafeEntrance.SafePath = ""
		return
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	GlobalSafeEntrance.Enabled = true
	GlobalSafeEntrance.SafePath = path
}

// GetSafePath 获取当前安全路径
func GetSafePath() (bool, string) {
	GlobalSafeEntrance.mu.RLock()
	defer GlobalSafeEntrance.mu.RUnlock()
	return GlobalSafeEntrance.Enabled, GlobalSafeEntrance.SafePath
}

// HandleSafeEntryVisit 当访问配置的安全入口时，种入专属凭据并跳转到根页面
func HandleSafeEntryVisit(c *gin.Context) {
	// 设置 Cookie，有效期 30 天
	c.SetCookie(SafeCookieName, SafeCookieVal, 30*24*3600, "/", "", false, true)
	// 302 重定向到控制台主入口
	c.Redirect(http.StatusFound, "/")
}

// StandardNginx404 伪装标准 Nginx 404 网页
const StandardNginx404 = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>`

// SafeEntranceFilter 全局安全路径过滤器
func SafeEntranceFilter() gin.HandlerFunc {
	return func(c *gin.Context) {
		GlobalSafeEntrance.mu.RLock()
		enabled := GlobalSafeEntrance.Enabled
		safePath := GlobalSafeEntrance.SafePath
		GlobalSafeEntrance.mu.RUnlock()

		if !enabled || safePath == "" {
			c.Next()
			return
		}

		path := c.Request.URL.Path

		// 1. 如果正是访问安全路径，直接执行入口解锁处理
		if path == safePath {
			HandleSafeEntryVisit(c)
			c.Abort()
			return
		}

		// 2. 白名单免检路径：订阅链接、Agent WS 长连、安装脚本
		if strings.HasPrefix(path, "/sub/") || strings.HasPrefix(path, "/ws/") || path == "/install.sh" {
			c.Next()
			return
		}

		// 3. 检查是否持有授权 Cookie
		cookieVal, err := c.Cookie(SafeCookieName)
		if err == nil && cookieVal == SafeCookieVal {
			c.Next()
			return
		}

		// 4. 允许通过 URL 参数紧急带入密钥访问 (例如 ?safe_key=safe_entry)
		keyParam := c.Query("safe_key")
		if keyParam != "" && "/"+strings.TrimPrefix(keyParam, "/") == safePath {
			c.SetCookie(SafeCookieName, SafeCookieVal, 30*24*3600, "/", "", false, true)
			c.Next()
			return
		}

		// 5. 未授权访问，伪装成标准 404 Not Found，彻底隐藏面板存在
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Server", "nginx")
		c.String(http.StatusNotFound, StandardNginx404)
		c.Abort()
	}
}

// GetSafeEntranceURL 构造完整的安全入口链接
func GetSafeEntranceURL(scheme, host string) string {
	GlobalSafeEntrance.mu.RLock()
	defer GlobalSafeEntrance.mu.RUnlock()
	if !GlobalSafeEntrance.Enabled || GlobalSafeEntrance.SafePath == "" {
		return fmt.Sprintf("%s://%s/", scheme, host)
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, GlobalSafeEntrance.SafePath)
}
