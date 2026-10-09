package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"work-v/internal/master/model"

	"github.com/gin-gonic/gin"
)

const (
	SafeCookieName = "workv_entrance_token"
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

// computeSafeEntryToken 根据当前安全入口路径与实例随机盐计算动态凭证
func computeSafeEntryToken(path string) string {
	salt := model.GetSetting("entrance_salt", "workv_default_salt")
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", path, salt)))
	return hex.EncodeToString(h[:16])
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

// HandleSafeEntryVisit 当访问配置的安全入口时，种入专属凭据并跳转到控制台
func HandleSafeEntryVisit(c *gin.Context) {
	_, safePath := GetSafePath()
	token := computeSafeEntryToken(safePath)
	isHTTPS := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"

	// 设置动态 Cookie，有效期 30 天
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(SafeCookieName, token, 30*24*3600, "/", "", isHTTPS, false)
	c.SetCookie("workv_entry_ok", "1", 30*24*3600, "/", "", isHTTPS, false)
	c.Redirect(http.StatusFound, "/")
}

// BaotaSafeEntranceHTML 类似宝塔面板安全入口拦截提示页面
const BaotaSafeEntranceHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>请使用正确的入口登录面板</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      background: #f0f2f5;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .panel-card {
      background: #ffffff;
      width: 100%;
      max-width: 480px;
      padding: 42px 36px;
      border-radius: 12px;
      box-shadow: 0 8px 24px rgba(0, 0, 0, 0.05);
      border: 1px solid #e5e7eb;
      text-align: center;
    }
    .warn-icon {
      width: 64px;
      height: 64px;
      line-height: 64px;
      border-radius: 50%;
      background: #fff7e6;
      border: 2px solid #ffd591;
      margin: 0 auto 18px;
      font-size: 32px;
      color: #fa8c16;
    }
    h1 {
      font-size: 20px;
      font-weight: 700;
      color: #1f2937;
      margin-bottom: 12px;
    }
    .subtitle {
      font-size: 13.5px;
      color: #4b5563;
      line-height: 1.6;
      margin-bottom: 22px;
    }
    .info-box {
      background: #f8fafc;
      border: 1px solid #e2e8f0;
      border-left: 4px solid #10b981;
      border-radius: 8px;
      padding: 14px 16px;
      text-align: left;
      font-size: 13px;
      color: #334155;
      line-height: 1.6;
      margin-bottom: 22px;
    }
    .info-box strong {
      color: #0f172a;
    }
    .code-badge {
      background: #e2e8f0;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      color: #0f172a;
    }
    .quick-entry {
      display: flex;
      gap: 8px;
    }
    .quick-input {
      flex: 1;
      padding: 10px 14px;
      border: 1px solid #d1d5db;
      border-radius: 8px;
      font-size: 13px;
      outline: none;
      transition: border-color 0.2s;
    }
    .quick-input:focus {
      border-color: #10b981;
      box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
    }
    .quick-btn {
      padding: 10px 20px;
      background: #10b981;
      color: #ffffff;
      border: none;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.2s;
      white-space: nowrap;
    }
    .quick-btn:hover {
      background: #059669;
    }
    .footer-brand {
      margin-top: 24px;
      font-size: 12px;
      color: #9ca3af;
    }
  </style>
</head>
<body>
  <div class="panel-card">
    <div class="warn-icon">⚠️</div>
    <h1>请使用正确的入口登录面板</h1>
    <p class="subtitle">出于系统与集群安全考虑，已开启安全入口登录保护。<br>请在控制台地址后附带正确的安全入口路径进行访问。</p>
    
    <div class="info-box">
      <strong>💡 管理员提示：</strong><br>
      • 请在控制台地址后附带正确的安全入口路径进行访问。<br>
      • 若忘记配置的安全入口，可登录服务器终端执行：<br>
      &nbsp;&nbsp;<span class="code-badge">work-v entry</span> 或 <span class="code-badge">work-v-master -entry</span>
    </div>

    <form onsubmit="event.preventDefault(); var val=document.getElementById('entryInput').value.trim(); if(val){ window.location.href=(val.startsWith('/')?val:('/'+val)); }">
      <div class="quick-entry">
        <input id="entryInput" type="text" class="quick-input" placeholder="输入安全路径 (如 /your_entry)" />
        <button type="submit" class="quick-btn">验证并进入</button>
      </div>
    </form>

    <div class="footer-brand">
      Work-V 分布式网络中枢 · 安全入口保护
    </div>
  </div>
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

		// 1. 如果访问的是安全路径 (支持带或不带结尾斜杠)，直接执行入口解锁处理
		if strings.TrimSuffix(path, "/") == strings.TrimSuffix(safePath, "/") {
			HandleSafeEntryVisit(c)
			c.Abort()
			return
		}

		// 2. 静态资源（js/css/图片/字体/ico）无论何时直接放行！绝不可拦截返回 HTML，否则会导致 JS 语法错误与白屏！
		if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".png") ||
			strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".svg") || strings.HasSuffix(path, ".ico") ||
			strings.HasSuffix(path, ".woff") || strings.HasSuffix(path, ".woff2") || strings.HasSuffix(path, ".ttf") {
			c.Next()
			return
		}

		// 3. 白名单免检路径：订阅链接、Agent WS 长连、安装脚本、二进制下载、原生离线二维码
		if strings.HasPrefix(path, "/sub/") || strings.HasPrefix(path, "/ws/") || strings.HasPrefix(path, "/download/") || path == "/install.sh" || path == "/api/v1/qrcode" {
			c.Next()
			return
		}

		expectedToken := computeSafeEntryToken(safePath)

		// 4. 检查是否持有授权 Cookie
		cookieVal, err := c.Cookie(SafeCookieName)
		if err == nil && cookieVal == expectedToken {
			c.Next()
			return
		}

		// 5. 允许通过 URL 参数紧急带入密钥访问 (例如 ?safe_key=/safe_entry)
		keyParam := c.Query("safe_key")
		if keyParam != "" && "/"+strings.TrimPrefix(keyParam, "/") == safePath {
			isHTTPS := c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
			c.SetSameSite(http.SameSiteLaxMode)
			c.SetCookie(SafeCookieName, expectedToken, 30*24*3600, "/", "", isHTTPS, false)
			c.SetCookie("workv_entry_ok", "1", 30*24*3600, "/", "", isHTTPS, false)
			c.Next()
			return
		}

		// 7. 未授权访问拦截：API 返回 403 JSON，浏览器展示类似宝塔安全入口提示页
		if strings.HasPrefix(path, "/api/") {
			c.JSON(http.StatusForbidden, gin.H{"error": "安全入口拦截：请先通过正确的安全入口访问"})
			c.Abort()
			return
		}

		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Server", "nginx")
		c.String(http.StatusOK, BaotaSafeEntranceHTML)
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
