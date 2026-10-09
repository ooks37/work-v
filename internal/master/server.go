package master

import (
	"fmt"
	"net/http"
	"strings"

	"work-v/internal/master/api"
	"work-v/internal/master/hub"
	"work-v/internal/master/middleware"
	"work-v/internal/master/sub"

	"github.com/gin-gonic/gin"
)

// SetupRouter 注册 Master 全部路由规则
func SetupRouter(webDistFS http.FileSystem) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()

	r.Use(gin.Recovery())
	r.Use(middleware.CORSMiddleware())
	r.Use(middleware.SecurityHeaders())

	// 1. Agent 反向长连通道 (免鉴权，通过长连协议首包 Token 认证)
	r.GET("/ws/agent", func(c *gin.Context) {
		hub.GlobalHub.HandleWebSocket(c.Writer, c.Request)
	})

	// 2. 外部多端自适应订阅接口
	r.GET("/sub/:token", sub.HandleSubscription)

	// 3. 节点一键安装脚本动态分发
	r.GET("/install.sh", handleAgentInstallScript)

	// 4. REST API 分组
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

			// 节点管理
			admin.GET("/nodes", api.HandleGetNodes)
			admin.POST("/nodes", api.HandleCreateNode)
			admin.PUT("/nodes/:id", api.HandleUpdateNode)
			admin.DELETE("/nodes/:id", api.HandleDeleteNode)
			admin.POST("/nodes/:id/sync", api.HandleSyncNode)

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

// handleAgentInstallScript 动态生成并返回节点安装脚本
func handleAgentInstallScript(c *gin.Context) {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := c.Request.Host
	masterURL := fmt.Sprintf("%s://%s", scheme, host)

	script := fmt.Sprintf(`#!/usr/bin/env bash
# ==========================================================
# Work-V Agent 一键安装与纳管脚本
# ==========================================================
set -e

SERVER="%s"
TOKEN=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --token) TOKEN="$2"; shift 2 ;;
    --server) SERVER="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ -z "$TOKEN" ]; then
  echo "❌ 错误: 必须指定节点 Token (--token <TOKEN>)"
  exit 1
fi

echo "🚀 [Work-V] 开始部署 Agent 到本机..."
echo "  主控地址: $SERVER"
echo "  节点令牌: $TOKEN"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) AGENT_ARCH="amd64" ;;
  aarch64|arm64) AGENT_ARCH="arm64" ;;
  *) echo "❌ 不支持的系统架构: $ARCH"; exit 1 ;;
esac

INSTALL_DIR="/opt/work-v-agent"
mkdir -p "$INSTALL_DIR"

echo "📦 下载并更新 Agent 二进制..."
# 尝试从主控拉取对应架构的 agent 二进制
curl -fsSL "$SERVER/download/agent-$AGENT_ARCH" -o "$INSTALL_DIR/work-v-agent" || {
  echo "⚠️ 主控未内置预编译包，使用通用 release 或本地构建包"
}
chmod +x "$INSTALL_DIR/work-v-agent" 2>/dev/null || true

# 写入配置文件
cat > "$INSTALL_DIR/config.json" <<EOF
{
  "server": "$SERVER",
  "token": "$TOKEN",
  "singbox_path": "/usr/local/bin/sing-box"
}
EOF

# 检查/下载 sing-box 核心
if ! command -v sing-box &> /dev/null && [ ! -f "/usr/local/bin/sing-box" ]; then
  echo "⚡ 正在下载 Sing-box 官方核心..."
  SB_VER="1.10.7"
  SB_URL="https://github.com/SagerNet/sing-box/releases/download/v${SB_VER}/sing-box-${SB_VER}-linux-${AGENT_ARCH}.tar.gz"
  curl -fsSL "$SB_URL" -o /tmp/sb.tar.gz
  tar -zxvf /tmp/sb.tar.gz -C /tmp
  mv /tmp/sing-box-*/sing-box /usr/local/bin/
  chmod +x /usr/local/bin/sing-box
  rm -rf /tmp/sb*
fi

# 安装 systemd 守护服务
cat > /etc/systemd/system/work-v-agent.service <<EOF
[Unit]
Description=Work-V Agent Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/work-v-agent --server $SERVER --token $TOKEN
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable work-v-agent
systemctl restart work-v-agent

echo "✅ [Work-V Agent] 部署并自启成功！已开始向主控反向握手！"
`, masterURL)

	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, script)
}
