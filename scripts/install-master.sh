#!/usr/bin/env bash
# ==========================================================
# Work-V Master 主控一键安装脚本 (原生 Linux Systemd)
# ==========================================================
set -e

PORT=${1:-8080}
DOMAIN=${2:-""}
INSTALL_DIR="/opt/work-v-master"

echo "🚀 [Work-V] 开始安装 Master 主控服务..."
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/data"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) GO_ARCH="amd64" ;;
  aarch64|arm64) GO_ARCH="arm64" ;;
  *) echo "❌ 不支持的架构: $ARCH"; exit 1 ;;
esac

echo "📦 准备主控二进制文件..."
if [ -f "./work-v-master" ]; then
  cp -f ./work-v-master "$INSTALL_DIR/"
elif [ -f "./work-v-master-linux" ]; then
  cp -f ./work-v-master-linux "$INSTALL_DIR/work-v-master"
else
  echo "正在拉取当前平台的 work-v-master..."
  curl -fsSL "https://github.com/ooks37/work-v/releases/latest/download/work-v-master-$GO_ARCH" -o "$INSTALL_DIR/work-v-master" 2>/dev/null || true
fi

if [ ! -f "$INSTALL_DIR/work-v-master" ]; then
  echo "❌ 无法获取 work-v-master 二进制文件，请确认网络连接"
  exit 1
fi
chmod +x "$INSTALL_DIR/work-v-master"

EXEC_CMD="$INSTALL_DIR/work-v-master -port $PORT -db $INSTALL_DIR/data/work-v.db"
if [ -n "$DOMAIN" ]; then
  DOMAIN=$(echo "$DOMAIN" | tr -d ' ' | sed -E 's|^https?://||; s|/$||')
  EXEC_CMD="$EXEC_CMD -domain $DOMAIN"
fi

# 安装 systemd 服务
cat > /etc/systemd/system/work-v-master.service <<EOF
[Unit]
Description=Work-V Master Hub Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$EXEC_CMD
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable work-v-master
systemctl restart work-v-master

echo "=================================================="
echo "✅ Work-V 主控已成功安装并启动！"
if [ -n "$DOMAIN" ]; then
  echo "  域名访问: http://$DOMAIN (反代配置后推荐使用 https://$DOMAIN)"
fi
echo "  Web 控制台直接访问: http://<你的服务器IP>:$PORT"
echo "  默认管理员账号: admin"
echo "  默认管理员密码: admin123456"
echo "=================================================="
