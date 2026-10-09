#!/usr/bin/env bash
# ==========================================================
# Work-V Agent 子节点一键纳管与启动脚本
# ==========================================================
set -e

SERVER=""
TOKEN=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --token) TOKEN="$2"; shift 2 ;;
    --server) SERVER="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ -z "$TOKEN" ] || [ -z "$SERVER" ]; then
  echo "❌ 用法: bash install-agent.sh --server <MASTER_URL> --token <NODE_TOKEN>"
  exit 1
fi

echo "🚀 [Work-V Agent] 正在连接主控纳管..."
echo "  主控地址: $SERVER"
echo "  节点令牌: $TOKEN"

INSTALL_DIR="/opt/work-v-agent"
mkdir -p "$INSTALL_DIR"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) AGENT_ARCH="amd64" ;;
  aarch64|arm64) AGENT_ARCH="arm64" ;;
  *) echo "❌ 不支持的系统架构: $ARCH"; exit 1 ;;
esac

# 检查或安装 Sing-box 核心
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

# 安装 systemd 服务
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

echo "✅ [Work-V Agent] 已就绪并与主控建立安全反向长连！"
