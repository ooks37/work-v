#!/bin/bash
set -e
DB="/www/wwwroot/work-v/data/work-v.db"
TOKEN=$(sqlite3 "$DB" "SELECT sub_token FROM users WHERE deleted_at IS NULL AND status='active' LIMIT 1;")
if [ -z "$TOKEN" ]; then
  echo "未找到活跃有效用户，创建测试订阅用户..."
  sqlite3 "$DB" "INSERT INTO users (username, uuid, sub_token, traffic_limit, used_traffic, expire_at, status, created_at, updated_at) VALUES ('vip_user', '22222222-3333-4444-5555-666666666666', 'subtokentest99999999', 107374182400, 1048576, 0, 'active', datetime('now'), datetime('now'));"
  TOKEN="subtokentest99999999"
fi

# 确保有可用的测试节点以验证单节点链接
NODE_COUNT=$(sqlite3 "$DB" "SELECT count(*) FROM nodes WHERE deleted_at IS NULL;")
if [ "$NODE_COUNT" -eq 0 ]; then
  echo "未找到有效节点，创建示例香港节点..."
  sqlite3 "$DB" "INSERT INTO nodes (name, address, rate, inbounds_json, token, status, created_at, updated_at) VALUES ('香港-0168高速节点', '38.76.193.152', 1.0, '', 'node_test_token', 'online', datetime('now'), datetime('now'));"
fi
sqlite3 "$DB" "UPDATE nodes SET address='38.76.193.152' WHERE deleted_at IS NULL AND (address='自动探测' OR address='' OR address='127.0.0.1');"


echo "=============================================="
echo "          Work-V 全套订阅与单节点验证         "
echo "=============================================="
PORTAL_URL="https://yx.shangxinci.com/sub/${TOKEN}"
echo "订阅总 URL: ${PORTAL_URL}"

echo ""
echo "[1] 验证面向客户的现代化自服务 HTML 门户:"
HTML=$(curl -s -k -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "${PORTAL_URL}")
echo "  • 门户主标题匹配: $(echo "$HTML" | grep -c "Work-V 订阅中心")"
echo "  • 独立节点直连匹配: $(echo "$HTML" | grep -c "独立节点直连")"
echo "  • 单节点二维码匹配: $(echo "$HTML" | grep -c "单节点码")"
echo "  • Clash一键导入匹配: $(echo "$HTML" | grep -c "导入 Clash")"
echo "  • Sing-box离线配置下载匹配: $(echo "$HTML" | grep -c "下载 Sing-box 配置")"

echo ""
echo "[2] 验证 Mihomo (Clash.Meta) YAML 导出:"
CLASH=$(curl -s -k "${PORTAL_URL}?type=clash")
echo "  • Clash 配置总行数: $(echo "$CLASH" | wc -l)"
echo "  • 前 10 行预览:"
echo "$CLASH" | head -n 10

echo ""
echo "[3] 验证 Sing-box 官方 JSON 导出:"
SINGBOX=$(curl -s -k "${PORTAL_URL}?type=sing-box")
echo "  • Sing-box 配置字符数: $(echo "$SINGBOX" | wc -c)"
echo "  • 前 10 行预览:"
echo "$SINGBOX" | head -n 10

echo ""
echo "[4] 验证客户端 User-Agent (v2rayN/小火箭) 纯 Base64 订阅导出:"
B64=$(curl -s -k -H "User-Agent: v2rayN/6.23" "${PORTAL_URL}")
DECODED=$(echo "$B64" | base64 -d 2>/dev/null || true)
echo "  • Base64 解密后的单节点直连协议链接列表:"
echo "$DECODED" | head -n 10
echo "=============================================="
