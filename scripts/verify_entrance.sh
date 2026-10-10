#!/bin/bash
set -e
DOMAIN="https://yx.shangxinci.com"
SAFE_PATH="/9c0b263436f567b2"

echo "=============================================="
echo "      Work-V 登录与安全入口新机制深度验证     "
echo "=============================================="

echo ""
echo "[1] 验证安全入口访问行为 (必须零跳转直出登录口):"
STATUS=$(curl -s -k -o /tmp/safe_body.html -w "%{http_code}" -c /tmp/cookies.txt "${DOMAIN}${SAFE_PATH}")
echo "  • HTTP 状态码: ${STATUS} (必须为 200，严禁 302/301)"
HAS_APP=$(grep -c "id=\"app\"" /tmp/safe_body.html || true)
HAS_LOGIN=$(grep -c "startLockCountdown" /tmp/safe_body.html || true)
HAS_GRID=$(grep -c "bg-grid-pattern" /tmp/safe_body.html || true)
HAS_COOKIE=$(grep -c "workv_entrance_token" /tmp/cookies.txt || true)
echo "  • 包含 Vue 挂载节点 (id=app): ${HAS_APP}"
echo "  • 包含登录框核心逻辑 (startLockCountdown): ${HAS_LOGIN}"
echo "  • 包含暗黑科技感样式 (bg-grid-pattern): ${HAS_GRID}"
echo "  • 下发入口凭证 Cookie: ${HAS_COOKIE}"

echo ""
echo "[2] 验证根路径访问行为 (开启安全入口时根路径严禁展示登录口):"
STATUS_ROOT=$(curl -s -k -o /tmp/root_body.html -w "%{http_code}" -b /tmp/cookies.txt "${DOMAIN}/")
IS_BLOCKED=$(grep -c "请使用正确的入口登录面板" /tmp/root_body.html || true)
ROOT_HAS_LOGIN=$(grep -c "startLockCountdown" /tmp/root_body.html || true)
echo "  • 根路径 HTTP 状态码: ${STATUS_ROOT}"
echo "  • 根路径是否成功展示安全拦截页: ${IS_BLOCKED} (必须为 1)"
echo "  • 根路径是否泄漏登录口: ${ROOT_HAS_LOGIN} (必须为 0)"

echo ""
echo "[3] 验证在安全路径下正常进行管理员登录 API:"
LOGIN_RES=$(curl -s -k -b /tmp/cookies.txt -H "Content-Type: application/json" -H "X-Safe-Entrance: ${SAFE_PATH}" \
  -d '{"username":"admin","password":"admin123456"}' "${DOMAIN}/api/v1/auth/login")
LOGIN_SUCCESS=$(echo "${LOGIN_RES}" | grep -c "token" || true)
echo "  • 登录 API 响应成功 (包含 Token): ${LOGIN_SUCCESS}"
echo "=============================================="
