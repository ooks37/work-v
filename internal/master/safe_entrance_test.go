package master

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"work-v/internal/master/middleware"
	"work-v/internal/master/model"

	"github.com/gin-gonic/gin"
)

const blockPageMark = "请使用正确的入口登录面板"

// newTestServer 启动一个带安全入口的测试路由, 并返回安全入口路径
func newTestServer(t *testing.T) (*gin.Engine, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dir, err := os.MkdirTemp("", "workv-entrance-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		if model.DB != nil {
			if sqlDB, err := model.DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
			model.DB = nil
		}
		_ = os.RemoveAll(dir)
	})
	if _, err := model.InitDB(filepath.Join(dir, "entrance.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	safePath := model.DefaultSafePath
	middleware.SetSafePath(safePath)

	// 前端产物目录 (与生产一致地交给路由托管)
	dist := filepath.Join("..", "..", "cmd", "master", "dist")
	if _, err := os.Stat(filepath.Join(dist, "index.html")); err != nil {
		t.Skipf("缺少前端产物目录 %s: %v", dist, err)
	}
	return SetupRouter(http.FS(os.DirFS(dist))), safePath
}

func do(t *testing.T, r *gin.Engine, method, path string, cookies []*http.Cookie, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Host = "panel.example.com"
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// entranceCookie 走真实流程访问安全入口, 取回服务端下发的凭证 Cookie
func entranceCookie(t *testing.T, r *gin.Engine, safePath string) *http.Cookie {
	t.Helper()
	w := do(t, r, "GET", safePath, nil, "")
	if w.Code != http.StatusFound {
		t.Fatalf("访问安全入口 %s 期望 302, 实际 %d", safePath, w.Code)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "workv_entrance_token" && c.Value != "" {
			return c
		}
	}
	t.Fatal("安全入口未下发凭证 Cookie")
	return nil
}

// 未通过安全入口时, 任何非白名单路径都必须拿到拦截页, 绝不能返回面板本身。
func TestSafeEntranceBlocksPanelWithoutCookie(t *testing.T) {
	r, _ := newTestServer(t)

	for _, path := range []string{"/", "/index.html", "/whatever.js", "/theme.css", "/logo.svg", "/favicon.ico"} {
		w := do(t, r, "GET", path, nil, "")
		body := w.Body.String()
		if !strings.Contains(body, blockPageMark) {
			t.Errorf("GET %s 未返回拦截页 (status=%d, 前 80 字: %.80s)", path, w.Code, body)
		}
	}
}

// 静态资源后缀白名单不能成为绕过安全入口的后门:
// 带 :id 参数的管理接口在追加 .js/.css 等后缀后, 原本会被后缀白名单直接放行。
func TestSafeEntranceSuffixCannotBypassAPI(t *testing.T) {
	r, _ := newTestServer(t)

	for _, c := range []struct{ method, path string }{
		{"PUT", "/api/v1/admin/nodes/999.js"},
		{"DELETE", "/api/v1/admin/nodes/999.js"},
		{"DELETE", "/api/v1/admin/users/999.js"},
		{"PUT", "/api/v1/admin/users/999.js"},
	} {
		w := do(t, r, c.method, c.path, nil, "")
		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s 未在安全入口层被拦截: status=%d body=%.80s", c.method, c.path, w.Code, w.Body.String())
		}
	}
}

// 真正的静态资源必须继续可用, 否则面板白屏。
func TestSafeEntranceStillServesStaticAssets(t *testing.T) {
	r, _ := newTestServer(t)
	for _, path := range []string{"/tailwind.js", "/vue.global.prod.js"} {
		w := do(t, r, "GET", path, nil, "")
		if w.Code != http.StatusOK {
			t.Errorf("静态资源 %s 被误拦: status=%d", path, w.Code)
		}
	}
}

// 持有入口 Cookie 时面板必须正常可访问。
func TestSafeEntranceAllowsPanelWithCookie(t *testing.T) {
	r, safePath := newTestServer(t)
	cookie := entranceCookie(t, r, safePath)

	w := do(t, r, "GET", "/", []*http.Cookie{cookie}, "")
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "id=\"app\"") {
		t.Errorf("持有效入口 Cookie 访问 / 失败: status=%d", w.Code)
	}
	if strings.Contains(body, blockPageMark) {
		t.Errorf("持有效入口 Cookie 仍被拦截")
	}
}

// 非数字 id 必须被拒绝, 不能静默解析成 0 之后去操作第一条记录。
func TestInvalidIDParamIsRejected(t *testing.T) {
	r, safePath := newTestServer(t)
	cookie := entranceCookie(t, r, safePath)

	if err := model.DB.Create(&model.Node{Name: "node-A", Token: "tok-a", Address: "1.1.1.1", Rate: 1}).Error; err != nil {
		t.Fatalf("创建节点: %v", err)
	}
	jwt, err := middleware.GenerateToken(1, "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	for _, c := range []struct{ method, path string }{
		{"DELETE", "/api/v1/admin/nodes/999abc"},
		{"PUT", "/api/v1/admin/nodes/999abc"},
		{"POST", "/api/v1/admin/nodes/999abc/sync"},
	} {
		w := do(t, r, c.method, c.path, []*http.Cookie{cookie}, jwt)
		if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
			t.Errorf("%s %s 未拒绝非法 id: status=%d body=%s", c.method, c.path, w.Code, w.Body.String())
		}
	}

	var still model.Node
	if err := model.DB.Where("token = ?", "tok-a").First(&still).Error; err != nil {
		t.Errorf("第一条节点记录被非法请求删除/修改了: %v", err)
	}
	if still.Name != "node-A" {
		t.Errorf("第一条节点记录被非法请求改名: %q", still.Name)
	}
}

// 安全入口路径必须做校验: 抢占保留路径会让订阅/安装脚本/接口直接不可用。
func TestSetSafeEntranceRejectsInvalidPaths(t *testing.T) {
	r, safePath := newTestServer(t)
	cookie := entranceCookie(t, r, safePath)
	jwt, err := middleware.GenerateToken(1, "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	invalid := []string{
		"/install.sh", "/api/v1/x", "/sub/abc", "/ws/agent", "/download/x",
		"/evil.js", "/index.html", "/a b", "/a?b", "/../etc",
		"/" + strings.Repeat("x", 80),
	}
	for _, p := range invalid {
		req := httptest.NewRequest("POST", "/api/v1/admin/safe-entrance", strings.NewReader(`{"safe_path":"`+p+`"}`))
		req.Host = "panel.example.com"
		req.AddCookie(cookie)
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("safe_path=%q 未被拒绝: status=%d body=%s", p, w.Code, w.Body.String())
		}
	}

	// 路径必须保持不变
	_, now := middleware.GetSafePath()
	if now != safePath {
		t.Errorf("非法请求改动了安全入口路径: %q", now)
	}
}

// 修改安全入口后必须给当前浏览器换发新凭据, 否则管理员会把自己锁在门外。
func TestSetSafeEntranceRefreshesCurrentCookie(t *testing.T) {
	r, safePath := newTestServer(t)
	cookie := entranceCookie(t, r, safePath)
	jwt, err := middleware.GenerateToken(1, "admin", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	req := httptest.NewRequest("POST", "/api/v1/admin/safe-entrance", strings.NewReader(`{"safe_path":"/my_secret"}`))
	req.Host = "panel.example.com"
	req.AddCookie(cookie)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("修改安全入口失败: status=%d body=%s", w.Code, w.Body.String())
	}

	var issued *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "workv_entrance_token" {
			issued = c
		}
	}
	if issued == nil {
		t.Fatal("修改安全入口后未换发新的入口 Cookie, 管理员会被自己锁在门外")
	}
	if issued.Value == cookie.Value {
		t.Errorf("新 Cookie 与旧路径的凭据相同, 未随路径更新")
	}
	if !issued.HttpOnly {
		t.Errorf("入口凭证 Cookie 应为 HttpOnly")
	}

	// 旧 Cookie 必须失效 (路径已变更)
	if w2 := do(t, r, "GET", "/", []*http.Cookie{cookie}, ""); !strings.Contains(w2.Body.String(), blockPageMark) {
		t.Errorf("旧路径的入口凭证在改路径后仍然有效")
	}
	// 新 Cookie 必须可用
	if w3 := do(t, r, "GET", "/", []*http.Cookie{issued}, ""); !strings.Contains(w3.Body.String(), "id=\"app\"") {
		t.Errorf("新换发的入口凭证不可用: status=%d", w3.Code)
	}
	// 新入口路径本身可用
	if w4 := do(t, r, "GET", "/my_secret", nil, ""); w4.Code != http.StatusFound {
		t.Errorf("新安全入口路径不可用: status=%d", w4.Code)
	}
}

// 白名单路径必须保持匿名可达, 否则节点安装/订阅会失效。
func TestPublicWhitelistStaysReachable(t *testing.T) {
	r, _ := newTestServer(t)
	for _, path := range []string{"/install.sh", "/api/v1/install.sh", "/api/v1/qrcode?text=hi"} {
		w := do(t, r, "GET", path, nil, "")
		if w.Code != http.StatusOK {
			t.Errorf("白名单路径 %s 被拦截: status=%d", path, w.Code)
		}
	}
}

// /download/ 必须拦住"备份文件"这类后缀变体 (work-v.db.bak 曾可匿名下载整个数据库)
func TestDownloadEndpointBlocksBackupFiles(t *testing.T) {
	r, _ := newTestServer(t)

	for _, name := range []string{
		"work-v.db.bak", "work-v.db.old", "work-v-master.db", "work-v.env.bak",
		"work-v-master.conf", "work-v-master.key", "work-v-master.pem",
		".work-v-master", "work-v-master.json",
	} {
		w := do(t, r, "GET", "/download/"+name, nil, "")
		if w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest {
			t.Errorf("/download/%s 未被拒绝: status=%d body=%.60s", name, w.Code, w.Body.String())
		}
	}
}
