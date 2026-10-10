package sub

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"work-v/internal/common"
	"work-v/internal/master/model"
	"work-v/internal/master/service"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// setupTestDB 每个用例独立数据库, 结束时关闭连接 (Windows 下不关闭会导致临时目录删不掉)
func setupTestDB(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "workv-sub-test-*")
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
	dbPath := filepath.Join(dir, name)
	if _, err := model.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	return dbPath
}

func newSubContext(t *testing.T, token string, ua string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/sub/"+token+"?pwd=testpassword", nil)
	c.Request.Host = "panel.example.com"
	if ua != "" {
		c.Request.Header.Set("User-Agent", ua)
	}
	c.Params = gin.Params{{Key: "token", Value: token}}
	return c, w
}

func createNodeAndUser(t *testing.T, node *model.Node, username string) model.User {
	t.Helper()
	if err := model.DB.Create(node).Error; err != nil {
		t.Fatalf("创建节点: %v", err)
	}
	user := model.User{
		Username: username,
		Password: "testpassword",
		UUID:     "11111111-1111-1111-1111-111111111111",
		SubToken: "subt",
		Status:   "active",
	}
	if err := model.DB.Create(&user).Error; err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	return user
}

// TestHandleSubscription 全量多端自适应格式与门户输出验证
func TestHandleSubscription(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t, "sub_integration.db")

	inbounds := []common.InboundConfig{
		{
			Type:       "vless",
			Tag:        "vless-in",
			ListenPort: 2083,
			Enabled:    true,
			Options: map[string]any{
				"public_key":  "test-pubkey",
				"short_id":    "test-shortid",
				"server_name": "gateway.icloud.com",
			},
		},
		{
			Type:       "hysteria2",
			Tag:        "hy2-in",
			ListenPort: 8443,
			Enabled:    true,
			Options: map[string]any{
				"server_name": "gateway.icloud.com",
			},
		},
		{
			Type:       "shadowsocks",
			Tag:        "ss-in",
			ListenPort: 8388,
			Enabled:    true,
			Options: map[string]any{
				"method":   "2022-blake3-aes-128-gcm",
				"password": "d29ya3YxMjM0NTY3ODkwMQ==",
			},
		},
	}
	inbJSON, _ := json.Marshal(inbounds)

	node := model.Node{
		Name:         "香港节点-01",
		Address:      "156.224.28.20",
		Token:        "node_token_abc",
		Status:       "online",
		Rate:         1.0,
		InboundsJSON: string(inbJSON),
	}
	model.DB.Create(&node)

	activeUser := model.User{
		Username:     "active_user",
		Password:     "pass1234",
		UUID:         "11111111-2222-3333-4444-555555555555",
		SubToken:     "sub_active_token",
		TrafficLimit: 100 * 1024 * 1024 * 1024,
		UsedTraffic:  10 * 1024 * 1024 * 1024,
		ExpireAt:     time.Now().Add(30 * 24 * time.Hour).Unix(),
		Status:       "active",
	}
	model.DB.Create(&activeUser)

	suspendedUser := model.User{
		Username:     "suspended_user",
		Password:     "pass1234",
		UUID:         "22222222-3333-4444-5555-666666666666",
		SubToken:     "sub_suspended_token",
		TrafficLimit: 10 * 1024 * 1024 * 1024,
		UsedTraffic:  10 * 1024 * 1024 * 1024,
		ExpireAt:     time.Now().Add(30 * 24 * time.Hour).Unix(),
		Status:       "suspended",
	}
	model.DB.Create(&suspendedUser)

	router := gin.New()
	router.GET("/sub/:token", HandleSubscription)

	// Case 1: 不存在的 Token -> 404
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/non_exist_token", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("expected 404 for non-existent token, got %d", w.Code)
		}
	}

	// Case 1b: 存在但无凭据的客户端请求 -> 401
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_active_token", nil)
		req.Header.Set("User-Agent", "v2rayNG/1.8.5")
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("expected 401 for unauthenticated client, got %d", w.Code)
		}
	}

	// Case 2: 熔断用户 (携带正确凭证) -> 403
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_suspended_token?pwd=pass1234", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for suspended user, got %d", w.Code)
		}
	}

	// Case 3: 默认 Base64 订阅返回 (带凭据)
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_active_token?pwd=pass1234", nil)
		req.Header.Set("User-Agent", "v2rayNG/1.8.5")
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for active user, got %d", w.Code)
		}

		userinfo := w.Header().Get("Subscription-Userinfo")
		if !strings.Contains(userinfo, "total=107374182400") {
			t.Errorf("missing or invalid Subscription-Userinfo header: %s", userinfo)
		}

		decoded, err := base64.StdEncoding.DecodeString(w.Body.String())
		if err != nil {
			t.Fatalf("failed to decode base64 response: %v", err)
		}
		decodedStr := string(decoded)
		if !strings.Contains(decodedStr, "vless://") || !strings.Contains(decodedStr, "hysteria2://") {
			t.Errorf("expected vless and hysteria2 links in decoded base64, got: %s", decodedStr)
		}
	}

	// Case 4: Clash YAML 导出 (?type=clash&pwd=pass1234)
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_active_token?type=clash&pwd=pass1234", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for clash export, got %d", w.Code)
		}

		var clashConf map[string]any
		err := yaml.Unmarshal(w.Body.Bytes(), &clashConf)
		if err != nil {
			t.Fatalf("invalid YAML in clash export: %v", err)
		}

		proxies, ok := clashConf["proxies"].([]any)
		if !ok || len(proxies) == 0 {
			t.Fatalf("expected non-empty proxies in clash config")
		}
	}

	// Case 5: Sing-box JSON 导出 (?type=singbox&pwd=pass1234)
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_active_token?type=singbox&pwd=pass1234", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for singbox export, got %d", w.Code)
		}

		var singboxConf map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &singboxConf)
		if err != nil {
			t.Fatalf("invalid JSON in singbox export: %v", err)
		}

		outbounds, ok := singboxConf["outbounds"].([]any)
		if !ok || len(outbounds) == 0 {
			t.Fatalf("expected non-empty outbounds in singbox config")
		}
	}

	// Case 6: 浏览器未带凭据访问自服务门户 -> 显示安全锁定页面 (200)
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_active_token", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for browser lock portal, got %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "订阅凭证安全解锁") {
			t.Errorf("portal HTML missing lock title, got: %s", body)
		}
	}

	// Case 7: 浏览器携带凭据访问自服务门户 -> 解锁并渲染控制台 (200)
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_active_token?pwd=pass1234", nil)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for browser user portal, got %d", w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Work-V 订阅中心") {
			t.Errorf("portal HTML missing brand title, got: %s", body)
		}
		if !strings.Contains(body, "active_user") {
			t.Errorf("portal HTML missing username, got: %s", body)
		}
		if !strings.Contains(body, "clash://install-config") {
			t.Errorf("portal HTML missing clash one-click import button, got: %s", body)
		}
	}
}

func TestSubscriptionIncludesNodeWithoutStoredInbounds(t *testing.T) {
	setupTestDB(t, "sub.db")

	node := model.Node{Name: "hk-01", Token: "tok-1", Address: "1.2.3.4", Rate: 1, Status: "offline"}
	createNodeAndUser(t, &node, "u1")

	// 模拟主控启动时的历史数据补齐
	service.EnsureAllNodesInbounds()

	var after model.Node
	if err := model.DB.First(&after, node.ID).Error; err != nil {
		t.Fatalf("读取节点: %v", err)
	}
	if strings.TrimSpace(after.InboundsJSON) == "" {
		t.Fatalf("启动补齐后节点仍无入站配置")
	}

	cases := []struct {
		name string
		ua   string
	}{
		{"base64", "Shadowrocket/2.2.0"},
		{"clash", "ClashforWindows/0.20.39"},
		{"sing-box", "sing-box 1.13.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, w := newSubContext(t, "subt", tc.ua)
			HandleSubscription(c)

			body := w.Body.String()
			if w.Code != 200 {
				t.Fatalf("订阅返回状态码 %d, body=%s", w.Code, body)
			}
			if strings.TrimSpace(body) == "" {
				t.Fatalf("订阅内容为空")
			}
			if !strings.Contains(body, "1.2.3.4") && tc.name != "base64" {
				t.Errorf("订阅内容缺少节点地址: %s", body)
			}
			if tc.name == "base64" {
				raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(body))
				if err != nil {
					t.Fatalf("base64 解码失败: %v (body=%q)", err, body)
				}
				if !strings.Contains(string(raw), "1.2.3.4") {
					t.Errorf("订阅解码后缺少节点地址: %s", string(raw))
				}
			}
		})
	}
}

func TestSubscriptionDoesNotWriteNode(t *testing.T) {
	setupTestDB(t, "sub_ro.db")

	node := model.Node{Name: "hk-02", Token: "tok-2", Address: "5.6.7.8", Rate: 1, Status: "online"}
	createNodeAndUser(t, &node, "u2")

	c, w := newSubContext(t, "subt", "ClashforWindows/0.20.39")
	HandleSubscription(c)
	if w.Code != 200 {
		t.Fatalf("订阅返回状态码 %d", w.Code)
	}

	var after model.Node
	if err := model.DB.First(&after, node.ID).Error; err != nil {
		t.Fatalf("读取节点: %v", err)
	}
	if after.InboundsJSON != "" {
		t.Errorf("订阅请求写入了节点入站配置 (纯读约束被破坏): %s", after.InboundsJSON)
	}
}

func TestSubscriptionNeverUsesRequestHost(t *testing.T) {
	setupTestDB(t, "sub_host.db")

	node := model.Node{Name: "hk-03", Token: "tok-3", Address: "自动探测", Rate: 1, Status: "online"}
	createNodeAndUser(t, &node, "u3")
	service.EnsureAllNodesInbounds()

	for _, ua := range []string{"ClashforWindows/0.20.39", "sing-box 1.13.0", "Shadowrocket"} {
		c, w := newSubContext(t, "subt", ua)
		c.Request.Host = "attacker-controlled.example.net"
		HandleSubscription(c)
		if strings.Contains(w.Body.String(), "attacker-controlled.example.net") {
			t.Errorf("订阅内容里出现了请求 Host (可被伪造劫持): %s", w.Body.String())
		}
	}
}

func TestNormalizeRealityKey(t *testing.T) {
	hexKey := "4302030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	want := "QwIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	if got := normalizeRealityKey(hexKey); got != want {
		t.Errorf("hex 公钥归一化错误: got=%q want=%q", got, want)
	}
	if got := normalizeRealityKey(want); got != want {
		t.Errorf("base64 公钥被破坏: got=%q want=%q", got, want)
	}
	if got := normalizeRealityKey(""); got != "" {
		t.Errorf("空值应原样返回: %q", got)
	}
}

func TestUniqueNameDedup(t *testing.T) {
	used := make(map[string]int)
	got := []string{
		uniqueName(used, "HK-01-Reality"),
		uniqueName(used, "HK-01-Reality"),
		uniqueName(used, "HK-01-Reality"),
	}
	want := []string{"HK-01-Reality", "HK-01-Reality-2", "HK-01-Reality-3"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("去重结果错误: got=%v want=%v", got, want)
			break
		}
	}
}
