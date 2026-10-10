package sub

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"work-v/internal/common"
	"work-v/internal/master/model"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

func setupTestDB(t *testing.T) string {
	gin.SetMode(gin.TestMode)
	dbPath := "test_sub.db"
	_ = os.Remove(dbPath)
	_, err := model.InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	return dbPath
}

func TestHandleSubscription(t *testing.T) {
	dbPath := setupTestDB(t)
	defer os.Remove(dbPath)

	// 创建测试节点
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

	// 创建正常用户
	activeUser := model.User{
		Username:     "active_user",
		UUID:         "11111111-2222-3333-4444-555555555555",
		SubToken:     "sub_active_token",
		TrafficLimit: 100 * 1024 * 1024 * 1024,
		UsedTraffic:  10 * 1024 * 1024 * 1024,
		ExpireAt:     time.Now().Add(30 * 24 * time.Hour).Unix(),
		Status:       "active",
	}
	model.DB.Create(&activeUser)

	// 创建熔断用户
	suspendedUser := model.User{
		Username:     "suspended_user",
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

	// Case 2: 熔断用户 -> 403
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_suspended_token", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 for suspended user, got %d", w.Code)
		}
	}

	// Case 3: 默认 Base64 订阅返回
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_active_token", nil)
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

	// Case 4: Clash YAML 导出 (?type=clash)
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_active_token?type=clash", nil)
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

	// Case 5: Sing-box JSON 导出 (?type=singbox)
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_active_token?type=singbox", nil)
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

	// Case 6: 浏览器直接访问自服务门户 (Accept: text/html)
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/sub/sub_active_token", nil)
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
