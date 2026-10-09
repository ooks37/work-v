package sub

import (
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"work-v/internal/master/model"

	"github.com/gin-gonic/gin"
)

// setupTestDB 每个用例独立数据库, 结束时关闭连接 (Windows 下不关闭会导致临时目录删不掉)
func setupTestDB(t *testing.T, name string) {
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
	if _, err := model.InitDB(filepath.Join(dir, name)); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
}

func newSubContext(t *testing.T, token string, ua string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/sub/"+token, nil)
	c.Request.Host = "panel.example.com"
	if ua != "" {
		c.Request.Header.Set("User-Agent", ua)
	}
	c.Params = gin.Params{{Key: "token", Value: token}}
	return c, w
}

// 历史缺陷: 订阅生成器遇到空的 InboundsJSON 直接 continue,
// 于是 work-v add-node 建的节点 (没有落库入站配置) 在订阅里一个都不出现,
// 而面板"节点链接"因为有 fallback 显示正常 -> 极难排查。
func TestSubscriptionIncludesNodeWithoutStoredInbounds(t *testing.T) {
	setupTestDB(t, "sub.db")

	node := model.Node{Name: "hk-01", Token: "tok-1", Address: "1.2.3.4", Rate: 1, Status: "offline"}
	if err := model.DB.Create(&node).Error; err != nil {
		t.Fatalf("创建节点: %v", err)
	}
	if node.InboundsJSON != "" {
		t.Fatalf("前置条件错误: 节点不应带有入站配置")
	}
	user := model.User{Username: "u1", UUID: "11111111-1111-1111-1111-111111111111",
		SubToken: "subt", Status: "active"}
	if err := model.DB.Create(&user).Error; err != nil {
		t.Fatalf("创建用户: %v", err)
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
