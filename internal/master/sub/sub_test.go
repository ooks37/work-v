package sub

import (
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"work-v/internal/master/model"
	"work-v/internal/master/service"

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

// createNodeAndUser 建节点+用户; 节点必须传指针, 否则拿不到自增 ID (测试里要按 ID 回读)
func createNodeAndUser(t *testing.T, node *model.Node, username string) model.User {
	t.Helper()
	if err := model.DB.Create(node).Error; err != nil {
		t.Fatalf("创建节点: %v", err)
	}
	user := model.User{Username: username, UUID: "11111111-1111-1111-1111-111111111111",
		SubToken: "subt", Status: "active"}
	if err := model.DB.Create(&user).Error; err != nil {
		t.Fatalf("创建用户: %v", err)
	}
	return user
}

// 历史缺陷: 订阅生成器遇到空的 InboundsJSON 直接 continue,
// 于是 work-v add-node 建的节点 (没有落库入站配置) 在订阅里一个都不出现,
// 而面板"节点链接"因为有 fallback 显示正常 -> 极难排查。
//
// 现在入站由启动期 EnsureAllNodesInbounds 一次性补齐 (订阅侧保持纯读),
// 因此这里先模拟启动补齐, 再断言节点出现在订阅里。
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

// 订阅接口是免鉴权的 GET, 绝不允许产生写库副作用。
// 历史实现在这里"发现入站为空就生成新 x25519 密钥并 UPDATE":
// 并发请求会互相覆盖节点密钥, 先返回给用户的 pbk 永久对不上节点实际密钥。
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

// 安全: 节点没有可用地址时必须跳过, 不能回落到请求 Host ——
// 否则任何持订阅令牌的人伪造 Host 就能让整份订阅指向自己的域名。
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

// Reality 公钥兼容: 历史版本落库的是 64 位 hex, 必须归一化成 base64url,
// 否则客户端解出 48 字节公钥, 该节点对所有客户端握手失败。
func TestNormalizeRealityKey(t *testing.T) {
	hexKey := "4302030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	want := "QwIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	if got := normalizeRealityKey(hexKey); got != want {
		t.Errorf("hex 公钥归一化错误: got=%q want=%q", got, want)
	}
	// 已经是 base64url 的必须原样保留
	if got := normalizeRealityKey(want); got != want {
		t.Errorf("base64 公钥被破坏: got=%q want=%q", got, want)
	}
	if got := normalizeRealityKey(""); got != "" {
		t.Errorf("空值应原样返回: %q", got)
	}
}

// 重名节点会让 Mihomo 以 duplicate name 拒绝整份配置, 因此生成时必须去重。
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
