package hub

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"work-v/internal/common"

	"github.com/gorilla/websocket"
)

// wsPair 生成一对真实的 websocket 连接 (register 会调用 old.Conn.Close())
func wsPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srvCh := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		srvCh <- c
	}))
	t.Cleanup(srv.Close)

	dialURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	cli, _, err := websocket.DefaultDialer.Dial(dialURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return <-srvCh, cli
}

func newAgent(t *testing.T, id uint, token string, buf int) *AgentConn {
	t.Helper()
	srv, cli := wsPair(t)
	t.Cleanup(func() { _ = cli.Close() })
	return &AgentConn{
		NodeID:    id,
		NodeToken: token,
		Conn:      srv,
		SendChan:  make(chan *common.WSMessage, buf),
		LastSeen:  time.Now(),
	}
}

// 历史缺陷: PushConfigToNode 在解锁后才向 SendChan 发送, 而节点重连会在写锁里 close 旧通道,
// 撞车时触发 "send on closed channel" 直接打挂主控进程 (该路径由 handler 派生的 goroutine 调用)。
func TestPushConfigToNodeSurvivesNodeReconnect(t *testing.T) {
	h := NewHub()
	h.SetCallbacks(nil, func(uint) (*common.NodeConfigPayload, error) {
		return &common.NodeConfigPayload{ConfigHash: "hash-1"}, nil
	})

	old := newAgent(t, 7, "token-7", 1)
	h.register(old)
	old.SendChan <- &common.WSMessage{Type: common.MsgTypeHeartbeat} // 占满缓冲, 强制走重试分支

	done := make(chan error, 1)
	go func() { done <- h.PushConfigToNode(7) }()

	time.Sleep(40 * time.Millisecond) // 让推送进入重试循环

	fresh := newAgent(t, 7, "token-7", 8)
	h.register(fresh) // 同一 token 重连: 关闭旧通道

	select {
	case err := <-done:
		t.Logf("推送返回: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("PushConfigToNode 未在预期时间内返回")
	}

	if ok := h.IsNodeOnline(7); !ok {
		t.Errorf("重连后的节点应当在线")
	}
}

func TestKickNodeClosesConnectionOnce(t *testing.T) {
	h := NewHub()
	a := newAgent(t, 9, "token-9", 4)
	h.register(a)

	h.KickNode(9)
	h.KickNode(9) // 幂等: 不允许二次 close 造成 panic

	if h.IsNodeOnline(9) {
		t.Errorf("节点被踢下线后不应仍标记为在线")
	}
	// unregister 由 readPump 在连接断开后调用, 此时表中已无该连接, 不得再次 close
	h.unregister(a)
}

func TestMaskToken(t *testing.T) {
	if got := maskToken("node_0123456789abcdef"); strings.Contains(got, "6789") {
		t.Errorf("token 未脱敏: %s", got)
	}
	if got := maskToken("abc"); got != "***" {
		t.Errorf("短 token 应当完全隐藏, 得到 %q", got)
	}
}
