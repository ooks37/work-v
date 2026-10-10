package runner

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"work-v/internal/common"
)

const sleepHelperSrc = `package main

import (
	"os"
	"time"
)

func main() {
	hb := os.Args[len(os.Args)-1]
	for {
		_ = os.WriteFile(hb, []byte(time.Now().String()), 0644)
		time.Sleep(100 * time.Millisecond)
	}
}
`

func buildSleepHelper(t *testing.T) (string, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "workv-runner-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(sleepHelperSrc), 0644); err != nil {
		t.Fatalf("写入 helper: %v", err)
	}
	// 统一带 .exe 后缀: Windows 下没有扩展名无法被 exec 执行, Linux 下只是文件名
	bin := filepath.Join(dir, "fake-singbox-bin.exe")
	build := exec.Command("go", "build", "-o", bin, src)
	if out, err := build.CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		t.Skipf("无法构建测试 helper (跳过): %v %s", err, out)
	}
	return dir, bin
}

func fileKeepsUpdating(t *testing.T, p string) bool {
	t.Helper()
	s1, err := os.Stat(p)
	if err != nil {
		return false
	}
	time.Sleep(400 * time.Millisecond)
	s2, err := os.Stat(p)
	if err != nil {
		return false
	}
	return s2.ModTime().After(s1.ModTime())
}

// 历史缺陷: 旧进程的 watcher 协程会在新进程启动之后把共享的 running 改成 false,
// 导致面板显示"内核已停止"、ApplyConfig 的幂等短路永久失效 (每次下发配置都重启内核)。
func TestReloadKeepsRunningState(t *testing.T) {
	dir, bin := buildSleepHelper(t)
	defer os.RemoveAll(dir)

	cfgDir := filepath.Join(dir, "cfg")
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	hb1 := filepath.Join(cfgDir, "hb1")
	hb2 := filepath.Join(cfgDir, "hb2")

	r := NewSingboxRunner(bin, cfgDir)

	r.mu.Lock()
	if err := r.restartProcess(hb1); err != nil {
		r.mu.Unlock()
		t.Fatalf("首次启动失败: %v", err)
	}
	r.mu.Unlock()
	time.Sleep(250 * time.Millisecond)

	// 第二次下发配置 (ApplyConfig 同样持锁调用)
	r.mu.Lock()
	err := r.restartProcess(hb2)
	r.mu.Unlock()
	if err != nil {
		t.Fatalf("重启失败: %v", err)
	}
	pid := r.GetPid()
	defer func() {
		if p, e := os.FindProcess(pid); e == nil && p != nil {
			_ = p.Kill()
		}
	}()

	time.Sleep(900 * time.Millisecond) // 给旧 watcher 充分的"作恶"时间

	if !fileKeepsUpdating(t, hb2) {
		t.Skip("helper 进程未按预期运行, 跳过")
	}
	if !r.IsRunning() || r.GetPid() == 0 {
		t.Errorf("新 sing-box 进程 (pid=%d) 仍在运行, 但 runner 报告 running=%v pid=%d",
			pid, r.IsRunning(), r.GetPid())
	}
}

// 历史缺陷: 无法归属的流量会被记到 activeUsers[0], 让排在第一位的用户背所有人的流量。
func TestUnattributedTrafficIsNotBilledToFirstUser(t *testing.T) {
	const body = `{"downloadTotal":5000,"uploadTotal":3000,"connections":[
 {"id":"c1","upload":100,"download":200,"metadata":{"user":""}},
 {"id":"c2","upload":10,"download":20,"metadata":{"user":"bob"}}
]}`

	ln, err := net.Listen("tcp", "127.0.0.1:9090")
	if err != nil {
		t.Skipf("端口 9090 被占用, 跳过: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, body)
	})}
	defer srv.Close()
	go func() { _ = srv.Serve(ln) }()
	time.Sleep(150 * time.Millisecond)

	r := NewSingboxRunner("sing-box", t.TempDir())
	r.activeUsers = []common.UserProfile{
		{UUID: "uuid-ALICE", Username: "alice", Status: "active"},
		{UUID: "uuid-BOB", Username: "bob", Status: "active"},
	}

	for _, d := range r.CollectTraffic() {
		if d.UUID == "uuid-ALICE" {
			t.Errorf("无法归属的连接流量被记到了第一个用户 alice 身上 (up=%d down=%d)", d.Up, d.Down)
		}
	}
}

func certPayload() *common.NodeConfigPayload {
	return &common.NodeConfigPayload{
		Users: []common.UserProfile{{Username: "u1", UUID: "uuid-1", Password: "p1", Status: "active"}},
		Inbounds: []common.InboundConfig{
			{Type: "vless", Tag: "vless-in", ListenPort: 2083, Enabled: true,
				Options: map[string]any{"private_key": "GFNY7WrCAo4m2guHkgcPe08N13yNE5lOJYtwW4_9ZVI", "short_id": "317928a0"}},
			{Type: "hysteria2", Tag: "hy2-in", ListenPort: 8443, Enabled: true, Options: map[string]any{}},
			{Type: "tuic", Tag: "tuic-in", ListenPort: 8444, Enabled: true, Options: map[string]any{}},
		},
	}
}

// 证书必须能自动生成 (纯 Go, 不依赖 openssl), 否则 hy2/TUIC 会被静默跳过、
// 或者更糟: 引用不存在的证书文件让整份配置 check 失败。
func TestSelfSignedCertificateIsGeneratedWithoutOpenssl(t *testing.T) {
	configDir := t.TempDir()
	out, err := generateSingboxJSON(certPayload(), configDir)
	if err != nil {
		t.Fatalf("generateSingboxJSON: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "cert.pem")); err != nil {
		t.Errorf("自签证书未生成: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "key.pem")); err != nil {
		t.Errorf("自签私钥未生成: %v", err)
	}
	js := string(out)
	for _, tag := range []string{"vless-in", "hy2-in", "tuic-in"} {
		if !strings.Contains(js, tag) {
			t.Errorf("证书可用时 %s 应当被写入配置: %s", tag, js)
		}
	}
}

// 证书确实无法生成时必须降级: 跳过证书相关入站, 保留 Reality,
// 而不是让整份配置(包括 VLESS)一起下发失败。
func TestMissingCertificateDegradesGracefully(t *testing.T) {
	matches, _ := filepath.Glob("/etc/letsencrypt/live/*/fullchain.pem")
	if len(matches) > 0 {
		t.Skip("本机存在 Let's Encrypt 证书, 无法构造证书缺失场景")
	}

	configDir := t.TempDir()
	// 把 cert.pem 建成目录 => 既不算"已存在证书", 也无法被写入
	if err := os.MkdirAll(filepath.Join(configDir, "cert.pem"), 0755); err != nil {
		t.Fatalf("构造证书写入失败场景: %v", err)
	}
	out, err := generateSingboxJSON(certPayload(), configDir)
	if err != nil {
		t.Fatalf("缺少证书时不应让整份配置生成失败: %v", err)
	}
	js := string(out)
	if !strings.Contains(js, "vless-in") {
		t.Errorf("Reality 入站被误删: %s", js)
	}
	if strings.Contains(js, "hy2-in") || strings.Contains(js, "tuic-in") {
		t.Errorf("证书不可用时仍生成了证书相关入站 (会导致 sing-box check 失败): %s", js)
	}
}
