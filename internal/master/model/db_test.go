package model

import (
	"os"
	"path/filepath"
	"testing"
)

// setupTestDB 使用独立临时目录, 并在用例结束时关闭连接 (否则 Windows 无法删除仍被占用的文件)
func setupTestDB(t *testing.T, name string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "workv-model-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		if DB != nil {
			if sqlDB, err := DB.DB(); err == nil {
				_ = sqlDB.Close()
			}
			DB = nil
		}
		_ = os.RemoveAll(dir)
	})
	if _, err := InitDB(filepath.Join(dir, name)); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
}

// 复现并锁定历史缺陷: SetSetting 曾把 os.Getenv("TZ") 写进 updated_at 时间列,
// 第二次修改后整行无法被 GORM 扫描, GetSetting 静默回落到默认值 (域名/JWT 密钥"改第二次就丢")。
func TestSetSettingIsReadableAfterRepeatedWrites(t *testing.T) {
	setupTestDB(t, "setting.db")

	if err := SetSetting("master_domain", "panel.example.com"); err != nil {
		t.Fatalf("first SetSetting: %v", err)
	}
	if got := GetSetting("master_domain", ""); got != "panel.example.com" {
		t.Fatalf("第一次写入后读取异常: %q", got)
	}

	if err := SetSetting("master_domain", "vpn.example.com"); err != nil {
		t.Fatalf("second SetSetting: %v", err)
	}
	if got := GetSetting("master_domain", ""); got != "vpn.example.com" {
		t.Errorf("第二次写入后设置丢失: 期望 vpn.example.com, 实际 %q", got)
	}

	// 行本身必须仍然可被 GORM 扫描 (updated_at 必须是合法时间)
	var s SystemSetting
	if err := DB.Where("key = ?", "master_domain").First(&s).Error; err != nil {
		t.Errorf("设置行无法被读取: %v", err)
	}
	if s.UpdatedAt.IsZero() {
		t.Errorf("updated_at 为空, 时间列被写坏")
	}
}

// 安全入口开关必须显式持久化: 历史实现用 "safe_path 为空" 表示关闭,
// 重启后会被默认值重新打开 (work-v disable-entry 失效)。
func TestGetSafeEntryConfigRespectsExplicitSwitch(t *testing.T) {
	setupTestDB(t, "entry.db")

	// 1. 默认状态: 启用且为默认路径
	enabled, path := GetSafeEntryConfig()
	if !enabled || path != DefaultSafePath {
		t.Fatalf("默认状态异常: enabled=%v path=%q", enabled, path)
	}

	// 2. 关闭之后必须一直保持关闭 (即使 safe_path 为空)
	if err := SetSetting("safe_entry_enabled", "0"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	enabled, _ = GetSafeEntryConfig()
	if enabled {
		t.Errorf("显式关闭后仍然报告已启用")
	}

	// 3. 重新设置路径后恢复启用
	_ = SetSetting("safe_path", "/my_secret")
	_ = SetSetting("safe_entry_enabled", "1")
	enabled, path = GetSafeEntryConfig()
	if !enabled || path != "/my_secret" {
		t.Errorf("重新启用异常: enabled=%v path=%q", enabled, path)
	}
}
