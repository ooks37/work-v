package model

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDB 初始化数据库连接与自动迁移
func InitDB(dbPath string) (*gorm.DB, error) {
	if dbPath == "" {
		dbPath = "data/work-v.db"
	}

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据库目录失败: %w", err)
	}

	// 启用 WAL 模式与 5 秒繁忙重试，极大减少并发锁冲突
	dsn := fmt.Sprintf("%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("连接 SQLite 失败: %w", err)
	}

	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(1) // 配合 WAL 模式，确保单写入句柄，杜绝 database locked
		sqlDB.SetMaxIdleConns(1)
	}

	// 自动数据迁移
	if err := db.AutoMigrate(
		&Admin{},
		&Node{},
		&User{},
		&SystemSetting{},
	); err != nil {
		return nil, fmt.Errorf("数据库表迁移失败: %w", err)
	}

	DB = db

	// 修复历史版本写坏的时间列 (必须在任何读取之前执行)
	repairSystemSettings(db)

	// 检查并初始化系统核心安全密钥 (JWT 密钥、安全入口动态 Salt 等)
	initSystemSecrets(db)

	// 检查是否需要初始化默认管理员
	initDefaultAdmin(db)

	return db, nil
}

// GetSetting 读取系统设置
func GetSetting(key, defaultVal string) string {
	if DB == nil {
		return defaultVal
	}
	var s SystemSetting
	if err := DB.Where("key = ?", key).First(&s).Error; err == nil && s.Value != "" {
		return s.Value
	}
	return defaultVal
}

// SetSetting 保存或更新系统设置 (原子 upsert, 避免读改写竞态)
// 注意: 这里必须写 time.Now()。历史实现误写成 os.Getenv("TZ"), 会把时区字符串塞进
// updated_at 时间列, 导致该行之后再也无法被 GORM 扫描 (unsupported Scan ... *time.Time),
// 读取时静默回落到默认值 (域名/JWT 密钥等设置"改第二次就丢")。
func SetSetting(key, val string) error {
	if DB == nil {
		return fmt.Errorf("db not initialized")
	}
	now := time.Now()
	return DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.Assignments(map[string]any{"value": val, "updated_at": now}),
	}).Create(&SystemSetting{Key: key, Value: val, UpdatedAt: now}).Error
}

// repairSystemSettings 修复历史版本缺陷造成的 updated_at 脏数据。
func repairSystemSettings(db *gorm.DB) {
	res := db.Exec(
		"UPDATE system_settings SET updated_at = ? WHERE updated_at IS NULL OR length(updated_at) < 19 OR updated_at NOT LIKE '____-__-__%'",
		time.Now(),
	)
	if res.Error != nil {
		log.Printf("[Work-V] 修复 system_settings 时间列失败: %v", res.Error)
		return
	}
	if res.RowsAffected > 0 {
		log.Printf("[Work-V] 已修复 %d 条被污染的系统设置记录 (updated_at)", res.RowsAffected)
	}
}

// DefaultSafePath 默认安全入口路径
const DefaultSafePath = "/safe_entry"

// GetSafeEntryConfig 读取安全入口配置。
// 不能用 "safe_path 为空" 表示"已关闭"——重启后会被默认值重新打开 (历史缺陷),
// 因此引入显式开关 safe_entry_enabled ("1"/"0")。
func GetSafeEntryConfig() (enabled bool, path string) {
	if DB != nil {
		var s SystemSetting
		if err := DB.Where("key = ?", "safe_path").First(&s).Error; err == nil {
			path = strings.TrimSpace(s.Value)
		}
		if GetSetting("safe_entry_enabled", "1") == "0" {
			return false, path
		}
	}
	if path == "" || path == "/" {
		path = DefaultSafePath
	}
	return true, path
}

func initSystemSecrets(db *gorm.DB) {
	// 1. 初始化唯一高熵 JWT 密钥
	var jwtSetting SystemSetting
	if err := db.Where("key = ?", "jwt_secret").First(&jwtSetting).Error; err != nil || jwtSetting.Value == "" {
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		newSecret := fmt.Sprintf("%x", buf)
		db.Save(&SystemSetting{Key: "jwt_secret", Value: newSecret, UpdatedAt: time.Now()})
	}

	// 2. 初始化安全入口动态凭证盐值 (防止全局静态 Cookie 绕过)
	var saltSetting SystemSetting
	if err := db.Where("key = ?", "entrance_salt").First(&saltSetting).Error; err != nil || saltSetting.Value == "" {
		buf := make([]byte, 16)
		_, _ = rand.Read(buf)
		newSalt := fmt.Sprintf("%x", buf)
		db.Save(&SystemSetting{Key: "entrance_salt", Value: newSalt, UpdatedAt: time.Now()})
	}
}

func initDefaultAdmin(db *gorm.DB) {
	var count int64
	db.Model(&Admin{}).Count(&count)
	if count == 0 {
		hash, err := bcrypt.GenerateFromPassword([]byte("admin123456"), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("初始化密码哈希失败: %v", err)
		}
		admin := Admin{
			Username:     "admin",
			PasswordHash: string(hash),
		}
		if err := db.Create(&admin).Error; err != nil {
			log.Printf("创建默认管理员失败: %v", err)
		} else {
			log.Println("==================================================")
			log.Println("[Work-V] 初始化系统默认管理员成功:")
			log.Println("  用户名: admin")
			log.Println("  初始密码: admin123456 (请在控制台及时修改)")
			log.Println("==================================================")
		}
	}
}
