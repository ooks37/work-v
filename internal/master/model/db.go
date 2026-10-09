package model

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
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

// SetSetting 保存或更新系统设置
func SetSetting(key, val string) error {
	if DB == nil {
		return fmt.Errorf("db not initialized")
	}
	var s SystemSetting
	if err := DB.Where("key = ?", key).First(&s).Error; err == nil {
		return DB.Model(&s).Updates(map[string]any{"value": val, "updated_at": os.Getenv("TZ")}).Error
	}
	return DB.Create(&SystemSetting{Key: key, Value: val}).Error
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
