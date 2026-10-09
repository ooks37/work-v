package model

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

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

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("连接 SQLite 失败: %w", err)
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

	// 检查是否需要初始化默认管理员
	initDefaultAdmin(db)

	return db, nil
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
