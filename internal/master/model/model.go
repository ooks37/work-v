package model

import (
	"time"
	"gorm.io/gorm"
)

// Admin 管理员账号
type Admin struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	Username     string         `gorm:"uniqueIndex;size:64;not null" json:"username"`
	PasswordHash string         `gorm:"size:255;not null" json:"-"`
	LastLoginAt  *time.Time     `json:"last_login_at"`
	LastLoginIP  string         `gorm:"size:64" json:"last_login_ip"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// Node 托管服务器节点
type Node struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	Name        string         `gorm:"size:100;not null" json:"name"`
	Token       string         `gorm:"uniqueIndex;size:64;not null" json:"token"`     // 节点连接凭证
	Address     string         `gorm:"size:255;not null" json:"address"`             // 节点客户端访问地址 (域名或公网IP)
	Rate        float64        `gorm:"default:1.0" json:"rate"`                      // 流量计算倍率
	Status      string         `gorm:"size:20;default:'offline'" json:"status"`      // "online" | "offline"
	LastSeenAt  *time.Time     `json:"last_seen_at"`                                 // 最近一次心跳时间
	
	// 动态监控数据 (由心跳更新)
	CPUPercent  float64        `json:"cpu_percent"`
	MemUsed     uint64         `json:"mem_used"`
	MemTotal    uint64         `json:"mem_total"`
	NetRxRate   uint64         `json:"net_rx_rate"`   // 实时下行速率 bytes/s
	NetTxRate   uint64         `json:"net_tx_rate"`   // 实时上行速率 bytes/s
	UptimeSec   uint64         `json:"uptime_sec"`
	AgentVer    string         `gorm:"size:32" json:"agent_ver"`
	SingboxPid  int            `json:"singbox_pid"`

	// 协议配置项 (JSON 序列化存储)
	InboundsJSON string        `gorm:"type:text" json:"inbounds_json"`

	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// User 订阅用户
type User struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	Username     string         `gorm:"size:64;not null" json:"username"`
	UUID         string         `gorm:"uniqueIndex;size:64;not null" json:"uuid"`      // Sing-box 客户端鉴权 UUID
	SubToken     string         `gorm:"uniqueIndex;size:64;not null" json:"sub_token"` // 外部订阅专用 Token
	TrafficLimit int64          `gorm:"default:0" json:"traffic_limit"`               // 流量配额限制 (Bytes, 0为不限)
	UsedTraffic  int64          `gorm:"default:0" json:"used_traffic"`                // 已消耗流量 (Bytes)
	ExpireAt     int64          `gorm:"default:0" json:"expire_at"`                   // 到期时间戳 (秒, 0为永久)
	Status       string         `gorm:"size:20;default:'active'" json:"status"`       // "active" | "suspended" | "expired"
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

// SystemSetting 系统全局设置
type SystemSetting struct {
	Key       string    `gorm:"primaryKey;size:64" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}
