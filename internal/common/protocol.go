package common

import (
	"encoding/json"
	"time"
)

// WebSocket 消息类型常量
const (
	MsgTypeAuthReq      = "auth_req"       // Agent -> Master: 发送 Token 认证
	MsgTypeAuthResp     = "auth_resp"      // Master -> Agent: 认证结果
	MsgTypeHeartbeat    = "heartbeat"      // Agent -> Master: 节点负载与状态上报
	MsgTypeTraffic      = "traffic_report" // Agent -> Master: 用户流量差量上报
	MsgTypeConfigPush   = "config_push"    // Master -> Agent: 下发最新 sing-box 配置
	MsgTypeConfigAck    = "config_ack"     // Agent -> Master: 配置应用回执
	MsgTypeCutoffUser   = "cutoff_user"    // Master -> Agent: 熔断/踢掉违规/超额用户
	MsgTypeCommand      = "command"        // Master -> Agent: 运维指令 (重启 sing-box, 重新采集)
)

// WSMessage 统一长连通信帧结构
type WSMessage struct {
	Type      string          `json:"type"`                // 消息类型
	NodeToken string          `json:"node_token,omitempty"` // 节点 Token
	Timestamp int64           `json:"timestamp"`           // 毫秒时间戳
	Payload   json.RawMessage `json:"payload,omitempty"`   // 负载数据
}

// NewWSMessage 辅助构造消息
func NewWSMessage(msgType string, payload any) (*WSMessage, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &WSMessage{
		Type:      msgType,
		Timestamp: time.Now().UnixMilli(),
		Payload:   data,
	}, nil
}

// NodeHardwareStats 节点物理状态上报载荷
type NodeHardwareStats struct {
	CPUPercent    float64 `json:"cpu_percent"`    // CPU 使用率 0~100
	MemUsedBytes  uint64  `json:"mem_used_bytes"` // 内存已用 (Bytes)
	MemTotalBytes uint64  `json:"mem_total_bytes"`// 内存总量 (Bytes)
	NetRxRate     uint64  `json:"net_rx_rate"`    // 实时下行速率 (Bytes/s)
	NetTxRate     uint64  `json:"net_tx_rate"`    // 实时上行速率 (Bytes/s)
	SingboxStatus string  `json:"singbox_status"` // "running", "stopped", "error"
	SingboxPid    int     `json:"singbox_pid"`    // 进程 PID
	UptimeSec     uint64  `json:"uptime_sec"`     // 系统运行时间
	Version       string  `json:"version"`        // Agent 版本
}

// UserDeltaTraffic 单用户流量增量
type UserDeltaTraffic struct {
	UUID string `json:"uuid"` // 用户 UUID
	Up   int64  `json:"up"`   // 周期内上传增量字节
	Down int64  `json:"down"` // 周期内下载增量字节
}

// TrafficReportPayload Agent 上报的一组用户流量
type TrafficReportPayload struct {
	Users []UserDeltaTraffic `json:"users"`
}

// InboundConfig 协议入站配置
type InboundConfig struct {
	Type       string         `json:"type"`       // "vless", "hysteria2", "shadowsocks"
	Tag        string         `json:"tag"`        // "vless-in", "hy2-in", "ss-in"
	ListenPort int            `json:"listen_port"`// 监听端口
	Enabled    bool           `json:"enabled"`    // 是否启用
	Options    map[string]any `json:"options"`    // 协议特定参数 (Reality 密钥、伪装域名、证书路径等)
}

// UserProfile 用户凭据与认证信息
type UserProfile struct {
	ID        uint   `json:"id"`
	Username  string `json:"username"`
	UUID      string `json:"uuid"`     // VLESS UUID / Hysteria2 密码 / SS 密码
	Password  string `json:"password"` // 补充密钥
	Status    string `json:"status"`   // "active", "suspended", "expired"
}

// NodeConfigPayload Master 下发给 Agent 的完整 sing-box 运行配置
type NodeConfigPayload struct {
	ConfigHash string          `json:"config_hash"` // 配置哈希，用于幂等检测
	Inbounds   []InboundConfig `json:"inbounds"`    // 启用的入站协议列表
	Users      []UserProfile   `json:"users"`       // 有效用户列表
}
