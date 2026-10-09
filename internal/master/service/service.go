package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"work-v/internal/common"
	"work-v/internal/master/hub"
	"work-v/internal/master/model"

	"golang.org/x/crypto/curve25519"
)

// GenerateX25519KeyPair 自动生成 Reality 协议所需的 x25519 公私钥对
func GenerateX25519KeyPair() (privateKeyBase64, publicKeyBase64 string, err error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", "", err
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	var pub [32]byte
	curve25519.ScalarBaseMult(&pub, &priv)

	return hex.EncodeToString(priv[:]), hex.EncodeToString(pub[:]), nil
}

// GenerateShortID 生成 8 字节 Reality ShortID
func GenerateShortID() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GetOrCreateDefaultInbounds 为节点生成默认开箱即用的 Inbounds (默认 VLESS-Reality 免证书)
func GetOrCreateDefaultInbounds(n *model.Node) []common.InboundConfig {
	if n.InboundsJSON != "" {
		var inbounds []common.InboundConfig
		if err := json.Unmarshal([]byte(n.InboundsJSON), &inbounds); err == nil && len(inbounds) > 0 {
			return inbounds
		}
	}

	privKey, pubKey, _ := GenerateX25519KeyPair()
	shortID := GenerateShortID()

	// 默认开箱配置：443 端口 VLESS-Reality (伪装 apple icloud) + 8443 端口 Hysteria 2
	inbounds := []common.InboundConfig{
		{
			Type:       "vless",
			Tag:        "vless-reality-in",
			ListenPort: 443,
			Enabled:    true,
			Options: map[string]any{
				"server_name": "gateway.icloud.com",
				"dest":        "gateway.icloud.com:443",
				"private_key": privKey,
				"public_key":  pubKey,
				"short_id":    shortID,
			},
		},
		{
			Type:       "hysteria2",
			Tag:        "hy2-in",
			ListenPort: 8443,
			Enabled:    true,
			Options: map[string]any{
				"insecure": true, // 支持一键自签证书
				"up_mbps":  100,
				"down_mbps": 500,
			},
		},
	}

	data, _ := json.Marshal(inbounds)
	n.InboundsJSON = string(data)
	model.DB.Model(n).Update("inbounds_json", n.InboundsJSON)

	return inbounds
}

// BuildNodeConfigPayload 组装下发给 Agent 的完整 sing-box 运行配置
func BuildNodeConfigPayload(nodeID uint) (*common.NodeConfigPayload, error) {
	var node model.Node
	if err := model.DB.First(&node, nodeID).Error; err != nil {
		return nil, fmt.Errorf("节点不存在: %w", err)
	}

	inbounds := GetOrCreateDefaultInbounds(&node)

	// 查询所有状态为 active 且未过期的用户
	now := time.Now().Unix()
	var users []model.User
	model.DB.Where("status = ?", "active").Find(&users)

	var validProfiles []common.UserProfile
	for _, u := range users {
		// 校验到期
		if u.ExpireAt > 0 && u.ExpireAt < now {
			model.DB.Model(&u).Update("status", "expired")
			continue
		}
		// 校验配额
		if u.TrafficLimit > 0 && u.UsedTraffic >= u.TrafficLimit {
			model.DB.Model(&u).Update("status", "suspended")
			continue
		}

		validProfiles = append(validProfiles, common.UserProfile{
			ID:       u.ID,
			Username: u.Username,
			UUID:     u.UUID,
			Password: u.UUID, // 对 hy2 也复用 uuid 作为安全凭据
			Status:   u.Status,
		})
	}

	// 计算配置哈希
	raw, _ := json.Marshal(struct {
		In []common.InboundConfig `json:"in"`
		Us []common.UserProfile   `json:"us"`
	}{In: inbounds, Us: validProfiles})
	h := sha256.Sum256(raw)
	configHash := hex.EncodeToString(h[:])

	return &common.NodeConfigPayload{
		ConfigHash: configHash,
		Inbounds:   inbounds,
		Users:      validProfiles,
	}, nil
}

// RecordTraffic 集中结算并实施秒级配额熔断
func RecordTraffic(nodeID uint, users []common.UserDeltaTraffic) {
	var node model.Node
	if err := model.DB.First(&node, nodeID).Error; err != nil {
		return
	}

	rate := node.Rate
	if rate <= 0 {
		rate = 1.0
	}

	for _, rep := range users {
		delta := int64(float64(rep.Up+rep.Down) * rate)
		if delta <= 0 {
			continue
		}

		var u model.User
		if err := model.DB.Where("uuid = ?", rep.UUID).First(&u).Error; err != nil {
			continue
		}

		newTotal := u.UsedTraffic + delta
		model.DB.Model(&u).Update("used_traffic", newTotal)

		// 检查是否达到流量限制，触发秒级熔断
		if u.TrafficLimit > 0 && newTotal >= u.TrafficLimit {
			model.DB.Model(&u).Update("status", "suspended")
			log.Printf("[Quota] 用户 %s 流量超标 (已用: %d / 上限: %d)，触发全网秒级熔断!", u.Username, newTotal, u.TrafficLimit)
			hub.GlobalHub.BroadcastCutoffUser(u.UUID)
		}
	}
}

// StartQuotaWatchdog 启动后台监控：定期检查到期用户并熔断
func StartQuotaWatchdog() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			now := time.Now().Unix()
			var expiredUsers []model.User
			model.DB.Where("status = ? AND expire_at > 0 AND expire_at <= ?", "active", now).Find(&expiredUsers)

			for _, u := range expiredUsers {
				model.DB.Model(&u).Update("status", "expired")
				log.Printf("[Quota] 用户 %s 已过期，执行全网下线广播", u.Username)
				hub.GlobalHub.BroadcastCutoffUser(u.UUID)
			}
		}
	}()
}
