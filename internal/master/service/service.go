package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	"work-v/internal/common"
	"work-v/internal/master/hub"
	"work-v/internal/master/model"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"
	"gorm.io/gorm"
)

// GenerateX25519KeyPair 自动生成 Reality 协议所需的 x25519 公私钥对 (Base64 URL 安全格式)
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

	return base64.RawURLEncoding.EncodeToString(priv[:]), base64.RawURLEncoding.EncodeToString(pub[:]), nil
}

// GenerateShortID 生成 8 字节 Reality ShortID
func GenerateShortID() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// EnsureAllNodesInbounds 启动期补齐历史节点的入站配置。
//
// 背景: 订阅接口已改为纯读 (避免并发请求各自生成 Reality 密钥互相覆盖,
// 导致用户拿到的 pbk 与节点实际密钥永久不匹配), 因此入站必须在建节点时就落库。
// 这里对历史数据做一次性补齐 —— 启动期单写入者, 不存在竞态。
func EnsureAllNodesInbounds() {
	var nodes []model.Node
	if err := model.DB.Find(&nodes).Error; err != nil {
		return
	}
	fixed := 0
	for i := range nodes {
		if strings.TrimSpace(nodes[i].InboundsJSON) == "" {
			GetOrCreateDefaultInbounds(&nodes[i])
			fixed++
		}
	}
	if fixed > 0 {
		log.Printf("[Work-V] 已为 %d 个历史节点补齐入站配置 (Reality 密钥一次性生成并落库)", fixed)
	}
}

// CreateCustomInbounds 根据管理员指定的协议选择列表定制创建入站配置
func CreateCustomInbounds(n *model.Node, enabledProtocols []string) []common.InboundConfig {
	privKey, pubKey, _ := GenerateX25519KeyPair()
	shortID := GenerateShortID()

	protoMap := make(map[string]bool)
	for _, p := range enabledProtocols {
		protoMap[strings.ToLower(strings.TrimSpace(p))] = true
	}
	// 若未指定任何协议，默认仅启用高隐蔽协议 (VLESS-WS 与 VLESS-Reality)
	if len(enabledProtocols) == 0 {
		protoMap["vless-ws"] = true
		protoMap["vless"] = true
		protoMap["grpc-reality"] = true
	}

	inbounds := []common.InboundConfig{
		{
			Type:       "vless",
			Tag:        "vless-reality-in",
			ListenPort: 2083,
			Enabled:    protoMap["vless"] || protoMap["reality"] || protoMap["vless-reality"],
			Options: map[string]any{
				"server_name": "gateway.icloud.com",
				"dest":        "gateway.icloud.com:443",
				"flow":        "xtls-rprx-vision",
				"private_key": privKey,
				"public_key":  pubKey,
				"short_id":    shortID,
			},
		},
		{
			Type:       "hysteria2",
			Tag:        "hy2-in",
			ListenPort: 8443,
			Enabled:    protoMap["hysteria2"] || protoMap["hy2"],
			Options: map[string]any{
				"insecure":  true,
				"up_mbps":   100,
				"down_mbps": 500,
			},
		},
		{
			Type:       "grpc-reality",
			Tag:        "grpc-reality-in",
			ListenPort: 2053,
			Enabled:    protoMap["grpc-reality"] || protoMap["grpc"],
			Options: map[string]any{
				"server_name":  "gateway.icloud.com",
				"dest":         "gateway.icloud.com:443",
				"service_name": "grpc-service",
				"private_key":  privKey,
				"public_key":   pubKey,
				"short_id":     shortID,
			},
		},
		{
			Type:       "tuic",
			Tag:        "tuic-in",
			ListenPort: 8444,
			Enabled:    protoMap["tuic"],
			Options: map[string]any{
				"congestion_control": "bbr",
				"alpn":               []string{"h3"},
				"insecure":           true,
			},
		},
		{
			Type:       "anytls",
			Tag:        "anytls-in",
			ListenPort: 8445,
			Enabled:    protoMap["anytls"],
			Options: map[string]any{
				"server_name": "gateway.icloud.com",
				"insecure":    true,
			},
		},
		{
			Type:       "shadowsocks",
			Tag:        "ss-in",
			ListenPort: 8388,
			Enabled:    protoMap["shadowsocks"] || protoMap["ss"],
			Options: map[string]any{
				"method":   "2022-blake3-aes-128-gcm",
				"password": "d29ya3YxMjM0NTY3ODkwMQ==",
			},
		},
		{
			Type:       "vless-ws",
			Tag:        "vless-ws-in",
			ListenPort: 2096,
			Enabled:    protoMap["vless-ws"] || protoMap["ws"],
			Options: map[string]any{
				"server_name": "gateway.icloud.com",
				"path":        "/ws",
			},
		},
		{
			Type:       "vmess-ws",
			Tag:        "vmess-ws-in",
			ListenPort: 2095,
			Enabled:    protoMap["vmess-ws"] || protoMap["vmess"],
			Options: map[string]any{
				"server_name": "gateway.icloud.com",
				"path":        "/vmess",
			},
		},
		{
			Type:       "trojan",
			Tag:        "trojan-in",
			ListenPort: 8446,
			Enabled:    protoMap["trojan"],
			Options: map[string]any{
				"server_name": "gateway.icloud.com",
			},
		},
	}

	data, _ := json.Marshal(inbounds)
	n.InboundsJSON = string(data)
	if model.DB != nil && n.ID > 0 {
		model.DB.Model(n).Update("inbounds_json", n.InboundsJSON)
	}

	return inbounds
}

// GetOrCreateDefaultInbounds 为节点生成默认开箱即用的 Inbounds (默认 VLESS-Reality 免证书)
func GetOrCreateDefaultInbounds(n *model.Node) []common.InboundConfig {
	if n.InboundsJSON != "" {
		var inbounds []common.InboundConfig
		if err := json.Unmarshal([]byte(n.InboundsJSON), &inbounds); err == nil && len(inbounds) > 0 {
			return inbounds
		}
	}
	return CreateCustomInbounds(n, nil)
}

// ProtocolShareLink 单个协议的客户端直连链接与元数据
type ProtocolShareLink struct {
	Protocol    string `json:"protocol"`    // 协议标识
	Name        string `json:"name"`        // 节点显示名
	Port        int    `json:"port"`        // 监听端口
	PortType    string `json:"port_type"`   // TCP / UDP
	Link        string `json:"link"`        // 完整客户端导入链接 (vless://, hysteria2://, tuic:// 等)
	Description string `json:"description"` // 协议特性说明
}

// GenerateNodeShareLinks 为指定节点与用户生成所有已启用协议的分享链接
func GenerateNodeShareLinks(node *model.Node, userUUID, username string) []ProtocolShareLink {
	if node.Address == "" || node.Address == "自动探测" {
		if d := model.GetSetting("master_domain", ""); d != "" {
			node.Address = d
		} else {
			node.Address = "127.0.0.1"
		}
	}
	if userUUID == "" {
		userUUID = "11111111-2222-3333-4444-555555555555"
	}
	if username == "" {
		username = "user"
	}

	var inbounds []common.InboundConfig
	if err := json.Unmarshal([]byte(node.InboundsJSON), &inbounds); err != nil || len(inbounds) == 0 {
		inbounds = GetOrCreateDefaultInbounds(node)
	}

	links := make([]ProtocolShareLink, 0)
	for _, in := range inbounds {
		if !in.Enabled {
			continue
		}

		isGRPC := in.Type == "grpc-reality" || (in.Type == "vless" && (strings.Contains(in.Tag, "grpc") || in.Options["service_name"] != nil))
		isWS := in.Type == "vless-ws" || (in.Type == "vless" && (strings.Contains(in.Tag, "ws") || in.Options["path"] != nil))

		switch {
		case isGRPC:
			pubKey, _ := in.Options["public_key"].(string)
			shortID, _ := in.Options["short_id"].(string)
			serverName, _ := in.Options["server_name"].(string)
			svcName, _ := in.Options["service_name"].(string)
			if serverName == "" {
				serverName = "gateway.icloud.com"
			}
			if svcName == "" {
				svcName = "grpc-service"
			}
			link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=grpc&serviceName=%s#%s",
				userUUID, node.Address, in.ListenPort, serverName, pubKey, shortID, svcName, fmt.Sprintf("%s-gRPC-Reality", node.Name))
			links = append(links, ProtocolShareLink{
				Protocol:    "grpc-reality",
				Name:        fmt.Sprintf("%s (gRPC Reality)", node.Name),
				Port:        in.ListenPort,
				PortType:    "TCP",
				Link:        link,
				Description: "基于 gRPC 传输的 Reality 节点，穿透性强，适配 CDN 与负载均衡",
			})

		case isWS:
			serverName, _ := in.Options["server_name"].(string)
			if serverName == "" {
				serverName = node.Address
			}
			wsPath, _ := in.Options["path"].(string)
			if wsPath == "" {
				wsPath = "/ws"
			}
			link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&sni=%s&type=ws&path=%s&allowInsecure=1#%s",
				userUUID, node.Address, in.ListenPort, serverName, url.QueryEscape(wsPath), url.QueryEscape(fmt.Sprintf("%s-VLESS-WS", node.Name)))
			links = append(links, ProtocolShareLink{
				Protocol:    "vless-ws",
				Name:        fmt.Sprintf("%s (VLESS WebSocket)", node.Name),
				Port:        in.ListenPort,
				PortType:    "TCP",
				Link:        link,
				Description: "基于 WebSocket + TLS 的传输协议，兼容 CDN 节点代理与反代加速",
			})

		case in.Type == "vmess-ws" || in.Type == "vmess":
			serverName, _ := in.Options["server_name"].(string)
			if serverName == "" {
				serverName = node.Address
			}
			wsPath, _ := in.Options["path"].(string)
			if wsPath == "" {
				wsPath = "/vmess"
			}
			vmessMeta := map[string]string{
				"v":    "2",
				"ps":   fmt.Sprintf("%s-VMess-WS", node.Name),
				"add":  node.Address,
				"port": strconv.Itoa(in.ListenPort),
				"id":   userUUID,
				"aid":  "0",
				"net":  "ws",
				"type": "none",
				"host": serverName,
				"path": wsPath,
				"tls":  "tls",
				"sni":  serverName,
			}
			metaJSON, _ := json.Marshal(vmessMeta)
			link := "vmess://" + base64.StdEncoding.EncodeToString(metaJSON)
			links = append(links, ProtocolShareLink{
				Protocol:    "vmess-ws",
				Name:        fmt.Sprintf("%s (VMess WebSocket)", node.Name),
				Port:        in.ListenPort,
				PortType:    "TCP",
				Link:        link,
				Description: "经典 VMess + WebSocket + TLS / CDN 传输协议 (233boy 经典兼容)",
			})

		case in.Type == "vless":
			pubKey, _ := in.Options["public_key"].(string)
			shortID, _ := in.Options["short_id"].(string)
			serverName, _ := in.Options["server_name"].(string)
			if serverName == "" {
				serverName = "gateway.icloud.com"
			}
			link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp#%s",
				userUUID, node.Address, in.ListenPort, serverName, pubKey, shortID, fmt.Sprintf("%s-Reality", node.Name))
			links = append(links, ProtocolShareLink{
				Protocol:    "vless-reality",
				Name:        fmt.Sprintf("%s (VLESS Reality)", node.Name),
				Port:        in.ListenPort,
				PortType:    "TCP",
				Link:        link,
				Description: "主流防封 Reality 伪装，基于 Vision 流控，原生 443 伪装",
			})

		case in.Type == "hysteria2":
			serverName, _ := in.Options["server_name"].(string)
			if serverName == "" {
				serverName = node.Address
			}
			link := fmt.Sprintf("hysteria2://%s@%s:%d/?sni=%s&insecure=1#%s",
				userUUID, node.Address, in.ListenPort, serverName, url.QueryEscape(fmt.Sprintf("%s-Hy2", node.Name)))
			links = append(links, ProtocolShareLink{
				Protocol:    "hysteria2",
				Name:        fmt.Sprintf("%s (Hysteria 2)", node.Name),
				Port:        in.ListenPort,
				PortType:    "UDP",
				Link:        link,
				Description: "基于 UDP 协议自研拥塞控制算法，极速抗封锁与低延迟",
			})

		case in.Type == "tuic":
			link := fmt.Sprintf("tuic://%s:%s@%s:%d?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#%s",
				userUUID, userUUID, node.Address, in.ListenPort, fmt.Sprintf("%s-TUIC", node.Name))
			links = append(links, ProtocolShareLink{
				Protocol:    "tuic",
				Name:        fmt.Sprintf("%s (TUIC v5)", node.Name),
				Port:        in.ListenPort,
				PortType:    "UDP",
				Link:        link,
				Description: "TUIC v5 自研 QUIC 协议，支持 BBR 拥塞控制与原生 UDP 中继",
			})

		case in.Type == "anytls":
			serverName, _ := in.Options["server_name"].(string)
			if serverName == "" {
				serverName = "gateway.icloud.com"
			}
			link := fmt.Sprintf("anytls://%s@%s:%d/?sni=%s&insecure=1#%s",
				userUUID, node.Address, in.ListenPort, serverName, fmt.Sprintf("%s-AnyTLS", node.Name))
			links = append(links, ProtocolShareLink{
				Protocol:    "anytls",
				Name:        fmt.Sprintf("%s (AnyTLS)", node.Name),
				Port:        in.ListenPort,
				PortType:    "TCP",
				Link:        link,
				Description: "AnyTLS 轻量化 TLS 传输协议",
			})

		case in.Type == "shadowsocks":
			method, _ := in.Options["method"].(string)
			if method == "" {
				method = "2022-blake3-aes-128-gcm"
			}
			pwd, _ := in.Options["password"].(string)
			if pwd == "" {
				pwd = "d29ya3YxMjM0NTY3ODkwMQ=="
			}
			userInfo := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", method, pwd)))
			link := fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, node.Address, in.ListenPort, url.QueryEscape(fmt.Sprintf("%s-Shadowsocks", node.Name)))
			links = append(links, ProtocolShareLink{
				Protocol:    "shadowsocks",
				Name:        fmt.Sprintf("%s (Shadowsocks)", node.Name),
				Port:        in.ListenPort,
				PortType:    "TCP",
				Link:        link,
				Description: fmt.Sprintf("经典抗封锁协议 (%s)，兼容原版 SS 与小火箭", method),
			})

		case in.Type == "trojan":
			serverName, _ := in.Options["server_name"].(string)
			if serverName == "" {
				serverName = node.Address
			}
			link := fmt.Sprintf("trojan://%s@%s:%d?security=tls&sni=%s&allowInsecure=1#%s",
				userUUID, node.Address, in.ListenPort, serverName, url.QueryEscape(fmt.Sprintf("%s-Trojan", node.Name)))
			links = append(links, ProtocolShareLink{
				Protocol:    "trojan",
				Name:        fmt.Sprintf("%s (Trojan)", node.Name),
				Port:        in.ListenPort,
				PortType:    "TCP",
				Link:        link,
				Description: "经典 Trojan 伪装协议，标准 TLS 流量特征",
			})
		}
	}
	return links
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

// RecordTraffic 集中结算并实施秒级配额熔断 (原子累加，杜绝多节点并发更新丢失)
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

		// 原子递增流量，防止多节点并发覆盖
		if err := model.DB.Model(&model.User{}).Where("uuid = ?", rep.UUID).
			Update("used_traffic", gorm.Expr("used_traffic + ?", delta)).Error; err != nil {
			continue
		}

		var u model.User
		if err := model.DB.Where("uuid = ?", rep.UUID).First(&u).Error; err != nil {
			continue
		}

		// 检查是否达到流量限制，触发秒级熔断
		if u.TrafficLimit > 0 && u.UsedTraffic >= u.TrafficLimit {
			model.DB.Model(&u).Update("status", "suspended")
			log.Printf("[Quota] 用户 %s 流量超标 (已用: %d / 上限: %d)，触发全网秒级熔断!", u.Username, u.UsedTraffic, u.TrafficLimit)
			hub.GlobalHub.BroadcastCutoffUser(u.UUID)
			pushConfigToAllNodes("流量超标")
		}
	}
}

// pushConfigToAllNodes 重新下发全网配置。
//
// 熔断只踢掉现有连接是不够的: 内核里的用户凭据(配置)没变, 客户端断开后用同一凭据
// 立刻就能重连继续用。必须让内核重载"不含该用户"的配置, 熔断才真正生效。
func pushConfigToAllNodes(reason string) {
	var nodes []model.Node
	if err := model.DB.Find(&nodes).Error; err != nil {
		return
	}
	for i := range nodes {
		nodeID := nodes[i].ID
		go hub.GlobalHub.PushConfigToNode(nodeID)
	}
	if len(nodes) > 0 {
		log.Printf("[Quota] 已向 %d 个节点重新下发配置 (%s), 确保被熔断用户的内核凭据同步失效", len(nodes), reason)
	}
}

// StartQuotaWatchdog 启动后台监控：定期检查到期用户熔断并同步离线节点
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
				pushConfigToAllNodes("已过期")
			}

			// 同步离线节点状态
			hub.GlobalHub.SyncOfflineNodes()
		}
	}()
}

// BatchCreateUsers 批量生成订阅用户
func BatchCreateUsers(prefix string, count int, trafficLimitGB int64, expireDays int64) ([]model.User, error) {
	if prefix == "" {
		prefix = "user"
	}
	if count <= 0 {
		count = 1
	}
	if count > 50 {
		count = 50
	}

	var expireAt int64 = 0
	if expireDays > 0 {
		expireAt = time.Now().AddDate(0, 0, int(expireDays)).Unix()
	}

	created := make([]model.User, 0, count)
	for i := 1; i <= count; i++ {
		uBytes := make([]byte, 4)
		rand.Read(uBytes)
		uname := fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(uBytes))

		user := model.User{
			Username:     uname,
			UUID:         uuid.New().String(),
			SubToken:     hex.EncodeToString(append(uBytes, uBytes...)),
			TrafficLimit: trafficLimitGB * 1024 * 1024 * 1024,
			UsedTraffic:  0,
			ExpireAt:     expireAt,
			Status:       "active",
		}

		if err := model.DB.Create(&user).Error; err != nil {
			return nil, err
		}
		created = append(created, user)
	}

	// 触发全网节点更新配置
	var nodes []model.Node
	model.DB.Find(&nodes)
	for _, n := range nodes {
		go hub.GlobalHub.PushConfigToNode(n.ID)
	}

	return created, nil
}

// ResetAllUsersTraffic 一键重置全网用户的已用流量
func ResetAllUsersTraffic() error {
	if err := model.DB.Model(&model.User{}).Where("1 = 1").Updates(map[string]any{
		"used_traffic": 0,
		"status":       "active",
	}).Error; err != nil {
		return err
	}

	// 触发全网节点更新配置
	var nodes []model.Node
	model.DB.Find(&nodes)
	for _, n := range nodes {
		go hub.GlobalHub.PushConfigToNode(n.ID)
	}
	return nil
}
