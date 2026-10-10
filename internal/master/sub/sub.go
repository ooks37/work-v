package sub

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"work-v/internal/common"
	"work-v/internal/master/model"
	"work-v/internal/master/service"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// resolveNodeAddress 解析客户端可连接的节点地址 (只用节点自己的配置)。
//
// 安全: 历史实现会回落到 "主控域名" 甚至 "请求 Host"。后者意味着任何拿到订阅令牌的人
// 只要伪造 Host 头, 就能让订阅里所有节点地址变成他自己控制的域名 (流量劫持/钓鱼),
// 因此这里只认节点自身已落库的地址; 没地址的节点直接跳过 (agent 连上后会自动回填)。
func resolveNodeAddress(n *model.Node, c *gin.Context) string {
	addr := strings.TrimSpace(n.Address)
	if addr == "" || addr == "自动探测" || addr == "127.0.0.1" || addr == "localhost" {
		if d := model.GetSetting("master_domain", ""); d != "" {
			return d
		}
		return ""
	}
	return addr
}

// normalizeRealityKey 归一化 Reality 公钥。
// 历史版本把公钥以 64 位 hex 存库, 而客户端需要的是 32 字节原始数据的 base64url 形式;
// 直接下发 hex 会让客户端解出 48 字节公钥, 该节点对所有客户端都握手失败。
func normalizeRealityKey(k string) string {
	k = strings.TrimSpace(k)
	if len(k) != 64 {
		return k
	}
	raw, err := hex.DecodeString(k)
	if err != nil {
		return k
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// uniqueName 保证同一份订阅里的代理名/tag 唯一。
// 重名会让 Mihomo 因 "duplicate name" 拒绝整份配置 (整张订阅全部不可用)。
func uniqueName(used map[string]int, base string) string {
	used[base]++
	if used[base] == 1 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, used[base])
}

// resolveInbounds 解析节点入站配置 (纯读)。
func resolveInbounds(n *model.Node) []common.InboundConfig {
	var inbounds []common.InboundConfig
	if err := json.Unmarshal([]byte(n.InboundsJSON), &inbounds); err != nil {
		return nil
	}
	return inbounds
}

// protoMatches 判断协议是否匹配用户筛选条件 (支持 ?proto=hy2 或 ?proto=reality 等)
func protoMatches(in common.InboundConfig, filter string) bool {
	if filter == "" || filter == "all" {
		return true
	}
	filter = strings.ToLower(filter)
	inType := strings.ToLower(in.Type)
	tag := strings.ToLower(in.Tag)
	isGRPC := inType == "grpc-reality" || (inType == "vless" && (strings.Contains(tag, "grpc") || in.Options["service_name"] != nil))
	isWS := inType == "vless-ws" || (inType == "vless" && (strings.Contains(tag, "ws") || in.Options["path"] != nil))

	switch filter {
	case "reality":
		return (inType == "vless" && !isWS) || isGRPC
	case "grpc":
		return isGRPC
	case "ws", "vless-ws":
		return isWS
	case "vless":
		return inType == "vless"
	case "hy2", "hysteria2", "hysteria":
		return inType == "hysteria2"
	case "tuic":
		return inType == "tuic"
	case "ss", "shadowsocks":
		return inType == "shadowsocks"
	case "trojan":
		return inType == "trojan"
	case "anytls":
		return inType == "anytls"
	default:
		return strings.Contains(inType, filter) || strings.Contains(tag, filter)
	}
}

// HandleSubscription 处理多端自适应订阅主入口
func HandleSubscription(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		c.String(http.StatusBadRequest, "Invalid subscription token")
		return
	}

	var user model.User
	if err := model.DB.Where("sub_token = ?", token).First(&user).Error; err != nil {
		c.String(http.StatusNotFound, "Subscription not found")
		return
	}

	// 注入客户端标准流量信息头 (Clash / Shadowrocket 支持直显配额进度条)
	userinfo := fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d",
		user.UsedTraffic, user.TrafficLimit, user.ExpireAt)
	c.Header("Subscription-Userinfo", userinfo)
	c.Header("Profile-Update-Interval", "24")

	now := time.Now().Unix()
	if user.Status != "active" || (user.ExpireAt > 0 && user.ExpireAt < now) || (user.TrafficLimit > 0 && user.UsedTraffic >= user.TrafficLimit) {
		c.String(http.StatusForbidden, "Subscription expired or quota exceeded")
		return
	}

	// 读取所有已配置且未删除的非隐藏节点 (过滤管理员设置的隐藏节点)
	var nodes []model.Node
	model.DB.Where("hidden = ?", false).Find(&nodes)

	// 获取客户端类型
	ua := strings.ToLower(c.GetHeader("User-Agent"))
	subType := strings.ToLower(c.Query("type"))
	accept := strings.ToLower(c.GetHeader("Accept"))

	// 浏览器直接访问展示用户自服务门户页面
	isBrowser := subType == "" && (strings.Contains(accept, "text/html") || strings.Contains(ua, "mozilla")) &&
		!strings.Contains(ua, "curl") && !strings.Contains(ua, "wget") && !strings.Contains(ua, "clash") &&
		!strings.Contains(ua, "sing-box") && !strings.Contains(ua, "shadowrocket") && !strings.Contains(ua, "v2ray") &&
		!strings.Contains(ua, "surge") && !strings.Contains(ua, "loon")
	if isBrowser {
		renderUserPortal(c, &user, nodes)
		return
	}

	if subType == "clash" || subType == "mihomo" || strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo") || strings.Contains(ua, "verge") {
		generateClashYAML(c, &user, nodes)
		return
	}

	if subType == "sing-box" || subType == "singbox" || strings.Contains(ua, "sing-box") || strings.Contains(ua, "s-box") {
		generateSingboxJSON(c, &user, nodes)
		return
	}

	// 默认 Base64 (小火箭 / V2rayN / 通用客户端)
	generateBase64Links(c, &user, nodes)
}

// generateBase64Links 生成 Base64 标准节点链接
func generateBase64Links(c *gin.Context, user *model.User, nodes []model.Node) {
	var links []string
	protoFilter := strings.ToLower(c.Query("proto"))

	for _, n := range nodes {
		nodeAddr := resolveNodeAddress(&n, c)
		if nodeAddr == "" {
			continue
		}
		inbounds := resolveInbounds(&n)
		if len(inbounds) == 0 {
			continue
		}

		for _, in := range inbounds {
			if !in.Enabled || !protoMatches(in, protoFilter) {
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

				params := url.Values{}
				params.Set("security", "reality")
				params.Set("sni", serverName)
				params.Set("pbk", normalizeRealityKey(pubKey))
				params.Set("sid", shortID)
				params.Set("type", "grpc")
				params.Set("serviceName", svcName)
				params.Set("encryption", "none")

				link := fmt.Sprintf("vless://%s@%s:%d?%s#%s",
					user.UUID, nodeAddr, in.ListenPort, params.Encode(), url.QueryEscape(fmt.Sprintf("%s-gRPC-Reality", n.Name)))
				links = append(links, link)

			case isWS:
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}
				wsPath, _ := in.Options["path"].(string)
				if wsPath == "" {
					wsPath = "/ws"
				}
				link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&sni=%s&type=ws&path=%s&allowInsecure=1#%s",
					user.UUID, nodeAddr, in.ListenPort, serverName, url.QueryEscape(wsPath), url.QueryEscape(fmt.Sprintf("%s-VLESS-WS", n.Name)))
				links = append(links, link)

			case in.Type == "vless":
				pubKey, _ := in.Options["public_key"].(string)
				shortID, _ := in.Options["short_id"].(string)
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = "gateway.icloud.com"
				}

				params := url.Values{}
				params.Set("security", "reality")
				params.Set("sni", serverName)
				params.Set("pbk", normalizeRealityKey(pubKey))
				params.Set("sid", shortID)
				params.Set("type", "tcp")
				params.Set("flow", "xtls-rprx-vision")
				params.Set("encryption", "none")

				link := fmt.Sprintf("vless://%s@%s:%d?%s#%s",
					user.UUID, nodeAddr, in.ListenPort, params.Encode(), url.QueryEscape(fmt.Sprintf("%s-Reality", n.Name)))
				links = append(links, link)

			case in.Type == "hysteria2":
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}
				params := url.Values{}
				params.Set("insecure", "1")
				params.Set("sni", serverName)

				link := fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s",
					user.UUID, nodeAddr, in.ListenPort, params.Encode(), url.QueryEscape(fmt.Sprintf("%s-Hy2", n.Name)))
				links = append(links, link)

			case in.Type == "tuic":
				link := fmt.Sprintf("tuic://%s:%s@%s:%d?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#%s",
					user.UUID, user.UUID, nodeAddr, in.ListenPort, url.QueryEscape(fmt.Sprintf("%s-TUIC", n.Name)))
				links = append(links, link)

			case in.Type == "anytls":
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = "gateway.icloud.com"
				}
				link := fmt.Sprintf("anytls://%s@%s:%d/?sni=%s&insecure=1#%s",
					user.UUID, nodeAddr, in.ListenPort, serverName, url.QueryEscape(fmt.Sprintf("%s-AnyTLS", n.Name)))
				links = append(links, link)

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
				link := fmt.Sprintf("ss://%s@%s:%d#%s", userInfo, nodeAddr, in.ListenPort, url.QueryEscape(fmt.Sprintf("%s-Shadowsocks", n.Name)))
				links = append(links, link)

			case in.Type == "trojan":
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}
				link := fmt.Sprintf("trojan://%s@%s:%d?security=tls&sni=%s&allowInsecure=1#%s",
					user.UUID, nodeAddr, in.ListenPort, serverName, url.QueryEscape(fmt.Sprintf("%s-Trojan", n.Name)))
				links = append(links, link)
			}
		}
	}

	plain := strings.Join(links, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(http.StatusOK, encoded)
}

// generateClashYAML 生成 Mihomo (Clash.Meta) YAML 完整订阅
func generateClashYAML(c *gin.Context, user *model.User, nodes []model.Node) {
	var proxies []map[string]any
	var proxyNames []string
	usedNames := make(map[string]int) // 同名节点会导致 Mihomo 拒绝整份配置, 这里强制去重
	protoFilter := strings.ToLower(c.Query("proto"))

	for _, n := range nodes {
		nodeAddr := resolveNodeAddress(&n, c)
		if nodeAddr == "" {
			continue
		}
		inbounds := resolveInbounds(&n)
		if len(inbounds) == 0 {
			continue
		}

		for _, in := range inbounds {
			if !in.Enabled || !protoMatches(in, protoFilter) {
				continue
			}

			isGRPC := in.Type == "grpc-reality" || (in.Type == "vless" && (strings.Contains(in.Tag, "grpc") || in.Options["service_name"] != nil))
			isWS := in.Type == "vless-ws" || (in.Type == "vless" && (strings.Contains(in.Tag, "ws") || in.Options["path"] != nil))

			switch {
			case isGRPC:
				name := uniqueName(usedNames, fmt.Sprintf("%s-gRPC-Reality", n.Name))
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

				p := map[string]any{
					"name":       name,
					"type":       "vless",
					"server":     nodeAddr,
					"port":       in.ListenPort,
					"uuid":       user.UUID,
					"network":    "grpc",
					"tls":        true,
					"udp":        true,
					"servername": serverName,
					"reality-opts": map[string]any{
						"public-key": normalizeRealityKey(pubKey),
						"short-id":   shortID,
					},
					"grpc-opts": map[string]any{
						"grpc-service-name": svcName,
					},
					"client-fingerprint": "chrome",
				}
				proxies = append(proxies, p)
				proxyNames = append(proxyNames, name)

			case isWS:
				name := uniqueName(usedNames, fmt.Sprintf("%s-VLESS-WS", n.Name))
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}
				wsPath, _ := in.Options["path"].(string)
				if wsPath == "" {
					wsPath = "/ws"
				}
				p := map[string]any{
					"name":             name,
					"type":             "vless",
					"server":           nodeAddr,
					"port":             in.ListenPort,
					"uuid":             user.UUID,
					"network":          "ws",
					"tls":              true,
					"udp":              true,
					"servername":       serverName,
					"skip-cert-verify": true,
					"ws-opts": map[string]any{
						"path": wsPath,
					},
				}
				proxies = append(proxies, p)
				proxyNames = append(proxyNames, name)

			case in.Type == "vless":
				name := uniqueName(usedNames, fmt.Sprintf("%s-Reality", n.Name))
				pubKey, _ := in.Options["public_key"].(string)
				shortID, _ := in.Options["short_id"].(string)
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = "gateway.icloud.com"
				}

				p := map[string]any{
					"name":       name,
					"type":       "vless",
					"server":     nodeAddr,
					"port":       in.ListenPort,
					"uuid":       user.UUID,
					"network":    "tcp",
					"tls":        true,
					"udp":        true,
					"flow":       "xtls-rprx-vision",
					"servername": serverName,
					"reality-opts": map[string]any{
						"public-key": normalizeRealityKey(pubKey),
						"short-id":   shortID,
					},
					"client-fingerprint": "chrome",
				}
				proxies = append(proxies, p)
			case in.Type == "hysteria2":
				name := uniqueName(usedNames, fmt.Sprintf("%s-Hy2", n.Name))
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}

				p := map[string]any{
					"name":             name,
					"type":             "hysteria2",
					"server":           nodeAddr,
					"port":             in.ListenPort,
					"password":         user.UUID,
					"sni":              serverName,
					"skip-cert-verify": true,
				}
				proxies = append(proxies, p)
				proxyNames = append(proxyNames, name)

			case in.Type == "tuic":
				name := uniqueName(usedNames, fmt.Sprintf("%s-TUIC", n.Name))
				p := map[string]any{
					"name":                  name,
					"type":                  "tuic",
					"server":                nodeAddr,
					"port":                  in.ListenPort,
					"uuid":                  user.UUID,
					"password":              user.UUID,
					"alpn":                  []string{"h3"},
					"congestion-controller": "bbr",
					"skip-cert-verify":      true,
				}
				proxies = append(proxies, p)
				proxyNames = append(proxyNames, name)

			case in.Type == "shadowsocks":
				name := uniqueName(usedNames, fmt.Sprintf("%s-Shadowsocks", n.Name))
				method, _ := in.Options["method"].(string)
				if method == "" {
					method = "2022-blake3-aes-128-gcm"
				}
				pwd, _ := in.Options["password"].(string)
				if pwd == "" {
					pwd = "d29ya3YxMjM0NTY3ODkwMQ=="
				}
				p := map[string]any{
					"name":     name,
					"type":     "ss",
					"server":   nodeAddr,
					"port":     in.ListenPort,
					"cipher":   method,
					"password": pwd,
					"udp":      true,
				}
				proxies = append(proxies, p)
				proxyNames = append(proxyNames, name)

			case in.Type == "trojan":
				name := uniqueName(usedNames, fmt.Sprintf("%s-Trojan", n.Name))
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}
				p := map[string]any{
					"name":             name,
					"type":             "trojan",
					"server":           nodeAddr,
					"port":             in.ListenPort,
					"password":         user.UUID,
					"udp":              true,
					"sni":              serverName,
					"skip-cert-verify": true,
				}
				proxies = append(proxies, p)
				proxyNames = append(proxyNames, name)

			case in.Type == "anytls":
				name := uniqueName(usedNames, fmt.Sprintf("%s-AnyTLS", n.Name))
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}
				p := map[string]any{
					"name":             name,
					"type":             "anytls",
					"server":           nodeAddr,
					"port":             in.ListenPort,
					"password":         user.UUID,
					"sni":              serverName,
					"skip-cert-verify": true,
					"udp":              true,
				}
				proxies = append(proxies, p)
				proxyNames = append(proxyNames, name)
			}
		}
	}

	if len(proxyNames) == 0 {
		proxyNames = append(proxyNames, "DIRECT")
	}

	config := map[string]any{
		"port":                7890,
		"socks-port":          7891,
		"allow-lan":           false,
		"mode":                "rule",
		"log-level":           "info",
		"external-controller": "127.0.0.1:9090",
		"dns": map[string]any{
			"enable":        true,
			"enhanced-mode": "fake-ip",
			"nameserver":    []string{"223.5.5.5", "119.29.29.29", "8.8.8.8"},
		},
		"proxies": proxies,
		"proxy-groups": []map[string]any{
			{
				"name":    "PROXIES",
				"type":    "select",
				"proxies": append([]string{"AUTO"}, proxyNames...),
			},
			{
				"name":      "AUTO",
				"type":      "url-test",
				"proxies":   proxyNames,
				"url":       "http://www.gstatic.com/generate_204",
				"interval":  300,
				"tolerance": 50,
			},
		},
		"rules": []string{
			"GEOIP,CN,DIRECT",
			"MATCH,PROXIES",
		},
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		c.String(http.StatusInternalServerError, "YAML Marshal Error")
		return
	}

	c.Header("Content-Type", "text/yaml; charset=utf-8")
	c.String(http.StatusOK, string(data))
}

// generateSingboxJSON 生成 Sing-box 官方 JSON 配置
func generateSingboxJSON(c *gin.Context, user *model.User, nodes []model.Node) {
	var outbounds []map[string]any
	var outTags []string
	protoFilter := strings.ToLower(c.Query("proto"))

	for _, n := range nodes {
		nodeAddr := resolveNodeAddress(&n, c)
		if nodeAddr == "" {
			continue
		}
		inbounds := resolveInbounds(&n)
		if len(inbounds) == 0 {
			continue
		}

		for _, in := range inbounds {
			if !in.Enabled || !protoMatches(in, protoFilter) {
				continue
			}

			isGRPC := strings.Contains(strings.ToLower(in.Tag), "grpc") || strings.EqualFold(in.Type, "grpc-reality") || strings.EqualFold(fmt.Sprint(in.Options["transport"]), "grpc")
			isWS := strings.Contains(strings.ToLower(in.Tag), "ws") || strings.EqualFold(in.Type, "vless-ws") || strings.EqualFold(fmt.Sprint(in.Options["transport"]), "ws")

			if (in.Type == "vless" || in.Type == "grpc-reality") && isGRPC {
				tag := fmt.Sprintf("%s-gRPC-Reality", n.Name)
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

				out := map[string]any{
					"type":        "vless",
					"tag":         tag,
					"server":      nodeAddr,
					"server_port": in.ListenPort,
					"uuid":        user.UUID,
					"transport": map[string]any{
						"type":         "grpc",
						"service_name": svcName,
					},
					"tls": map[string]any{
						"enabled":     true,
						"server_name": serverName,
						"reality": map[string]any{
							"enabled":    true,
							"public_key": normalizeRealityKey(pubKey),
							"short_id":   shortID,
						},
						"utls": map[string]any{
							"enabled":     true,
							"fingerprint": "chrome",
						},
					},
				}
				outbounds = append(outbounds, out)
				outTags = append(outTags, tag)

			} else if (in.Type == "vless" || in.Type == "vless-ws") && isWS {
				tag := fmt.Sprintf("%s-VLESS-WS", n.Name)
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}
				wsPath, _ := in.Options["path"].(string)
				if wsPath == "" {
					wsPath = "/ws"
				}
				out := map[string]any{
					"type":        "vless",
					"tag":         tag,
					"server":      nodeAddr,
					"server_port": in.ListenPort,
					"uuid":        user.UUID,
					"transport": map[string]any{
						"type": "ws",
						"path": wsPath,
					},
					"tls": map[string]any{
						"enabled":     true,
						"server_name": serverName,
						"insecure":    true,
					},
				}
				outbounds = append(outbounds, out)
				outTags = append(outTags, tag)

			} else {
				switch in.Type {
				case "vless":
					tag := fmt.Sprintf("%s-Reality", n.Name)
					pubKey, _ := in.Options["public_key"].(string)
					shortID, _ := in.Options["short_id"].(string)
					serverName, _ := in.Options["server_name"].(string)
					if serverName == "" {
						serverName = "gateway.icloud.com"
					}

					out := map[string]any{
						"type":        "vless",
						"tag":         tag,
						"server":      nodeAddr,
						"server_port": in.ListenPort,
						"uuid":        user.UUID,
						"flow":        "xtls-rprx-vision",
						"tls": map[string]any{
							"enabled":     true,
							"server_name": serverName,
							"reality": map[string]any{
								"enabled":    true,
								"public_key": normalizeRealityKey(pubKey),
								"short_id":   shortID,
							},
							"utls": map[string]any{
								"enabled":     true,
								"fingerprint": "chrome",
							},
						},
					}
					outbounds = append(outbounds, out)
					outTags = append(outTags, tag)

				case "hysteria2":
					tag := fmt.Sprintf("%s-Hy2", n.Name)
					serverName, _ := in.Options["server_name"].(string)
					if serverName == "" {
						serverName = nodeAddr
					}

					out := map[string]any{
						"type":        "hysteria2",
						"tag":         tag,
						"server":      nodeAddr,
						"server_port": in.ListenPort,
						"password":    user.UUID,
						"tls": map[string]any{
							"enabled":     true,
							"server_name": serverName,
							"insecure":    true,
						},
					}
					outbounds = append(outbounds, out)
					outTags = append(outTags, tag)

				case "tuic":
					tag := fmt.Sprintf("%s-TUIC", n.Name)
					out := map[string]any{
						"type":               "tuic",
						"tag":                tag,
						"server":             nodeAddr,
						"server_port":        in.ListenPort,
						"uuid":               user.UUID,
						"password":           user.UUID,
						"congestion_control": "bbr",
						"tls": map[string]any{
							"enabled":  true,
							"alpn":     []string{"h3"},
							"insecure": true,
						},
					}
					outbounds = append(outbounds, out)
					outTags = append(outTags, tag)

				case "anytls":
					tag := fmt.Sprintf("%s-AnyTLS", n.Name)
					serverName, _ := in.Options["server_name"].(string)
					if serverName == "" {
						serverName = "gateway.icloud.com"
					}
					out := map[string]any{
						"type":        "anytls",
						"tag":         tag,
						"server":      nodeAddr,
						"server_port": in.ListenPort,
						"password":    user.UUID,
						"tls": map[string]any{
							"enabled":     true,
							"server_name": serverName,
							"insecure":    true,
						},
					}
					outbounds = append(outbounds, out)
					outTags = append(outTags, tag)

				case "shadowsocks":
					tag := fmt.Sprintf("%s-Shadowsocks", n.Name)
					method, _ := in.Options["method"].(string)
					if method == "" {
						method = "2022-blake3-aes-128-gcm"
					}
					pwd, _ := in.Options["password"].(string)
					if pwd == "" {
						pwd = "d29ya3YxMjM0NTY3ODkwMQ=="
					}
					out := map[string]any{
						"type":        "shadowsocks",
						"tag":         tag,
						"server":      nodeAddr,
						"server_port": in.ListenPort,
						"method":      method,
						"password":    pwd,
					}
					outbounds = append(outbounds, out)
					outTags = append(outTags, tag)

				case "trojan":
					tag := fmt.Sprintf("%s-Trojan", n.Name)
					serverName, _ := in.Options["server_name"].(string)
					if serverName == "" {
						serverName = nodeAddr
					}
					out := map[string]any{
						"type":        "trojan",
						"tag":         tag,
						"server":      nodeAddr,
						"server_port": in.ListenPort,
						"password":    user.UUID,
						"tls": map[string]any{
							"enabled":     true,
							"server_name": serverName,
							"insecure":    true,
						},
					}
					outbounds = append(outbounds, out)
					outTags = append(outTags, tag)
				}
			}
		}
	}

	// 组装完整客户端配置
	allOutbounds := append(outbounds,
		map[string]any{
			"type": "direct",
			"tag":  "direct",
		},
		map[string]any{
			"type": "block",
			"tag":  "block",
		},
	)

	finalOutbound := "direct"
	if len(outTags) > 0 {
		finalOutbound = "select"
		selectorGroup := map[string]any{
			"type":      "selector",
			"tag":       "select",
			"outbounds": append([]string{"auto"}, outTags...),
			"default":   "auto",
		}
		urltestGroup := map[string]any{
			"type":      "urltest",
			"tag":       "auto",
			"outbounds": outTags,
			"url":       "https://www.gstatic.com/generate_204",
			"interval":  "3m",
			"tolerance": 50,
		}
		allOutbounds = append([]map[string]any{selectorGroup, urltestGroup}, allOutbounds...)
	}

	clientConfig := map[string]any{
		"inbounds": []map[string]any{
			{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": 2080,
			},
		},
		"outbounds": allOutbounds,
		"route": map[string]any{
			"auto_detect_interface": true,
			"rules": []map[string]any{
				{
					"geoip":    []string{"private"},
					"outbound": "direct",
				},
				{
					"geosite":  []string{"cn"},
					"geoip":    []string{"cn"},
					"outbound": "direct",
				},
			},
			"final": finalOutbound,
		},
	}

	c.Header("Content-Type", "application/json; charset=utf-8")
	c.JSON(http.StatusOK, clientConfig)
}

func formatBytes(b int64) string {
	if b <= 0 {
		return "0 B"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// renderUserPortal 渲染面向普通订阅客户的自适应自服务面板
func renderUserPortal(c *gin.Context, user *model.User, nodes []model.Node) {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := c.Request.Host
	if d := model.GetSetting("master_domain", ""); d != "" {
		scheme = "https"
		host = d
	}
	subBase := fmt.Sprintf("%s://%s/sub/%s", scheme, host, user.SubToken)

	usedStr := formatBytes(user.UsedTraffic)
	limitStr := "不限流量"
	percent := 0.0
	if user.TrafficLimit > 0 {
		limitStr = formatBytes(user.TrafficLimit)
		percent = (float64(user.UsedTraffic) / float64(user.TrafficLimit)) * 100
		if percent > 100 {
			percent = 100
		}
	}

	expireStr := "永久有效"
	if user.ExpireAt > 0 {
		expireStr = time.Unix(user.ExpireAt, 0).Format("2006-01-02")
	}

	statusBadge := `<span style="background:rgba(16,185,129,0.2);color:#34d399;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;">🟢 活跃正常</span>`
	if user.Status == "suspended" {
		statusBadge = `<span style="background:rgba(239,68,68,0.2);color:#f87171;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;">🔴 流量熔断</span>`
	} else if user.Status == "expired" {
		statusBadge = `<span style="background:rgba(245,158,11,0.2);color:#fbbf24;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;">🟡 账号已过期</span>`
	}

	clashURL := fmt.Sprintf("clash://install-config?url=%s&name=%s", url.QueryEscape(subBase+"?type=clash"), url.QueryEscape("Work-V-"+user.Username))
	singboxURL := fmt.Sprintf("sing-box://import-remote-profile?url=%s#%s", url.QueryEscape(subBase+"?type=sing-box"), url.QueryEscape("Work-V-"+user.Username))
	srURL := "sub://" + base64.URLEncoding.EncodeToString([]byte(subBase))

	// 组装各节点的单个独立直连协议链接与二维码
	var nodeCardsHTML strings.Builder
	totalSingleLinks := 0
	for _, n := range nodes {
		addr := resolveNodeAddress(&n, c)
		if addr == "" {
			continue
		}
		nodeCopy := n
		nodeCopy.Address = addr
		sLinks := service.GenerateNodeShareLinks(&nodeCopy, user.UUID, user.Username)
		for idx, sl := range sLinks {
			totalSingleLinks++
			qrID := fmt.Sprintf("qr-%d-%d", n.ID, idx)
			badgeColor := "#38bdf8"
			if strings.Contains(strings.ToLower(sl.Protocol), "hy") || strings.Contains(strings.ToLower(sl.Protocol), "tuic") {
				badgeColor = "#a855f7"
			}
			qrTarget := url.QueryEscape(sl.Link)
			safeLink := html.EscapeString(sl.Link)
			nodeCardsHTML.WriteString(fmt.Sprintf(`
      <div class="single-node-card" data-proto="%s" style="background:rgba(15,23,42,0.6);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:12px 14px;margin-bottom:10px;">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
          <div style="flex:1;min-width:180px;">
            <div style="display:flex;align-items:center;gap:6px;">
              <span style="font-size:13px;font-weight:700;color:#f8fafc;">%s</span>
              <span style="background:%s20;color:%s;padding:2px 6px;border-radius:6px;font-size:10px;font-weight:600;">%s</span>
            </div>
            <div style="font-size:11px;color:#64748b;margin-top:2px;">%s · 端口: %d (%s)</div>
          </div>
          <div style="display:flex;gap:6px;">
            <button onclick="copyText('%s')" style="background:rgba(56,189,248,0.15);color:#38bdf8;border:1px solid rgba(56,189,248,0.3);padding:6px 10px;border-radius:8px;font-size:11px;cursor:pointer;font-weight:600;">📋 复制单链接</button>
            <button onclick="toggleQR('%s')" style="background:rgba(168,85,247,0.15);color:#c084fc;border:1px solid rgba(168,85,247,0.3);padding:6px 10px;border-radius:8px;font-size:11px;cursor:pointer;font-weight:600;">📱 单节点码</button>
          </div>
        </div>
        <div id="%s" style="display:none;text-align:center;margin-top:12px;padding-top:12px;border-top:1px dashed rgba(255,255,255,0.08);">
          <img src="/api/v1/qrcode?text=%s" style="width:130px;height:130px;background:white;padding:6px;border-radius:8px;display:inline-block;" alt="Node QR">
          <div style="font-size:10px;color:#94a3b8;margin-top:4px;">客户端扫码直接接入该节点</div>
        </div>
      </div>`,
				strings.ToLower(sl.Protocol),
				html.EscapeString(sl.Name), badgeColor, badgeColor, strings.ToUpper(sl.Protocol),
				html.EscapeString(sl.Description), sl.Port, sl.PortType,
				safeLink, qrID, qrID, qrTarget,
			))
		}
	}

	nodesSectionHTML := ""
	if totalSingleLinks > 0 {
		nodesSectionHTML = fmt.Sprintf(`
    <div style="margin-top:24px;border-top:1px solid rgba(255,255,255,0.08);padding-top:20px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
        <span style="font-size:14px;font-weight:700;color:#f8fafc;">📡 独立节点直连 (%d 个接入点)</span>
        <span style="font-size:11px;color:#94a3b8;">可按协议筛选直连链接</span>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:12px;overflow-x:auto;padding-bottom:4px;">
        <button onclick="filterProto('all')" class="proto-tag active" id="btn-proto-all" style="background:#10b98120;color:#34d399;border:1px solid #10b98140;padding:4px 10px;border-radius:8px;font-size:11px;cursor:pointer;font-weight:600;">全部协议</button>
        <button onclick="filterProto('vless')" class="proto-tag" id="btn-proto-vless" style="background:rgba(255,255,255,0.05);color:#94a3b8;border:1px solid rgba(255,255,255,0.08);padding:4px 10px;border-radius:8px;font-size:11px;cursor:pointer;">Reality</button>
        <button onclick="filterProto('hy2')" class="proto-tag" id="btn-proto-hy2" style="background:rgba(255,255,255,0.05);color:#94a3b8;border:1px solid rgba(255,255,255,0.08);padding:4px 10px;border-radius:8px;font-size:11px;cursor:pointer;">Hysteria 2</button>
        <button onclick="filterProto('tuic')" class="proto-tag" id="btn-proto-tuic" style="background:rgba(255,255,255,0.05);color:#94a3b8;border:1px solid rgba(255,255,255,0.08);padding:4px 10px;border-radius:8px;font-size:11px;cursor:pointer;">TUIC</button>
        <button onclick="filterProto('ss')" class="proto-tag" id="btn-proto-ss" style="background:rgba(255,255,255,0.05);color:#94a3b8;border:1px solid rgba(255,255,255,0.08);padding:4px 10px;border-radius:8px;font-size:11px;cursor:pointer;">Shadowsocks</button>
      </div>
      <div id="nodes-container">%s</div>
    </div>`, totalSingleLinks, nodeCardsHTML.String())
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>我的订阅凭证 - Work-V</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: #090d16; color: #f1f5f9; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .card { background: rgba(30, 41, 59, 0.75); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 24px; max-width: 540px; width: 100%%; padding: 28px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; }
    .title { font-size: 20px; font-weight: 800; color: #fff; display: flex; align-items: center; gap: 8px; }
    .stat-box { background: rgba(15, 23, 42, 0.7); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 16px; padding: 18px; margin-bottom: 20px; }
    .progress-bar { width: 100%%; height: 8px; background: #334155; border-radius: 999px; overflow: hidden; margin: 12px 0 8px 0; }
    .progress-fill { height: 100%%; background: linear-gradient(90deg, #10b981, #06b6d4); border-radius: 999px; width: %.1f%%%%; transition: width 0.3s; }
    .btn-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 18px; }
    .btn { display: flex; align-items: center; justify-content: center; gap: 8px; padding: 12px 14px; border-radius: 14px; font-size: 13px; font-weight: 700; text-decoration: none; cursor: pointer; border: 1px solid transparent; transition: all 0.2s; }
    .btn-clash { background: rgba(6, 182, 212, 0.15); color: #22d3ee; border-color: rgba(6, 182, 212, 0.3); }
    .btn-clash:hover { background: rgba(6, 182, 212, 0.25); }
    .btn-singbox { background: rgba(168, 85, 247, 0.15); color: #c084fc; border-color: rgba(168, 85, 247, 0.3); }
    .btn-singbox:hover { background: rgba(168, 85, 247, 0.25); }
    .btn-sr { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border-color: rgba(245, 158, 11, 0.3); }
    .btn-sr:hover { background: rgba(245, 158, 11, 0.25); }
    .btn-copy { background: rgba(16, 185, 129, 0.15); color: #34d399; border-color: rgba(16, 185, 129, 0.3); }
    .btn-copy:hover { background: rgba(16, 185, 129, 0.25); }
    .sub-input { width: 100%%; background: #0f172a; border: 1px solid #334155; border-radius: 12px; padding: 10px 14px; font-family: monospace; font-size: 11px; color: #94a3b8; outline: none; margin-bottom: 14px; word-break: break-all; }
    .qr-box { text-align: center; margin-top: 14px; padding-top: 14px; border-top: 1px solid rgba(255, 255, 255, 0.08); }
    .qr-img { width: 180px; height: 180px; border-radius: 12px; background: white; padding: 8px; margin: 0 auto 8px auto; display: block; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="title">
        <span>⚡ Work-V 订阅中心</span>
      </div>
      <div>%s</div>
    </div>

    <div class="stat-box">
      <div style="display:flex;justify-content:space-between;font-size:13px;color:#94a3b8;">
        <span>用户: <strong style="color:#fff;">%s</strong></span>
        <span>有效期至: <strong style="color:#fff;">%s</strong></span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill"></div>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:12px;color:#94a3b8;">
        <span>已用流量: <strong style="color:#34d399;">%s</strong></span>
        <span>总配额: <strong style="color:#fff;">%s</strong> (%.1f%%%%)</span>
      </div>
    </div>

    <div class="btn-grid">
      <a href="%s" class="btn btn-clash">⚡ 导入 Clash / Verge</a>
      <a href="%s" class="btn btn-singbox">📦 导入 Sing-box</a>
      <a href="%s" class="btn btn-sr">🚀 导入 小火箭</a>
      <button onclick="copyText('%s')" class="btn btn-copy">📋 复制订阅地址</button>
    </div>

    <div style="display:flex;gap:10px;margin-bottom:14px;">
      <a href="%s?type=clash" download="clash.yaml" class="btn" style="flex:1;background:rgba(6,182,212,0.1);color:#22d3ee;border-color:rgba(6,182,212,0.25);font-size:12px;padding:10px;">📥 下载 Clash 配置</a>
      <a href="%s?type=sing-box" download="singbox.json" class="btn" style="flex:1;background:rgba(168,85,247,0.1);color:#c084fc;border-color:rgba(168,85,247,0.25);font-size:12px;padding:10px;">📥 下载 Sing-box 配置</a>
    </div>

    <input type="text" readonly value="%s" class="sub-input" onclick="this.select()">

    <div class="qr-box">
      <img src="/api/v1/qrcode?text=%s" class="qr-img" alt="Subscription QR Code">
      <p style="font-size:11px;color:#64748b;">支持手机客户端打开相机或小火箭直接扫码导入</p>
    </div>

    %s
  </div>

  <script>
    function copyText(t) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(t).then(function() {
          alert('已复制到剪贴板！');
        }).catch(function() {
          prompt('请长按复制链接:', t);
        });
      } else {
        prompt('请长按复制链接:', t);
      }
    }
    function toggleQR(id) {
      var el = document.getElementById(id);
      if (el) {
        el.style.display = (el.style.display === 'none' || el.style.display === '') ? 'block' : 'none';
      }
    }
    function filterProto(tag) {
      var tags = ['all', 'vless', 'hy2', 'tuic', 'ss'];
      tags.forEach(function(t) {
        var b = document.getElementById('btn-proto-' + t);
        if (b) {
          if (t === tag) {
            b.style.background = '#10b98120';
            b.style.color = '#34d399';
            b.style.borderColor = '#10b98140';
            b.style.fontWeight = '600';
          } else {
            b.style.background = 'rgba(255,255,255,0.05)';
            b.style.color = '#94a3b8';
            b.style.borderColor = 'rgba(255,255,255,0.08)';
            b.style.fontWeight = 'normal';
          }
        }
      });
      var cards = document.querySelectorAll('.single-node-card');
      cards.forEach(function(card) {
        var proto = (card.getAttribute('data-proto') || '').toLowerCase();
        if (tag === 'all') {
          card.style.display = 'block';
        } else if (tag === 'vless' && (proto.indexOf('vless') !== -1 || proto.indexOf('reality') !== -1)) {
          card.style.display = 'block';
        } else if (tag === 'hy2' && proto.indexOf('hy') !== -1) {
          card.style.display = 'block';
        } else if (tag === 'tuic' && proto.indexOf('tuic') !== -1) {
          card.style.display = 'block';
        } else if (tag === 'ss' && (proto.indexOf('shadowsocks') !== -1 || proto.indexOf('ss') !== -1)) {
          card.style.display = 'block';
        } else {
          card.style.display = 'none';
        }
      });
    }
  </script>
</body>
</html>`, percent, statusBadge, user.Username, expireStr, usedStr, limitStr, percent, clashURL, singboxURL, srURL, subBase, subBase, subBase, subBase, url.QueryEscape(subBase), nodesSectionHTML)

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}
