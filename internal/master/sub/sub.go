package sub

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"work-v/internal/common"
	"work-v/internal/master/model"

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
//
// 历史实现在这里是"空则生成新 x25519 密钥并 UPDATE 落库": 订阅是免鉴权的 GET,
// 并发请求会各自生成不同密钥互相覆盖, 先响应出去的订阅里的 pbk 永远对不上节点实际密钥,
// 该用户就再也握手不上了 (同时任何持令牌者都能反复覆盖节点密钥)。
// 现在入站在建节点时一次性生成 (含启动时的历史数据补齐), 订阅侧只读。
func resolveInbounds(n *model.Node) []common.InboundConfig {
	var inbounds []common.InboundConfig
	if err := json.Unmarshal([]byte(n.InboundsJSON), &inbounds); err != nil {
		return nil
	}
	return inbounds
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

	// 读取所有已配置且未删除的节点
	var nodes []model.Node
	model.DB.Find(&nodes)

	// 获取客户端类型
	ua := strings.ToLower(c.GetHeader("User-Agent"))
	subType := strings.ToLower(c.Query("type"))

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
			if !in.Enabled {
				continue
			}

			switch in.Type {
			case "vless":
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

			case "grpc-reality":
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

			case "hysteria2":
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

			case "tuic":
				link := fmt.Sprintf("tuic://%s:%s@%s:%d?congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#%s",
					user.UUID, user.UUID, nodeAddr, in.ListenPort, url.QueryEscape(fmt.Sprintf("%s-TUIC", n.Name)))
				links = append(links, link)

			case "anytls":
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = "gateway.icloud.com"
				}
				link := fmt.Sprintf("anytls://%s@%s:%d/?sni=%s&insecure=1#%s",
					user.UUID, nodeAddr, in.ListenPort, serverName, url.QueryEscape(fmt.Sprintf("%s-AnyTLS", n.Name)))
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
			if !in.Enabled {
				continue
			}

			switch in.Type {
			case "vless":
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
				proxyNames = append(proxyNames, name)

			case "grpc-reality":
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

			case "hysteria2":
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

			case "tuic":
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

			case "anytls":
				// 历史实现漏了这个分支: 服务端开了 AnyTLS(8445) 但 Clash 订阅里静默消失
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
		"proxies":             proxies,
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
			if !in.Enabled {
				continue
			}

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

			case "grpc-reality":
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
			}
		}
	}

	// 组装完整客户端配置
	clientConfig := map[string]any{
		"outbounds": append(outbounds, map[string]any{
			"type": "direct",
			"tag":  "direct",
		}),
	}

	c.Header("Content-Type", "application/json; charset=utf-8")
	c.JSON(http.StatusOK, clientConfig)
}
