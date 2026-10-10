package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"work-v/internal/common"
	"work-v/internal/master/model"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// resolveNodeAddress 智能解析客户端可连接的节点地址 (优先节点显式配置，回退主控域名或当前 Host)
func resolveNodeAddress(n *model.Node, c *gin.Context) string {
	addr := strings.TrimSpace(n.Address)
	if addr != "" && addr != "自动探测" && addr != "127.0.0.1" {
		return addr
	}
	if d := model.GetSetting("master_domain", ""); d != "" {
		return d
	}
	host := c.Request.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
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

	for _, n := range nodes {
		nodeAddr := resolveNodeAddress(&n, c)
		if nodeAddr == "" {
			continue
		}
		var inbounds []common.InboundConfig
		if err := json.Unmarshal([]byte(n.InboundsJSON), &inbounds); err != nil {
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
				params.Set("pbk", pubKey)
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
				params.Set("pbk", pubKey)
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

			case "shadowsocks":
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

			case "vless-ws":
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

			case "trojan":
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

	for _, n := range nodes {
		nodeAddr := resolveNodeAddress(&n, c)
		if nodeAddr == "" {
			continue
		}
		var inbounds []common.InboundConfig
		if err := json.Unmarshal([]byte(n.InboundsJSON), &inbounds); err != nil {
			continue
		}

		for _, in := range inbounds {
			if !in.Enabled {
				continue
			}

			switch in.Type {
			case "vless":
				name := fmt.Sprintf("%s-Reality", n.Name)
				pubKey, _ := in.Options["public_key"].(string)
				shortID, _ := in.Options["short_id"].(string)
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = "gateway.icloud.com"
				}

				p := map[string]any{
					"name":                name,
					"type":                "vless",
					"server":              nodeAddr,
					"port":                in.ListenPort,
					"uuid":                user.UUID,
					"network":             "tcp",
					"tls":                 true,
					"udp":                 true,
					"flow":                "xtls-rprx-vision",
					"servername":          serverName,
					"reality-opts": map[string]any{
						"public-key": pubKey,
						"short-id":   shortID,
					},
					"client-fingerprint": "chrome",
				}
				proxies = append(proxies, p)
				proxyNames = append(proxyNames, name)

			case "grpc-reality":
				name := fmt.Sprintf("%s-gRPC-Reality", n.Name)
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
					"name":                name,
					"type":                "vless",
					"server":              nodeAddr,
					"port":                in.ListenPort,
					"uuid":                user.UUID,
					"network":             "grpc",
					"tls":                 true,
					"udp":                 true,
					"servername":          serverName,
					"reality-opts": map[string]any{
						"public-key": pubKey,
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
				name := fmt.Sprintf("%s-Hy2", n.Name)
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
				name := fmt.Sprintf("%s-TUIC", n.Name)
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

			case "shadowsocks":
				name := fmt.Sprintf("%s-Shadowsocks", n.Name)
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

			case "vless-ws":
				name := fmt.Sprintf("%s-VLESS-WS", n.Name)
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

			case "trojan":
				name := fmt.Sprintf("%s-Trojan", n.Name)
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

	for _, n := range nodes {
		nodeAddr := resolveNodeAddress(&n, c)
		if nodeAddr == "" {
			continue
		}
		var inbounds []common.InboundConfig
		if err := json.Unmarshal([]byte(n.InboundsJSON), &inbounds); err != nil {
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
							"public_key": pubKey,
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
							"public_key": pubKey,
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
					"type":        "tuic",
					"tag":         tag,
					"server":      nodeAddr,
					"server_port": in.ListenPort,
					"uuid":        user.UUID,
					"password":    user.UUID,
					"congestion_control": "bbr",
					"tls": map[string]any{
						"enabled":     true,
						"alpn":        []string{"h3"},
						"insecure":    true,
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

			case "vless-ws":
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

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>我的订阅凭证 - Work-V</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: #090d16; color: #f1f5f9; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .card { background: rgba(30, 41, 59, 0.75); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 24px; max-width: 520px; width: 100%%; padding: 28px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }
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
      <button onclick="navigator.clipboard.writeText('%s').then(()=>alert('订阅链接已复制到剪贴板！'))" class="btn btn-copy">📋 复制订阅地址</button>
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
  </div>
</body>
</html>`, percent, statusBadge, user.Username, expireStr, usedStr, limitStr, percent, clashURL, singboxURL, srURL, subBase, subBase, subBase, subBase, url.QueryEscape(subBase))

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}
