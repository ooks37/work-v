package sub

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strconv"
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
	case "vmess", "vmess-ws":
		return inType == "vmess-ws" || inType == "vmess"
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

// calcSubAuthCookie 计算订阅访问鉴权 Cookie 签名
func calcSubAuthCookie(user *model.User) string {
	raw := fmt.Sprintf("%s:%s:%s", user.SubToken, user.Password, user.UUID)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// checkSubscriptionAuth 校验订阅专属凭据
// 验证来源:
// 1. HTTP Basic Auth (p == user.Password || p == user.UUID)
// 2. URL 查询参数 (?pwd= 或 ?password=)
// 3. POST 表单参数 (password 或 pwd)
// 4. 浏览器 Cookie (workv_sub_auth)
func checkSubscriptionAuth(c *gin.Context, user *model.User) (isAuth bool, hasError bool) {
	// 登出参数: 仅在非 POST 表单提交时清除 Cookie 并返回未认证
	if c.Query("logout") == "1" && c.Request.Method != "POST" {
		c.SetCookie("workv_sub_auth", "", -1, "/", "", false, true)
		return false, false
	}

	validPasswords := make(map[string]bool)
	if strings.TrimSpace(user.Password) != "" {
		validPasswords[strings.TrimSpace(user.Password)] = true
	}
	if strings.TrimSpace(user.UUID) != "" {
		validPasswords[strings.TrimSpace(user.UUID)] = true
	}

	// 1. 检查 HTTP Basic Auth
	if u, p, ok := c.Request.BasicAuth(); ok {
		p = strings.TrimSpace(p)
		if validPasswords[p] && (u == "" || u == user.Username || u == user.SubToken || u == "work-v") {
			return true, false
		}
	}

	// 2. 检查 Query 参数 (?pwd= 或 ?password=)
	queryPwd := strings.TrimSpace(c.DefaultQuery("pwd", c.Query("password")))
	if queryPwd != "" {
		if validPasswords[queryPwd] {
			return true, false
		}
		return false, true
	}

	// 3. 检查 POST 表单参数
	formPwd := strings.TrimSpace(c.DefaultPostForm("password", c.PostForm("pwd")))
	if formPwd != "" {
		if validPasswords[formPwd] {
			return true, false
		}
		return false, true
	}

	// 4. 检查浏览器 Cookie
	expectedCookie := calcSubAuthCookie(user)
	if cookieVal, err := c.Cookie("workv_sub_auth"); err == nil && cookieVal != "" {
		if cookieVal == expectedCookie {
			return true, false
		}
	}

	return false, false
}

// HandleSubscription 处理多端自适应订阅主入口 (含严格账号凭据安全鉴权)
func HandleSubscription(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		token = c.Query("token")
	}

	var user model.User
	if token != "" {
		if err := model.DB.Where("sub_token = ?", token).First(&user).Error; err != nil {
			c.String(http.StatusNotFound, "Subscription not found")
			return
		}
	} else {
		// 支持通过 Basic Auth 用户名反查
		if u, _, ok := c.Request.BasicAuth(); ok && u != "" {
			if err := model.DB.Where("username = ? OR sub_token = ?", u, u).First(&user).Error; err != nil {
				c.Header("WWW-Authenticate", `Basic realm="Work-V Subscription"`)
				c.String(http.StatusUnauthorized, "Unauthorized: User not found")
				return
			}
		} else {
			c.Header("WWW-Authenticate", `Basic realm="Work-V Subscription"`)
			c.String(http.StatusUnauthorized, "Unauthorized: Subscription token or user credentials required")
			return
		}
	}

	// 获取客户端类型
	ua := strings.ToLower(c.GetHeader("User-Agent"))
	subType := strings.ToLower(c.Query("type"))
	accept := strings.ToLower(c.GetHeader("Accept"))

	// 浏览器直接访问展示用户自服务门户页面
	isBrowser := subType == "" && (strings.Contains(accept, "text/html") || strings.Contains(ua, "mozilla")) &&
		!strings.Contains(ua, "curl") && !strings.Contains(ua, "wget") && !strings.Contains(ua, "clash") &&
		!strings.Contains(ua, "sing-box") && !strings.Contains(ua, "shadowrocket") && !strings.Contains(ua, "v2ray") &&
		!strings.Contains(ua, "surge") && !strings.Contains(ua, "loon")

	// 账号凭据严格鉴权 (必须有账号凭据才可以订阅)
	isAuth, hasError := checkSubscriptionAuth(c, &user)
	if !isAuth {
		if isBrowser {
			renderLockPortal(c, &user, hasError)
			return
		}
		// 客户端请求拒绝裸奔，必须返回 401 并索要 Basic Auth
		c.Header("WWW-Authenticate", `Basic realm="Work-V Subscription"`)
		c.String(http.StatusUnauthorized, "401 Unauthorized: Subscription credentials required (HTTP Basic Auth or ?pwd=)\n")
		return
	}

	// 鉴权通过：若为网页请求，写入免登录 Cookie (30天有效)
	if isBrowser {
		c.SetCookie("workv_sub_auth", calcSubAuthCookie(&user), 86400*30, "/", "", false, true)
		if c.Request.Method == "POST" {
			c.Redirect(http.StatusSeeOther, fmt.Sprintf("/sub/%s", user.SubToken))
			return
		}
	}

	// 注入客户端标准流量信息头 (Clash / Shadowrocket 支持直显配额进度条)
	userinfo := fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d",
		user.UsedTraffic, user.TrafficLimit, user.ExpireAt)
	c.Header("Subscription-Userinfo", userinfo)
	c.Header("Profile-Update-Interval", "24")

	// 读取所有已配置且未删除的非隐藏节点 (过滤管理员设置的隐藏节点)
	var nodes []model.Node
	model.DB.Where("hidden = ?", false).Find(&nodes)

	if isBrowser {
		renderUserPortal(c, &user, nodes)
		return
	}

	now := time.Now().Unix()
	if user.Status != "active" || (user.ExpireAt > 0 && user.ExpireAt < now) || (user.TrafficLimit > 0 && user.UsedTraffic >= user.TrafficLimit) {
		c.String(http.StatusForbidden, "Subscription expired or quota exceeded")
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

			case in.Type == "vmess-ws" || in.Type == "vmess":
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}
				wsPath, _ := in.Options["path"].(string)
				if wsPath == "" {
					wsPath = "/vmess"
				}
				vmessMeta := map[string]string{
					"v":    "2",
					"ps":   fmt.Sprintf("%s-VMess-WS", n.Name),
					"add":  nodeAddr,
					"port": strconv.Itoa(in.ListenPort),
					"id":   user.UUID,
					"aid":  "0",
					"net":  "ws",
					"type": "none",
					"host": serverName,
					"path": wsPath,
					"tls":  "tls",
					"sni":  serverName,
				}
				metaJSON, _ := json.Marshal(vmessMeta)
				links = append(links, "vmess://"+base64.StdEncoding.EncodeToString(metaJSON))

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

			case in.Type == "vmess-ws" || in.Type == "vmess":
				name := uniqueName(usedNames, fmt.Sprintf("%s-VMess-WS", n.Name))
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}
				wsPath, _ := in.Options["path"].(string)
				if wsPath == "" {
					wsPath = "/vmess"
				}

				p := map[string]any{
					"name":             name,
					"type":             "vmess",
					"server":           nodeAddr,
					"port":             in.ListenPort,
					"uuid":             user.UUID,
					"alterId":          0,
					"cipher":           "auto",
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
				proxyNames = append(proxyNames, name)
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
	usedTags := map[string]int{"direct": 1, "block": 1, "select": 1, "auto": 1}
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
				tag := uniqueName(usedTags, fmt.Sprintf("%s-gRPC-Reality", n.Name))
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
				tag := uniqueName(usedTags, fmt.Sprintf("%s-VLESS-WS", n.Name))
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

			} else if in.Type == "vmess" || in.Type == "vmess-ws" {
				tag := uniqueName(usedTags, fmt.Sprintf("%s-VMess-WS", n.Name))
				serverName, _ := in.Options["server_name"].(string)
				if serverName == "" {
					serverName = nodeAddr
				}
				wsPath, _ := in.Options["path"].(string)
				if wsPath == "" {
					wsPath = "/vmess"
				}
				out := map[string]any{
					"type":        "vmess",
					"tag":         tag,
					"server":      nodeAddr,
					"server_port": in.ListenPort,
					"uuid":        user.UUID,
					"security":    "auto",
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
					tag := uniqueName(usedTags, fmt.Sprintf("%s-Reality", n.Name))
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
					tag := uniqueName(usedTags, fmt.Sprintf("%s-Hy2", n.Name))
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
					tag := uniqueName(usedTags, fmt.Sprintf("%s-TUIC", n.Name))
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
					tag := uniqueName(usedTags, fmt.Sprintf("%s-AnyTLS", n.Name))
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
					tag := uniqueName(usedTags, fmt.Sprintf("%s-Shadowsocks", n.Name))
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
					tag := uniqueName(usedTags, fmt.Sprintf("%s-Trojan", n.Name))
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

// renderLockPortal 渲染纯白苹果风格的订阅密码凭证解锁界面
func renderLockPortal(c *gin.Context, user *model.User, hasError bool) {
	errorAlertHTML := ""
	if hasError {
		errorAlertHTML = `
      <div style="background:#fff1f2;border:1px solid #fecdd3;color:#e11d48;padding:10px 14px;border-radius:14px;font-size:12px;font-weight:500;margin-bottom:18px;display:flex;align-items:center;justify-content:center;gap:6px;">
        <span>⚠️ 凭据密码不正确，请核对后重试</span>
      </div>`
	}

	safeUsername := html.EscapeString(user.Username)
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>订阅凭证解锁 - Work-V</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Helvetica Neue", "Segoe UI", Roboto, sans-serif; }
    body { background: #f5f5f7; color: #1d1d1f; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .card { background: #ffffff; border: 1px solid rgba(0, 0, 0, 0.08); border-radius: 24px; max-width: 420px; width: 100%%; padding: 36px 32px; box-shadow: 0 20px 40px rgba(0, 0, 0, 0.04); text-align: center; }
    .icon-box { width: 56px; height: 56px; border-radius: 18px; background: #f2f2f7; display: inline-flex; align-items: center; justify-content: center; font-size: 26px; margin-bottom: 16px; border: 1px solid rgba(0, 0, 0, 0.04); }
    .title { font-size: 20px; font-weight: 700; color: #1d1d1f; letter-spacing: -0.02em; margin-bottom: 6px; }
    .subtitle { font-size: 13px; color: #86868b; line-height: 1.5; margin-bottom: 24px; }
    .user-pill { display: inline-block; background: #f2f2f7; color: #1d1d1f; padding: 2px 8px; border-radius: 6px; font-weight: 600; font-family: monospace; }
    .input { width: 100%%; background: #f2f2f7; border: 1px solid rgba(0, 0, 0, 0.08); border-radius: 14px; padding: 12px 16px; font-size: 14px; color: #1d1d1f; outline: none; transition: all 0.2s; font-family: monospace; margin-bottom: 14px; text-align: center; letter-spacing: 2px; }
    .input:focus { border-color: #0071e3; background: #ffffff; box-shadow: 0 0 0 3px rgba(0, 113, 227, 0.15); }
    .btn { width: 100%%; background: #0071e3; color: #ffffff; border: none; border-radius: 14px; padding: 12px 16px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; box-shadow: 0 2px 8px rgba(0, 113, 227, 0.25); }
    .btn:hover { background: #0077ed; }
    .btn:active { transform: scale(0.98); }
    .footer { margin-top: 24px; font-size: 11px; color: #86868b; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon-box">🔐</div>
    <h2 class="title">订阅凭证安全解锁</h2>
    <p class="subtitle">账户 <span class="user-pill">%s</span> 已启用凭据保护<br>请输入专属订阅密码以解锁节点配置</p>

    %s

    <form method="POST" action="?">
      <input type="password" name="password" placeholder="请输入凭据密码..." required autofocus class="input">
      <button type="submit" class="btn">解锁订阅与节点</button>
    </form>

    <div class="footer">
      💡 此订阅受访问权限保护，未授权客户端将拒绝接入。<br>
      如遗忘凭据密码，请联系管理员在控制台查看或重置。
    </div>
  </div>
</body>
</html>`, safeUsername, errorAlertHTML)

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, htmlContent)
}

// renderUserPortal 渲染面向普通订阅客户的自适应自服务面板 (Apple Light 纯白风格)
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
	subWithPwd := subBase
	if user.Password != "" {
		subWithPwd = fmt.Sprintf("%s?pwd=%s", subBase, url.QueryEscape(user.Password))
	}

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

	now := time.Now().Unix()
	isExpired := user.ExpireAt > 0 && user.ExpireAt < now
	isOverQuota := user.TrafficLimit > 0 && user.UsedTraffic >= user.TrafficLimit
	isSuspended := user.Status != "active" || isExpired || isOverQuota

	statusBadge := `<span style="background:rgba(52,199,89,0.12);color:#34c759;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;">🟢 活跃正常</span>`
	var alertBanner string
	progressColor := "linear-gradient(90deg, #34c759, #30b0c7)"
	if user.Status == "suspended" || isOverQuota {
		statusBadge = `<span style="background:rgba(255,59,48,0.12);color:#ff3b30;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;">🔴 流量熔断</span>`
		alertBanner = `<div style="background:rgba(255,59,48,0.08);border:1px solid rgba(255,59,48,0.25);border-radius:14px;padding:12px 16px;margin-bottom:16px;color:#ff3b30;font-size:12px;line-height:1.5;"><strong>⚠️ 流量已熔断:</strong> 您的已用流量已超出配额上限，代理节点服务已暂停。如需恢复请联系管理员提升配额。</div>`
		progressColor = "#ff3b30"
	} else if user.Status == "expired" || isExpired {
		statusBadge = `<span style="background:rgba(255,149,0,0.12);color:#ff9500;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;">🟡 账号已过期</span>`
		alertBanner = `<div style="background:rgba(255,149,0,0.08);border:1px solid rgba(255,149,0,0.25);border-radius:14px;padding:12px 16px;margin-bottom:16px;color:#ff9500;font-size:12px;line-height:1.5;"><strong>⚠️ 账号已过期:</strong> 您的订阅有效期已届满，节点服务已停止。如需续期请联系管理员。</div>`
		progressColor = "#ff9500"
	} else if user.Status != "active" {
		statusBadge = `<span style="background:rgba(255,59,48,0.12);color:#ff3b30;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:600;">🔴 账号停用</span>`
		alertBanner = `<div style="background:rgba(255,59,48,0.08);border:1px solid rgba(255,59,48,0.25);border-radius:14px;padding:12px 16px;margin-bottom:16px;color:#ff3b30;font-size:12px;line-height:1.5;"><strong>⚠️ 账号已停用:</strong> 该账户当前已被管理员禁用，请联系管理员核实。</div>`
		progressColor = "#ff3b30"
	}

	clashTargetURL := subBase + "?type=clash"
	singboxTargetURL := subBase + "?type=sing-box"
	if user.Password != "" {
		clashTargetURL += "&pwd=" + url.QueryEscape(user.Password)
		singboxTargetURL += "&pwd=" + url.QueryEscape(user.Password)
	}

	clashURL := fmt.Sprintf("clash://install-config?url=%s&name=%s", url.QueryEscape(clashTargetURL), url.QueryEscape("Work-V-"+user.Username))
	singboxURL := fmt.Sprintf("sing-box://import-remote-profile?url=%s#%s", url.QueryEscape(singboxTargetURL), url.QueryEscape("Work-V-"+user.Username))
	srURL := "sub://" + base64.URLEncoding.EncodeToString([]byte(subWithPwd))

	// 组装各节点的单个独立直连协议链接与二维码 (Apple Light 质感)
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
			badgeColor := "#0071e3"
			if strings.Contains(strings.ToLower(sl.Protocol), "hy") || strings.Contains(strings.ToLower(sl.Protocol), "tuic") {
				badgeColor = "#af52de"
			} else if strings.Contains(strings.ToLower(sl.Protocol), "ss") {
				badgeColor = "#ff9500"
			}
			qrTarget := url.QueryEscape(sl.Link)
			safeLink := html.EscapeString(sl.Link)
			nodeCardsHTML.WriteString(fmt.Sprintf(`
      <div class="single-node-card" data-proto="%s" style="background:#ffffff;border:1px solid rgba(0,0,0,0.06);border-radius:16px;padding:14px 16px;margin-bottom:10px;box-shadow:0 1px 3px rgba(0,0,0,0.02);">
        <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
          <div style="flex:1;min-width:180px;">
            <div style="display:flex;align-items:center;gap:6px;">
              <span style="font-size:13px;font-weight:600;color:#1d1d1f;">%s</span>
              <span style="background:%s15;color:%s;padding:2px 8px;border-radius:6px;font-size:10px;font-weight:600;">%s</span>
            </div>
            <div style="font-size:11px;color:#86868b;margin-top:2px;">%s · 端口: %d (%s)</div>
          </div>
          <div style="display:flex;gap:6px;">
            <button onclick="copyText('%s')" style="background:rgba(0,113,227,0.08);color:#0071e3;border:1px solid rgba(0,113,227,0.2);padding:6px 12px;border-radius:999px;font-size:11px;cursor:pointer;font-weight:600;">📋 复制单链接</button>
            <button onclick="toggleQR('%s')" style="background:rgba(175,82,222,0.08);color:#af52de;border:1px solid rgba(175,82,222,0.2);padding:6px 12px;border-radius:999px;font-size:11px;cursor:pointer;font-weight:600;">📱 单节点码</button>
          </div>
        </div>
        <div id="%s" style="display:none;text-align:center;margin-top:12px;padding-top:12px;border-top:1px dashed rgba(0,0,0,0.08);">
          <img src="/api/v1/qrcode?text=%s" style="width:130px;height:130px;background:white;padding:6px;border-radius:10px;border:1px solid rgba(0,0,0,0.08);display:inline-block;" alt="Node QR">
          <div style="font-size:10px;color:#86868b;margin-top:4px;">客户端扫码直接接入该节点</div>
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
	if isSuspended {
		nodesSectionHTML = `<div style="margin-top:24px;border-top:1px solid rgba(0,0,0,0.06);padding-top:20px;text-align:center;color:#ff3b30;font-size:12px;font-weight:600;">🚫 账号当前已熔断或过期，节点连接已下线</div>`
	} else if totalSingleLinks > 0 {
		nodesSectionHTML = fmt.Sprintf(`
    <div style="margin-top:24px;border-top:1px solid rgba(0,0,0,0.06);padding-top:20px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
        <span style="font-size:14px;font-weight:700;color:#1d1d1f;">📡 独立节点直连 (%d 个接入点)</span>
        <span style="font-size:11px;color:#86868b;">可按协议筛选直连链接</span>
      </div>
      <div style="display:flex;gap:6px;margin-bottom:12px;overflow-x:auto;padding-bottom:4px;">
        <button onclick="filterProto('all')" class="proto-tag active" id="btn-proto-all" style="background:#0071e315;color:#0071e3;border:1px solid #0071e330;padding:4px 12px;border-radius:999px;font-size:11px;cursor:pointer;font-weight:600;">全部协议</button>
        <button onclick="filterProto('vless')" class="proto-tag" id="btn-proto-vless" style="background:#f2f2f7;color:#86868b;border:1px solid rgba(0,0,0,0.06);padding:4px 12px;border-radius:999px;font-size:11px;cursor:pointer;">Reality</button>
        <button onclick="filterProto('hy2')" class="proto-tag" id="btn-proto-hy2" style="background:#f2f2f7;color:#86868b;border:1px solid rgba(0,0,0,0.06);padding:4px 12px;border-radius:999px;font-size:11px;cursor:pointer;">Hysteria 2</button>
        <button onclick="filterProto('tuic')" class="proto-tag" id="btn-proto-tuic" style="background:#f2f2f7;color:#86868b;border:1px solid rgba(0,0,0,0.06);padding:4px 12px;border-radius:999px;font-size:11px;cursor:pointer;">TUIC</button>
        <button onclick="filterProto('ss')" class="proto-tag" id="btn-proto-ss" style="background:#f2f2f7;color:#86868b;border:1px solid rgba(0,0,0,0.06);padding:4px 12px;border-radius:999px;font-size:11px;cursor:pointer;">Shadowsocks</button>
      </div>
      <div id="nodes-container">%s</div>
    </div>`, totalSingleLinks, nodeCardsHTML.String())
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>我的订阅凭证 - Work-V</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display", "Helvetica Neue", "Segoe UI", Roboto, sans-serif; }
    body { background: #f5f5f7; color: #1d1d1f; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .card { background: #ffffff; border: 1px solid rgba(0, 0, 0, 0.08); border-radius: 28px; max-width: 540px; width: 100%%; padding: 30px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.04); }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .title { font-size: 20px; font-weight: 700; color: #1d1d1f; display: flex; align-items: center; gap: 8px; letter-spacing: -0.02em; }
    .stat-box { background: #f2f2f7; border: 1px solid rgba(0, 0, 0, 0.04); border-radius: 18px; padding: 18px; margin-bottom: 18px; }
    .progress-bar { width: 100%%; height: 8px; background: #e5e5ea; border-radius: 999px; overflow: hidden; margin: 12px 0 8px 0; }
    .progress-fill { height: 100%%; border-radius: 999px; transition: width 0.3s; }
    .btn-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 14px; }
    .btn { display: flex; align-items: center; justify-content: center; gap: 6px; padding: 12px 14px; border-radius: 14px; font-size: 13px; font-weight: 600; text-decoration: none; cursor: pointer; border: 1px solid transparent; transition: all 0.2s; }
    .btn-clash { background: rgba(0, 113, 227, 0.08); color: #0071e3; border-color: rgba(0, 113, 227, 0.2); }
    .btn-clash:hover { background: rgba(0, 113, 227, 0.15); }
    .btn-singbox { background: rgba(175, 82, 222, 0.08); color: #af52de; border-color: rgba(175, 82, 222, 0.2); }
    .btn-singbox:hover { background: rgba(175, 82, 222, 0.15); }
    .btn-sr { background: rgba(255, 149, 0, 0.08); color: #ff9500; border-color: rgba(255, 149, 0, 0.2); }
    .btn-sr:hover { background: rgba(255, 149, 0, 0.15); }
    .btn-copy { background: rgba(52, 199, 89, 0.08); color: #34c759; border-color: rgba(52, 199, 89, 0.2); }
    .btn-copy:hover { background: rgba(52, 199, 89, 0.15); }
    .sub-input { width: 100%%; background: #f2f2f7; border: 1px solid rgba(0, 0, 0, 0.08); border-radius: 12px; padding: 10px 14px; font-family: monospace; font-size: 11px; color: #1d1d1f; outline: none; margin-bottom: 14px; word-break: break-all; }
    .qr-box { text-align: center; margin-top: 14px; padding-top: 14px; border-top: 1px solid rgba(0, 0, 0, 0.06); }
    .qr-img { width: 160px; height: 160px; border-radius: 12px; background: white; padding: 8px; margin: 0 auto 8px auto; display: block; border: 1px solid rgba(0, 0, 0, 0.08); }
    .lock-btn { background: #f2f2f7; color: #86868b; border: 1px solid rgba(0, 0, 0, 0.06); padding: 5px 12px; border-radius: 999px; font-size: 11px; text-decoration: none; font-weight: 500; transition: all 0.2s; }
    .lock-btn:hover { background: #e5e5ea; color: #1d1d1f; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="title">
        <span>⚡ Work-V 订阅中心</span>
      </div>
      <div style="display:flex;align-items:center;gap:8px;">
        %s
        <a href="?logout=1" class="lock-btn">🔒 锁定</a>
      </div>
    </div>

    %s

    <div class="stat-box">
      <div style="display:flex;justify-content:space-between;font-size:13px;color:#86868b;">
        <span>用户: <strong style="color:#1d1d1f;">%s</strong></span>
        <span>有效期至: <strong style="color:#1d1d1f;">%s</strong></span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill" style="background:%s;width:%.1f%%%%;"></div>
      </div>
      <div style="display:flex;justify-content:space-between;font-size:12px;color:#86868b;">
        <span>已用流量: <strong style="color:#34c759;">%s</strong></span>
        <span>总配额: <strong style="color:#1d1d1f;">%s</strong> (%.1f%%%%)</span>
      </div>
      <div style="margin-top:12px;padding-top:12px;border-top:1px solid rgba(0,0,0,0.06);display:flex;justify-content:space-between;align-items:center;">
        <span style="font-size:12px;color:#86868b;">🔑 账号专属凭证密码: <strong style="color:#0071e3;font-family:monospace;font-size:13px;">%s</strong></span>
        <button onclick="copyText('%s')" style="background:#ffffff;border:1px solid rgba(0,0,0,0.1);padding:3px 10px;border-radius:999px;font-size:11px;color:#1d1d1f;cursor:pointer;font-weight:500;">复制密码</button>
      </div>
    </div>

    <div class="btn-grid">
      <a href="%s" class="btn btn-clash">⚡ 导入 Clash / Verge</a>
      <a href="%s" class="btn btn-singbox">📦 导入 Sing-box</a>
      <a href="%s" class="btn btn-sr">🚀 导入 小火箭</a>
      <button onclick="copyText('%s')" class="btn btn-copy">📋 复制订阅地址</button>
    </div>

    <div style="display:flex;gap:10px;margin-bottom:14px;">
      <a href="%s" download="clash.yaml" class="btn" style="flex:1;background:#f2f2f7;color:#1d1d1f;border-color:rgba(0,0,0,0.06);font-size:12px;padding:10px;">📥 下载 Clash 配置</a>
      <a href="%s" download="singbox.json" class="btn" style="flex:1;background:#f2f2f7;color:#1d1d1f;border-color:rgba(0,0,0,0.06);font-size:12px;padding:10px;">📥 下载 Sing-box 配置</a>
    </div>

    <input type="text" readonly value="%s" class="sub-input" onclick="this.select()">

    <div class="qr-box">
      <img src="/api/v1/qrcode?text=%s" class="qr-img" alt="Subscription QR Code">
      <p style="font-size:11px;color:#86868b;">手机客户端打开相机或小火箭直接扫码一键导入</p>
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
            b.style.background = '#0071e315';
            b.style.color = '#0071e3';
            b.style.borderColor = '#0071e330';
            b.style.fontWeight = '600';
          } else {
            b.style.background = '#f2f2f7';
            b.style.color = '#86868b';
            b.style.borderColor = 'rgba(0,0,0,0.06)';
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
</html>`, statusBadge, alertBanner, user.Username, expireStr, progressColor, percent, usedStr, limitStr, percent, user.Password, user.Password, clashURL, singboxURL, srURL, subWithPwd, clashTargetURL, singboxTargetURL, subWithPwd, url.QueryEscape(subWithPwd), nodesSectionHTML)

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, htmlContent)
}
