package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"work-v/internal/common"
	"work-v/internal/master/hub"
	"work-v/internal/master/middleware"
	"work-v/internal/master/model"
	"work-v/internal/master/service"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// RandomToken 生成随机 Token 字符串
func RandomToken(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// LoginRequest 登录请求载荷
type LoginRequest struct {
	Username   string `json:"username" binding:"required"`
	Password   string `json:"password" binding:"required"`
	RememberMe bool   `json:"remember_me"`
}

// HandleLogin 管理员安全登录 (含防暴力破解)
func HandleLogin(c *gin.Context) {
	clientIP := c.ClientIP()

	// 1. 防暴力破解检查
	allowed, waitSec := middleware.GlobalLoginLimiter.CheckAllowed(clientIP)
	if !allowed {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error": fmt.Sprintf("尝试登录失败次数过多，已被临时锁定，请等待 %d 秒后重试", waitSec),
		})
		return
	}

	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请求参数不完整"})
		return
	}

	// 2. 数据库检索管理员
	var admin model.Admin
	if err := model.DB.Where("username = ?", req.Username).First(&admin).Error; err != nil {
		middleware.GlobalLoginLimiter.RecordFailure(clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 3. Bcrypt 密码比对
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.Password)); err != nil {
		middleware.GlobalLoginLimiter.RecordFailure(clientIP)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 登录成功，重置失败计数
	middleware.GlobalLoginLimiter.ResetSuccess(clientIP)

	// 更新登录信息
	now := time.Now()
	model.DB.Model(&admin).Updates(map[string]any{
		"last_login_at": &now,
		"last_login_ip": clientIP,
	})

	// 4. 签发 JWT (支持记住登录 30 天，否则 24 小时)
	expireDuration := 24 * time.Hour
	cookieMaxAge := 24 * 3600
	if req.RememberMe {
		expireDuration = 30 * 24 * time.Hour
		cookieMaxAge = 30 * 24 * 3600
	}

	token, err := middleware.GenerateToken(admin.ID, admin.Username, expireDuration)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "签发 Token 失败"})
		return
	}

	// 设置安全 Cookie (方便直接浏览器鉴权)
	c.SetCookie("workv_token", token, cookieMaxAge, "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"token": token,
		"admin": gin.H{
			"id":       admin.ID,
			"username": admin.Username,
		},
	})
}

// HandleChangePassword 修改管理员密码
func HandleChangePassword(c *gin.Context) {
	adminID := c.GetUint("admin_id")

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required,min=6"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "新密码长度至少需要 6 位"})
		return
	}

	var admin model.Admin
	if err := model.DB.First(&admin, adminID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "管理员不存在"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.OldPassword)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "原密码不正确"})
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}

	model.DB.Model(&admin).Update("password_hash", string(newHash))
	c.JSON(http.StatusOK, gin.H{"message": "密码修改成功"})
}

// HandleGetSafeEntrance 获取当前安全入口状态与完整 URL (含域名模式)
func HandleGetSafeEntrance(c *gin.Context) {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := c.Request.Host
	domain := model.GetSetting("master_domain", "")
	if domain != "" {
		scheme = "https"
		host = domain
	}
	enabled, safePath := middleware.GetSafePath()
	url := middleware.GetSafeEntranceURL(scheme, host)

	c.JSON(http.StatusOK, gin.H{
		"enabled":   enabled,
		"safe_path": safePath,
		"domain":    domain,
		"url":       url,
	})
}

// HandleSetSafeEntrance 修改安全入口路径与访问域名
func HandleSetSafeEntrance(c *gin.Context) {
	var req struct {
		SafePath string `json:"safe_path"`
		Domain   string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}

	if req.SafePath != "" {
		middleware.SetSafePath(req.SafePath)
		_, newPath := middleware.GetSafePath()
		model.DB.Save(&model.SystemSetting{
			Key:       "safe_path",
			Value:     newPath,
			UpdatedAt: time.Now(),
		})
	}

	if req.Domain != "" {
		cleanDomain := strings.TrimSpace(req.Domain)
		cleanDomain = strings.TrimPrefix(cleanDomain, "http://")
		cleanDomain = strings.TrimPrefix(cleanDomain, "https://")
		cleanDomain = strings.TrimRight(cleanDomain, "/")
		_ = model.SetSetting("master_domain", cleanDomain)
	}

	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := c.Request.Host
	domain := model.GetSetting("master_domain", "")
	if domain != "" {
		scheme = "https"
		host = domain
	}

	_, newPath := middleware.GetSafePath()
	url := middleware.GetSafeEntranceURL(scheme, host)

	c.JSON(http.StatusOK, gin.H{
		"message":   "安全入口与访问配置已更新",
		"safe_path": newPath,
		"domain":    domain,
		"url":       url,
	})
}

// HandleGetDashboard 获取仪表盘全局汇总
func HandleGetDashboard(c *gin.Context) {
	var totalNodes, onlineNodes int64
	var totalUsers, activeUsers int64
	var totalTraffic int64
	var totalRxRate, totalTxRate uint64

	model.DB.Model(&model.Node{}).Count(&totalNodes)
	model.DB.Model(&model.Node{}).Where("status = ?", "online").Count(&onlineNodes)

	model.DB.Model(&model.User{}).Count(&totalUsers)
	model.DB.Model(&model.User{}).Where("status = ?", "active").Count(&activeUsers)

	var nodes []model.Node
	model.DB.Find(&nodes)
	for _, n := range nodes {
		if n.Status == "online" {
			totalRxRate += n.NetRxRate
			totalTxRate += n.NetTxRate
		}
	}

	type TrafficSum struct {
		Total int64
	}
	var sum TrafficSum
	model.DB.Model(&model.User{}).Select("COALESCE(SUM(used_traffic), 0) as total").Scan(&sum)
	totalTraffic = sum.Total

	c.JSON(http.StatusOK, gin.H{
		"total_nodes":   totalNodes,
		"online_nodes":  onlineNodes,
		"total_users":   totalUsers,
		"active_users":  activeUsers,
		"total_traffic": totalTraffic,
		"total_rx_rate": totalRxRate,
		"total_tx_rate": totalTxRate,
	})
}

// HandleGetNodes 获取节点列表
func HandleGetNodes(c *gin.Context) {
	var nodes []model.Node
	model.DB.Order("id desc").Find(&nodes)

	// 动态检测长连在线状态
	for i := range nodes {
		if !hub.GlobalHub.IsNodeOnline(nodes[i].ID) && nodes[i].Status == "online" {
			// 若长连已断但数据库仍标 online，动态纠正
			if nodes[i].LastSeenAt == nil || time.Since(*nodes[i].LastSeenAt) > 15*time.Second {
				nodes[i].Status = "offline"
			}
		}
	}

	c.JSON(http.StatusOK, nodes)
}

// HandleCreateNode 创建节点 (支持免填地址，上线自动回填)
func HandleCreateNode(c *gin.Context) {
	var req struct {
		Name    string  `json:"name" binding:"required"`
		Address string  `json:"address"`
		Rate    float64 `json:"rate"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供有效的节点名称"})
		return
	}

	if req.Address == "" {
		req.Address = "自动探测"
	}

	if req.Rate <= 0 {
		req.Rate = 1.0
	}

	token := "node_" + RandomToken(16)
	node := model.Node{
		Name:    req.Name,
		Address: req.Address,
		Rate:    req.Rate,
		Token:   token,
		Status:  "offline",
	}

	if err := model.DB.Create(&node).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保存节点失败: " + err.Error()})
		return
	}

	// 自动生成初始入站
	service.GetOrCreateDefaultInbounds(&node)

	c.JSON(http.StatusOK, node)
}

// HandleUpdateNode 更新节点
func HandleUpdateNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var node model.Node
	if err := model.DB.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}

	var req struct {
		Name         string  `json:"name"`
		Address      string  `json:"address"`
		Rate         float64 `json:"rate"`
		InboundsJSON string  `json:"inbounds_json"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	if req.Name != "" {
		node.Name = req.Name
	}
	if req.Address != "" {
		node.Address = req.Address
	}
	if req.Rate > 0 {
		node.Rate = req.Rate
	}
	if req.InboundsJSON != "" {
		node.InboundsJSON = req.InboundsJSON
	}

	model.DB.Save(&node)

	// 配置更新，尝试即时下发
	go hub.GlobalHub.PushConfigToNode(node.ID)

	c.JSON(http.StatusOK, node)
}

// HandleDeleteNode 删除节点
func HandleDeleteNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	model.DB.Delete(&model.Node{}, id)
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// HandleSyncNode 强制同步节点配置
func HandleSyncNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	err := hub.GlobalHub.PushConfigToNode(uint(id))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "配置已推送到节点"})
}

// HandleGetUsers 获取用户列表
func HandleGetUsers(c *gin.Context) {
	var users []model.User
	model.DB.Order("id desc").Find(&users)
	c.JSON(http.StatusOK, users)
}

// HandleCreateUser 创建订阅用户
func HandleCreateUser(c *gin.Context) {
	var req struct {
		Username     string `json:"username" binding:"required"`
		TrafficLimitGB int64 `json:"traffic_limit_gb"` // GB
		ExpireDays   int64  `json:"expire_days"`      // 天数
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请提供有效用户名"})
		return
	}

	userUUID := uuid.New().String()
	subToken := RandomToken(16)

	var expireAt int64 = 0
	if req.ExpireDays > 0 {
		expireAt = time.Now().AddDate(0, 0, int(req.ExpireDays)).Unix()
	}

	user := model.User{
		Username:     req.Username,
		UUID:         userUUID,
		SubToken:     subToken,
		TrafficLimit: req.TrafficLimitGB * 1024 * 1024 * 1024,
		UsedTraffic:  0,
		ExpireAt:     expireAt,
		Status:       "active",
	}

	if err := model.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败: " + err.Error()})
		return
	}

	// 触发全网节点更新配置
	var nodes []model.Node
	model.DB.Find(&nodes)
	for _, n := range nodes {
		go hub.GlobalHub.PushConfigToNode(n.ID)
	}

	c.JSON(http.StatusOK, user)
}

// HandleUpdateUser 更新用户
func HandleUpdateUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user model.User
	if err := model.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	var req struct {
		Username       string `json:"username"`
		TrafficLimitGB *int64 `json:"traffic_limit_gb"`
		ResetTraffic   bool   `json:"reset_traffic"`
		ExpireAt       *int64 `json:"expire_at"`
		Status         string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	if req.Username != "" {
		user.Username = req.Username
	}
	if req.TrafficLimitGB != nil {
		user.TrafficLimit = *req.TrafficLimitGB * 1024 * 1024 * 1024
	}
	if req.ResetTraffic {
		user.UsedTraffic = 0
	}
	if req.ExpireAt != nil {
		user.ExpireAt = *req.ExpireAt
	}
	if req.Status != "" {
		user.Status = req.Status
		if req.Status != "active" {
			hub.GlobalHub.BroadcastCutoffUser(user.UUID)
		}
	}

	model.DB.Save(&user)

	// 广播更新
	var nodes []model.Node
	model.DB.Find(&nodes)
	for _, n := range nodes {
		go hub.GlobalHub.PushConfigToNode(n.ID)
	}

	c.JSON(http.StatusOK, user)
}

// HandleDeleteUser 删除用户
func HandleDeleteUser(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user model.User
	if err := model.DB.First(&user, id).Error; err == nil {
		hub.GlobalHub.BroadcastCutoffUser(user.UUID)
		model.DB.Delete(&user)
	}
	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// HandleGetNodeLinks 获取指定节点的客户端直连协议链接与配置 (支持全 5 大协议直显与二维码)
func HandleGetNodeLinks(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var node model.Node
	if err := model.DB.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}

	// 查找系统默认活跃用户或使用示范 UUID
	var user model.User
	userUUID := "11111111-2222-3333-4444-555555555555"
	username := "default_user"
	if err := model.DB.Where("status = ?", "active").First(&user).Error; err == nil {
		userUUID = user.UUID
		username = user.Username
	}

	links := service.GenerateNodeShareLinks(&node, userUUID, username)
	c.JSON(http.StatusOK, gin.H{
		"node_id":   node.ID,
		"node_name": node.Name,
		"address":   node.Address,
		"user":      username,
		"uuid":      userUUID,
		"links":     links,
	})
}

// HandleGetNodeInbounds 获取指定节点的入站协议配置
func HandleGetNodeInbounds(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var node model.Node
	if err := model.DB.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}
	inbounds := service.GetOrCreateDefaultInbounds(&node)
	c.JSON(http.StatusOK, inbounds)
}

// HandleUpdateNodeInbounds 保存并即时热推节点协议入站配置
func HandleUpdateNodeInbounds(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var node model.Node
	if err := model.DB.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}

	var inbounds []common.InboundConfig
	if err := c.ShouldBindJSON(&inbounds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "协议入站参数格式错误"})
		return
	}

	data, err := json.Marshal(inbounds)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "序列化失败"})
		return
	}

	node.InboundsJSON = string(data)
	model.DB.Model(&node).Update("inbounds_json", node.InboundsJSON)

	// 实时推送最新配置至节点
	go hub.GlobalHub.PushConfigToNode(node.ID)

	c.JSON(http.StatusOK, gin.H{"message": "协议配置已更新并推送到节点", "inbounds": inbounds})
}

// HandleRestartNodeSingbox 远程重启节点 Sing-box 进程
func HandleRestartNodeSingbox(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	err := hub.GlobalHub.RestartNodeSingbox(uint(id))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "重启失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "节点 Sing-box 进程已成功重启！"})
}

// HandleGetNodeLogs 远程实时提取节点 Sing-box 运行日志
func HandleGetNodeLogs(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	logs, err := hub.GlobalHub.RequestNodeLogs(uint(id))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "获取日志失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"logs": logs})
}

// HandlePingNode 主控端对目标节点发起 TCP 连通性与延迟探测
func HandlePingNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var node model.Node
	if err := model.DB.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}

	addr := strings.TrimSpace(node.Address)
	if addr == "" || addr == "自动探测" || addr == "127.0.0.1" {
		c.JSON(http.StatusOK, gin.H{"reachable": false, "latency_ms": 0, "message": "节点未上报有效公网 IP"})
		return
	}

	port := 2083
	var inbounds []common.InboundConfig
	if err := json.Unmarshal([]byte(node.InboundsJSON), &inbounds); err == nil {
		for _, in := range inbounds {
			if in.Enabled && in.ListenPort > 0 {
				port = in.ListenPort
				break
			}
		}
	}

	target := net.JoinHostPort(addr, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"reachable":  false,
			"latency_ms": latency,
			"target":     target,
			"message":    fmt.Sprintf("TCP 握手失败: %v", err),
		})
		return
	}
	_ = conn.Close()

	c.JSON(http.StatusOK, gin.H{
		"reachable":  true,
		"latency_ms": latency,
		"target":     target,
		"message":    "连接正常",
	})
}

// HandleBatchCreateUsers 批量创建用户
func HandleBatchCreateUsers(c *gin.Context) {
	var req struct {
		Prefix         string `json:"prefix"`
		Count          int    `json:"count"`
		TrafficLimitGB int64  `json:"traffic_limit_gb"`
		ExpireDays     int64  `json:"expire_days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	users, err := service.BatchCreateUsers(req.Prefix, req.Count, req.TrafficLimitGB, req.ExpireDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("已成功创建 %d 个用户", len(users)), "users": users})
}

// HandleBatchResetTraffic 全网用户流量清零
func HandleBatchResetTraffic(c *gin.Context) {
	if err := service.ResetAllUsersTraffic(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "全网用户流量已成功清零，状态已重置为正常"})
}

// HandleRegenerateUserCredentials 重置用户凭据与订阅 Token
func HandleRegenerateUserCredentials(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var user model.User
	if err := model.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	oldUUID := user.UUID
	user.UUID = uuid.New().String()
	user.SubToken = RandomToken(16)
	model.DB.Save(&user)

	// 熔断旧凭据
	hub.GlobalHub.BroadcastCutoffUser(oldUUID)

	// 推送新凭据
	var nodes []model.Node
	model.DB.Find(&nodes)
	for _, n := range nodes {
		go hub.GlobalHub.PushConfigToNode(n.ID)
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "用户凭据与订阅 Token 已重置",
		"uuid":      user.UUID,
		"sub_token": user.SubToken,
	})
}

// HandleBackupDB 下载 SQLite 数据库备份
func HandleBackupDB(c *gin.Context) {
	candidates := []string{
		"data/work-v.db",
		"work-v.db",
		"/opt/work-v-master/data/work-v.db",
	}
	var target string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			target = p
			break
		}
	}
	if target == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到数据库文件"})
		return
	}
	fileName := fmt.Sprintf("work-v-backup-%s.db", time.Now().Format("20060102-150405"))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	c.File(target)
}

// HandleGetSystemSettings 获取全局系统配置
func HandleGetSystemSettings(c *gin.Context) {
	domain := model.GetSetting("master_domain", "")
	enabled, safePath := middleware.GetSafePath()
	c.JSON(http.StatusOK, gin.H{
		"master_domain": domain,
		"safe_path":     safePath,
		"safe_enabled":  enabled,
	})
}

// HandleUpdateSystemSettings 保存全局系统配置
func HandleUpdateSystemSettings(c *gin.Context) {
	var req struct {
		MasterDomain string `json:"master_domain"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}
	clean := strings.TrimSpace(req.MasterDomain)
	clean = strings.TrimPrefix(clean, "http://")
	clean = strings.TrimPrefix(clean, "https://")
	clean = strings.TrimRight(clean, "/")
	_ = model.SetSetting("master_domain", clean)
	c.JSON(http.StatusOK, gin.H{"message": "全局配置已保存", "master_domain": clean})
}

var (
	sbVersionCache  string
	sbLatestCache   string
	sbCacheTime     time.Time
	sbCacheMu       sync.Mutex
)

// HandleGetSingboxVersion 获取本地与远端 sing-box 最新版本 (带 1 小时缓存防 GitHub 403 限流)
func HandleGetSingboxVersion(c *gin.Context) {
	curVer := "未安装"
	for _, p := range []string{"/usr/local/bin/sing-box", "sing-box"} {
		if out, err := exec.Command(p, "version").CombinedOutput(); err == nil {
			lines := strings.Split(string(out), "\n")
			if len(lines) > 0 {
				curVer = strings.TrimSpace(lines[0])
				break
			}
		}
	}

	sbCacheMu.Lock()
	defer sbCacheMu.Unlock()

	latestVer := "1.13.12"
	if time.Since(sbCacheTime) < time.Hour && sbLatestCache != "" {
		latestVer = sbLatestCache
	} else {
		client := &http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequest("GET", "https://api.github.com/repos/SagerNet/sing-box/releases/latest", nil)
		req.Header.Set("User-Agent", "Work-V-Master")
		if resp, err := client.Do(req); err == nil && resp.StatusCode == 200 {
			var res struct {
				TagName string `json:"tag_name"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&res); err == nil && res.TagName != "" {
				latestVer = strings.TrimPrefix(res.TagName, "v")
				sbLatestCache = latestVer
				sbCacheTime = time.Now()
			}
			resp.Body.Close()
		}
	}

	updateAvailable := false
	if curVer != "未安装" && latestVer != "" && !strings.Contains(curVer, latestVer) {
		updateAvailable = true
	}

	c.JSON(http.StatusOK, gin.H{
		"current_version":  curVer,
		"latest_version":   latestVer,
		"update_available": updateAvailable,
	})
}

// HandleUpgradeSingbox 在线一键升级 sing-box 官方内核 (多源智能兜底与自动备份)
func HandleUpgradeSingbox(c *gin.Context) {
	go func() {
		arch := runtime.GOARCH
		if arch != "amd64" && arch != "arm64" {
			arch = "amd64"
		}

		ver := "1.13.12"
		sbCacheMu.Lock()
		if sbLatestCache != "" {
			ver = sbLatestCache
		}
		sbCacheMu.Unlock()

		url := fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-linux-%s.tar.gz", ver, ver, arch)
		mirrorURL := fmt.Sprintf("https://ghfast.top/%s", url)

		tmpDir := fmt.Sprintf("/tmp/singbox-update-%d", time.Now().Unix())
		os.MkdirAll(tmpDir, 0755)
		defer os.RemoveAll(tmpDir)

		tarFile := filepath.Join(tmpDir, "sb.tar.gz")

		// 优先主源，失败镜像源
		dlCmd := exec.Command("curl", "-fsSL", "--connect-timeout", "10", "--retry", "2", "-o", tarFile, url)
		if err := dlCmd.Run(); err != nil {
			dlMirror := exec.Command("curl", "-fsSL", "--connect-timeout", "15", "--retry", "3", "-o", tarFile, mirrorURL)
			_ = dlMirror.Run()
		}

		// 解压并替换
		untarCmd := exec.Command("tar", "-xzf", tarFile, "-C", tmpDir)
		if err := untarCmd.Run(); err != nil {
			return
		}

		// 查找解压出的可执行文件
		var newBin string
		_ = filepath.Walk(tmpDir, func(p string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() && info.Name() == "sing-box" {
				newBin = p
				return filepath.SkipAll
			}
			return nil
		})
		if newBin == "" {
			return
		}

		// 严格校验版本输出合法性
		verOut, err := exec.Command(newBin, "version").CombinedOutput()
		if err != nil || !strings.Contains(string(verOut), "sing-box") {
			log.Printf("[Singbox Upgrade] 升级产物校验失败，终止覆盖: %v", err)
			return
		}

		// 备份旧版本
		targetBin := "/usr/local/bin/sing-box"
		if _, err := os.Stat(targetBin); err == nil {
			bak := fmt.Sprintf("%s.bak.%d", targetBin, time.Now().Unix())
			_ = exec.Command("cp", "-f", targetBin, bak).Run()
		}

		_ = exec.Command("cp", "-f", newBin, targetBin).Run()
		_ = exec.Command("chmod", "755", targetBin).Run()

		// 重启服务生效
		_ = exec.Command("systemctl", "restart", "work-v-master").Run()
		_ = exec.Command("systemctl", "restart", "work-v-agent").Run()
	}()

	c.JSON(http.StatusOK, gin.H{
		"message": "内核升级任务已在后台启动，下载校验通过后将自动热重载！",
	})
}

// ListeningPort 开放端口详情
type ListeningPort struct {
	Port    string `json:"port"`
	Proto   string `json:"proto"`
	Process string `json:"process"`
	Status  string `json:"status"`
}

// HandleGetOpenPorts 扫描当前机器所有正在监听的端口与网络服务
func HandleGetOpenPorts(c *gin.Context) {
	cmd := exec.Command("ss", "-lntup")
	out, err := cmd.CombinedOutput()
	ports := make([]ListeningPort, 0)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ports": ports})
		return
	}

	lines := strings.Split(string(out), "\n")
	seen := make(map[string]bool)
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToUpper(fields[0])
		local := fields[4]

		port := ""
		if idx := strings.LastIndex(local, ":"); idx != -1 {
			port = local[idx+1:]
		}
		if port == "" || port == "*" {
			continue
		}

		process := "系统服务"
		if len(fields) >= 7 {
			procPart := fields[6]
			if strings.Contains(procPart, `users:(("`) {
				start := strings.Index(procPart, `users:(("`) + 9
				end := strings.Index(procPart[start:], `"`)
				if end != -1 {
					process = procPart[start : start+end]
				}
			}
		}

		key := fmt.Sprintf("%s/%s", port, proto)
		if !seen[key] {
			seen[key] = true
			ports = append(ports, ListeningPort{
				Port:    port,
				Proto:   proto,
				Process: process,
				Status:  "LISTEN",
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ports": ports,
	})
}

// HandleGetDiagnostic 一键生成系统环境、资源、协议状态与网络诊断报告 (对标 iwantrun 核心排错工具)
func HandleGetDiagnostic(c *gin.Context) {
	osRel := "Linux"
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				osRel = strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
				break
			}
		}
	}

	kernel := "未知"
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		kernel = strings.TrimSpace(string(out))
	}

	curVer := "未检测到"
	for _, p := range []string{"/usr/local/bin/sing-box", "sing-box"} {
		if out, err := exec.Command(p, "version").CombinedOutput(); err == nil {
			lines := strings.Split(string(out), "\n")
			if len(lines) > 0 {
				curVer = strings.TrimSpace(lines[0])
				break
			}
		}
	}

	bbrStatus := "已开启"
	if out, err := exec.Command("sysctl", "net.ipv4.tcp_congestion_control").CombinedOutput(); err == nil {
		if !strings.Contains(string(out), "bbr") {
			bbrStatus = "未开启 (默认 " + strings.TrimSpace(string(out)) + ")"
		}
	}

	var totalNodes, onlineNodes int64
	model.DB.Model(&model.Node{}).Count(&totalNodes)
	model.DB.Model(&model.Node{}).Where("status = ?", "online").Count(&onlineNodes)

	var totalUsers int64
	model.DB.Model(&model.User{}).Count(&totalUsers)

	// 采集最近 30 行日志
	logCmd := exec.Command("journalctl", "-u", "work-v-master", "-n", "25", "--no-pager")
	logOut, _ := logCmd.CombinedOutput()
	recentLogs := string(logOut)
	if strings.TrimSpace(recentLogs) == "" {
		recentLogs = "暂无系统异常日志"
	}

	diagReport := fmt.Sprintf(`===== Work-V 分布式网络中枢系统综合诊断报告 =====
操作系统: %s
系统内核: %s
架构类型: %s
TCP BBR 加速: %s
Sing-box 内核: %s
主控服务状态: 🟢 运行中 (work-v-master)
受控节点总数: %d (在线: %d, 离线: %d)
系统用户总数: %d
诊断生成时间: %s

===== 最近运行事件日志 =====
%s
==================================================`,
		osRel, kernel, runtime.GOARCH, bbrStatus, curVer, totalNodes, onlineNodes, totalNodes-onlineNodes, totalUsers,
		time.Now().Format("2006-01-02 15:04:05"), recentLogs)

	c.JSON(http.StatusOK, gin.H{
		"os":          osRel,
		"kernel":      kernel,
		"arch":        runtime.GOARCH,
		"bbr":         bbrStatus,
		"singbox_ver": curVer,
		"report":      diagReport,
	})
}
