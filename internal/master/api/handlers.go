package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

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
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
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

	// 4. 签发 JWT (有效期 7 天)
	token, err := middleware.GenerateToken(admin.ID, admin.Username, 7*24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "签发 Token 失败"})
		return
	}

	// 设置安全 Cookie (方便直接浏览器鉴权)
	c.SetCookie("workv_token", token, 7*24*3600, "/", "", false, true)

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

// HandleGetSafeEntrance 获取当前安全入口状态与完整 URL
func HandleGetSafeEntrance(c *gin.Context) {
	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	enabled, safePath := middleware.GetSafePath()
	url := middleware.GetSafeEntranceURL(scheme, c.Request.Host)

	c.JSON(http.StatusOK, gin.H{
		"enabled":   enabled,
		"safe_path": safePath,
		"url":       url,
	})
}

// HandleSetSafeEntrance 修改安全入口路径
func HandleSetSafeEntrance(c *gin.Context) {
	var req struct {
		SafePath string `json:"safe_path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}

	middleware.SetSafePath(req.SafePath)

	// 持久化存储至数据库
	_, newPath := middleware.GetSafePath()
	model.DB.Save(&model.SystemSetting{
		Key:       "safe_path",
		Value:     newPath,
		UpdatedAt: time.Now(),
	})

	scheme := "http"
	if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	url := middleware.GetSafeEntranceURL(scheme, c.Request.Host)

	c.JSON(http.StatusOK, gin.H{
		"message":   "安全路径已更新",
		"safe_path": newPath,
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

// HandleCreateNode 创建节点
func HandleCreateNode(c *gin.Context) {
	var req struct {
		Name    string  `json:"name" binding:"required"`
		Address string  `json:"address" binding:"required"`
		Rate    float64 `json:"rate"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误，请提供节点名称与地址"})
		return
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
