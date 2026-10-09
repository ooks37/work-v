package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"work-v/internal/common"
	"work-v/internal/master/model"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // 节点反向长连通常跨域或直接以客户端模式接入
	},
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
}

// AgentConn 单个节点的活跃连接实例
type AgentConn struct {
	NodeID       uint
	NodeToken    string
	Conn         *websocket.Conn
	SendChan     chan *common.WSMessage
	LastSeen     time.Time
	lastDBUpdate time.Time
}

// Hub 全局节点调度连接池
type Hub struct {
	mu         sync.RWMutex
	agents     map[uint]*AgentConn // NodeID -> AgentConn
	tokenMap   map[string]uint     // NodeToken -> NodeID
	onTraffic  func(nodeID uint, users []common.UserDeltaTraffic)
	onNeedConf func(nodeID uint) (*common.NodeConfigPayload, error)
}

var GlobalHub = NewHub()

func NewHub() *Hub {
	return &Hub{
		agents:   make(map[uint]*AgentConn),
		tokenMap: make(map[string]uint),
	}
}

// SetCallbacks 注入流量处理与配置生成回调
func (h *Hub) SetCallbacks(
	trafficCb func(nodeID uint, users []common.UserDeltaTraffic),
	confCb func(nodeID uint) (*common.NodeConfigPayload, error),
) {
	h.onTraffic = trafficCb
	h.onNeedConf = confCb
}

// HandleWebSocket 处理节点 Agent 发起的反向 WS 升级
func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[Hub] WebSocket 升级失败: %v", err)
		return
	}

	// 开启握手流程：等待首个认证消息
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var authMsg common.WSMessage
	if err := conn.ReadJSON(&authMsg); err != nil {
		log.Printf("[Hub] 读取节点握手认证超时或失败: %v", err)
		conn.Close()
		return
	}

	if authMsg.Type != common.MsgTypeAuthReq || authMsg.NodeToken == "" {
		log.Printf("[Hub] 节点首包非有效认证: type=%s", authMsg.Type)
		conn.Close()
		return
	}

	// 数据库校验 Token
	var node model.Node
	if err := model.DB.Where("token = ?", authMsg.NodeToken).First(&node).Error; err != nil {
		log.Printf("[Hub] 节点 Token 验证未通过: %s", maskToken(authMsg.NodeToken))
		resp, _ := common.NewWSMessage(common.MsgTypeAuthResp, map[string]any{
			"success": false,
			"error":   "token 无效或节点不存在",
		})
		conn.WriteJSON(resp)
		conn.Close()
		return
	}

	// 认证成功
	conn.SetReadDeadline(time.Time{})
	resp, _ := common.NewWSMessage(common.MsgTypeAuthResp, map[string]any{
		"success": true,
		"node_id": node.ID,
		"message": "节点接入成功",
	})
	if err := conn.WriteJSON(resp); err != nil {
		conn.Close()
		return
	}

	// 注册到 Hub 连接池
	agent := &AgentConn{
		NodeID:    node.ID,
		NodeToken: node.Token,
		Conn:      conn,
		SendChan:  make(chan *common.WSMessage, 64),
		LastSeen:  time.Now(),
	}
	h.register(agent)

	// 更新节点状态为在线，并智能自动提取节点的公网 IP 回填
	now := time.Now()
	updates := map[string]any{
		"status":       "online",
		"last_seen_at": &now,
	}

	// 提取真实对端 IP (仅当来自本机反向代理时信任转发头，防止直连伪造)
	peerHost, _, _ := net.SplitHostPort(r.RemoteAddr)
	remoteIP := peerHost
	if (peerHost == "127.0.0.1" || peerHost == "::1") && r.Header.Get("X-Forwarded-For") != "" {
		xfwd := r.Header.Get("X-Forwarded-For")
		if idx := strings.Index(xfwd, ","); idx != -1 {
			xfwd = strings.TrimSpace(xfwd[:idx])
		}
		if xfwd != "" {
			remoteIP = xfwd
		}
	} else if (peerHost == "127.0.0.1" || peerHost == "::1") && r.Header.Get("X-Real-IP") != "" {
		remoteIP = r.Header.Get("X-Real-IP")
	}

	if remoteIP != "" && remoteIP != "127.0.0.1" && (node.Address == "" || node.Address == "127.0.0.1" || strings.Contains(node.Address, "自动探测")) {
		updates["address"] = remoteIP
		node.Address = remoteIP
	}

	model.DB.Model(&node).Updates(updates)

	log.Printf("[Hub] 节点已上线: ID=%d, Name=%s, Token=%s", node.ID, node.Name, maskToken(node.Token))

	// 立即下发一次最新配置
	go h.PushConfigToNode(node.ID)

	// 启动写协程与读协程
	go agent.writePump()
	agent.readPump(h)
}

func (h *Hub) register(agent *AgentConn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// 若存在旧连接，优雅关闭旧连接
	if old, exists := h.agents[agent.NodeID]; exists {
		close(old.SendChan)
		old.Conn.Close()
	}

	h.agents[agent.NodeID] = agent
	h.tokenMap[agent.NodeToken] = agent.NodeID
}

func (h *Hub) unregister(agent *AgentConn) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cur, exists := h.agents[agent.NodeID]; exists && cur == agent {
		delete(h.agents, agent.NodeID)
		delete(h.tokenMap, agent.NodeToken)
		close(agent.SendChan)

		// 标为离线
		model.DB.Model(&model.Node{}).Where("id = ?", agent.NodeID).Update("status", "offline")
		log.Printf("[Hub] 节点已下线: ID=%d", agent.NodeID)
	}
}

// PushConfigToNode 针对指定节点推送最新 Sing-box 配置。
//
// 出队必须始终在持有读锁的状态下完成: register()/unregister()/KickNode() 都在写锁内
// 关闭旧连接的 SendChan, 历史实现"先解锁再发送"会在"节点重连"与"配置下发"撞车时触发
// send on closed channel。该路径由 handler 派生的 goroutine 调用, gin.Recovery 兜不住,
// 会直接把主控进程打挂。
func (h *Hub) PushConfigToNode(nodeID uint) error {
	if h.onNeedConf == nil {
		return fmt.Errorf("未设置配置提供回调")
	}

	confPayload, err := h.onNeedConf(nodeID)
	if err != nil {
		return err
	}

	msg, err := common.NewWSMessage(common.MsgTypeConfigPush, confPayload)
	if err != nil {
		return err
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		h.mu.RLock()
		agent, ok := h.agents[nodeID]
		if !ok {
			h.mu.RUnlock()
			return fmt.Errorf("节点 %d 未在线", nodeID)
		}
		select {
		case agent.SendChan <- msg:
			h.mu.RUnlock()
			return nil
		default:
		}
		h.mu.RUnlock()

		if time.Now().After(deadline) {
			return fmt.Errorf("推送配置超时")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// KickNode 主动断开指定节点的长连 (删除节点、强制下线时使用)。
// 只在写锁内摘表并关闭, unregister 随后会因为表中已无该连接而跳过, 不会二次 close。
func (h *Hub) KickNode(nodeID uint) {
	h.mu.Lock()
	defer h.mu.Unlock()

	agent, ok := h.agents[nodeID]
	if !ok {
		return
	}
	delete(h.agents, nodeID)
	delete(h.tokenMap, agent.NodeToken)
	close(agent.SendChan)
	if agent.Conn != nil {
		_ = agent.Conn.Close()
	}
	log.Printf("[Hub] 已主动断开节点: ID=%d", nodeID)
}

// maskToken 日志脱敏, 避免节点凭证进入日志文件
func maskToken(token string) string {
	if len(token) <= 6 {
		return "***"
	}
	return token[:6] + "***"
}

// BroadcastCutoffUser 向所有在线节点广播熔断指定用户 (踢下线)
func (h *Hub) BroadcastCutoffUser(uuid string) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	msg, err := common.NewWSMessage(common.MsgTypeCutoffUser, map[string]string{"uuid": uuid})
	if err != nil {
		return
	}

	for _, agent := range h.agents {
		select {
		case agent.SendChan <- msg:
		default:
		}
	}
}

// IsNodeOnline 查询节点是否在线
func (h *Hub) IsNodeOnline(nodeID uint) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, exists := h.agents[nodeID]
	return exists
}

// readPump 节点心跳与流量数据监听
func (a *AgentConn) readPump(h *Hub) {
	defer func() {
		h.unregister(a)
		a.Conn.Close()
	}()

	a.Conn.SetReadLimit(1024 * 1024) // 1MB
	_ = a.Conn.SetReadDeadline(time.Now().Add(75 * time.Second))

	for {
		var msg common.WSMessage
		if err := a.Conn.ReadJSON(&msg); err != nil {
			break
		}

		_ = a.Conn.SetReadDeadline(time.Now().Add(75 * time.Second))
		a.LastSeen = time.Now()

		switch msg.Type {
		case common.MsgTypeHeartbeat:
			var stats common.NodeHardwareStats
			if err := json.Unmarshal(msg.Payload, &stats); err == nil {
				now := time.Now()
				// 节流写入：心跳虽高频上报，但数据库每 15 秒更新一次，大幅减少高并发 SQLite 写入锁冲突
				if now.Sub(a.lastDBUpdate) >= 15*time.Second {
					a.lastDBUpdate = now
					model.DB.Model(&model.Node{}).Where("id = ?", a.NodeID).Updates(map[string]any{
						"status":       "online",
						"last_seen_at": &now,
						"cpu_percent":  stats.CPUPercent,
						"mem_used":     stats.MemUsedBytes,
						"mem_total":    stats.MemTotalBytes,
						"net_rx_rate":  stats.NetRxRate,
						"net_tx_rate":  stats.NetTxRate,
						"uptime_sec":   stats.UptimeSec,
						"agent_ver":    stats.Version,
						"singbox_pid":  stats.SingboxPid,
					})
				}
			}

		case common.MsgTypeTraffic:
			var report common.TrafficReportPayload
			if err := json.Unmarshal(msg.Payload, &report); err == nil && h.onTraffic != nil {
				h.onTraffic(a.NodeID, report.Users)
			}

		case common.MsgTypeConfigAck:
			var ack common.ConfigAckPayload
			if err := json.Unmarshal(msg.Payload, &ack); err == nil {
				if ack.Success {
					log.Printf("[Hub] 节点 %d 已确认应用新配置 (hash=%s)", a.NodeID, ack.ConfigHash)
				} else {
					log.Printf("[Hub] 节点 %d 应用配置失败: %s", a.NodeID, ack.Error)
				}
			}
		}
	}
}

// writePump 异步下发通道
func (a *AgentConn) writePump() {
	ticker := time.NewTicker(20 * time.Second)
	defer func() {
		ticker.Stop()
		a.Conn.Close()
	}()

	for {
		select {
		case msg, ok := <-a.SendChan:
			if !ok {
				a.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			a.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := a.Conn.WriteJSON(msg); err != nil {
				return
			}
		case <-ticker.C:
			a.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := a.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
