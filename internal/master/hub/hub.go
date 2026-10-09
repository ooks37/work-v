package hub

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
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
	NodeID    uint
	NodeToken string
	Conn      *websocket.Conn
	SendChan  chan *common.WSMessage
	LastSeen  time.Time
}

// Hub 全局节点调度连接池
type Hub struct {
	mu         sync.RWMutex
	agents     map[uint]*AgentConn      // NodeID -> AgentConn
	tokenMap   map[string]uint          // NodeToken -> NodeID
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
		log.Printf("[Hub] 节点 Token 验证未通过: %s", authMsg.NodeToken)
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

	// 更新节点状态为在线
	now := time.Now()
	model.DB.Model(&node).Updates(map[string]any{
		"status":       "online",
		"last_seen_at": &now,
	})

	log.Printf("[Hub] 节点已上线: ID=%d, Name=%s, Token=%s", node.ID, node.Name, node.Token)

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

// PushConfigToNode 针对指定节点推送最新 Sing-box 配置
func (h *Hub) PushConfigToNode(nodeID uint) error {
	h.mu.RLock()
	agent, ok := h.agents[nodeID]
	h.mu.RUnlock()
	if !ok {
		return fmt.Errorf("节点 %d 未在线", nodeID)
	}

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

	select {
	case agent.SendChan <- msg:
		return nil
	case <-time.After(3 * time.Second):
		return fmt.Errorf("推送配置超时")
	}
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

		case common.MsgTypeTraffic:
			var report common.TrafficReportPayload
			if err := json.Unmarshal(msg.Payload, &report); err == nil && h.onTraffic != nil {
				h.onTraffic(a.NodeID, report.Users)
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
