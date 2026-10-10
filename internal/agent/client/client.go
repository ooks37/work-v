package client

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"sync"
	"time"

	"work-v/internal/agent/collector"
	"work-v/internal/agent/runner"
	"work-v/internal/common"

	"github.com/gorilla/websocket"
)

type AgentClient struct {
	serverURL string
	token     string
	runner    *runner.SingboxRunner
	collector *collector.SystemCollector

	// gorilla/websocket 不允许并发写, 心跳与配置回执必须串行化
	writeMu sync.Mutex
}

func NewAgentClient(serverURL, token string, r *runner.SingboxRunner) *AgentClient {
	return &AgentClient{
		serverURL: serverURL,
		token:     token,
		runner:    r,
		collector: collector.NewSystemCollector(),
	}
}

// writeJSON 串行化对同一连接的写操作 (gorilla/websocket 不允许并发写)
func (c *AgentClient) writeJSON(conn *websocket.Conn, v any) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return conn.WriteJSON(v)
}

// Start 启动反向长连并保持自动重连
func (c *AgentClient) Start() {
	for {
		log.Printf("[Agent] 正在连接主控: %s ...", c.serverURL)
		err := c.connectAndLoop()
		if err != nil {
			log.Printf("[Agent] 连接断开或失败: %v, 将在 5 秒后重试...", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func (c *AgentClient) connectAndLoop() error {
	u, err := url.Parse(c.serverURL)
	if err != nil {
		return err
	}

	wsScheme := "ws"
	if u.Scheme == "https" {
		wsScheme = "wss"
	}

	wsURL := url.URL{
		Scheme: wsScheme,
		Host:   u.Host,
		Path:   "/ws/agent",
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	// 1. 发送握手认证包
	authMsg, _ := common.NewWSMessage(common.MsgTypeAuthReq, nil)
	authMsg.NodeToken = c.token
	if err := c.writeJSON(conn, authMsg); err != nil {
		return err
	}

	// 2. 接收认证响应
	var resp common.WSMessage
	if err := conn.ReadJSON(&resp); err != nil {
		return err
	}

	var authResult struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(resp.Payload, &authResult)
	if !authResult.Success {
		// 历史上这里返回 nil, 于是 token 配错时会每 5 秒无限重连且完全没有日志
		return fmt.Errorf("认证被主控拒绝: %s (请核对 --token 是否与主控节点列表一致)", authResult.Error)
	}

	log.Println("[Agent] 节点认证成功！长连已建立")

	// 3. 开启心跳协程
	done := make(chan struct{})
	defer close(done)

	go c.heartbeatLoop(conn, done)

	// 4. 主监听循环
	for {
		var msg common.WSMessage
		if err := conn.ReadJSON(&msg); err != nil {
			return err
		}

		switch msg.Type {
		case common.MsgTypeConfigPush:
			var config common.NodeConfigPayload
			if err := json.Unmarshal(msg.Payload, &config); err == nil {
				log.Printf("[Agent] 收到主控新配置推送 (Hash: %s)，正在应用...", config.ConfigHash)
				applyErr := c.runner.ApplyConfig(&config)
				if applyErr != nil {
					log.Printf("[Agent] 应用配置失败: %v", applyErr)
				} else {
					log.Println("[Agent] 新配置已成功加载并在 Sing-box 生效！")
				}

				// 回执主控, 让下发结果(成功/失败原因)能在主控日志里看到
				ack := common.ConfigAckPayload{ConfigHash: config.ConfigHash, Success: applyErr == nil}
				if applyErr != nil {
					ack.Error = applyErr.Error()
				}
				if ackMsg, err := common.NewWSMessage(common.MsgTypeConfigAck, ack); err == nil {
					_ = c.writeJSON(conn, ackMsg)
				}
			}

		case common.MsgTypeCutoffUser:
			var req struct {
				UUID string `json:"uuid"`
			}
			if err := json.Unmarshal(msg.Payload, &req); err == nil && req.UUID != "" {
				c.runner.CutoffUser(req.UUID)
			}

		case common.MsgTypeGetLogsReq:
			logs := c.runner.GetRecentLogs()
			respMsg, _ := common.NewWSMessage(common.MsgTypeGetLogsResp, map[string]any{"logs": logs})
			_ = c.writeJSON(conn, respMsg)

		case common.MsgTypeRestartReq:
			err := c.runner.Restart()
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			respMsg, _ := common.NewWSMessage(common.MsgTypeRestartResp, map[string]any{
				"success": err == nil,
				"error":   errMsg,
			})
			_ = c.writeJSON(conn, respMsg)

		case common.MsgTypeCommand:
			var cmdReq struct {
				Action string `json:"action"`
			}
			_ = json.Unmarshal(msg.Payload, &cmdReq)
			if cmdReq.Action == "restart" {
				_ = c.runner.Restart()
			}
		}
	}
}

func (c *AgentClient) heartbeatLoop(conn *websocket.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// 采集硬件指标
			stats := c.collector.CollectStats(c.runner.GetPid(), c.runner.IsRunning())
			msg, _ := common.NewWSMessage(common.MsgTypeHeartbeat, stats)
			if err := c.writeJSON(conn, msg); err != nil {
				return
			}

			// 采集流量增量并上报
			usersTraffic := c.runner.CollectTraffic()
			if len(usersTraffic) > 0 {
				tMsg, _ := common.NewWSMessage(common.MsgTypeTraffic, common.TrafficReportPayload{Users: usersTraffic})
				_ = c.writeJSON(conn, tMsg)
			}
		}
	}
}
