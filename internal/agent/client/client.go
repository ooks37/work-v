package client

import (
	"encoding/json"
	"log"
	"net/url"
	"strings"
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
}

func NewAgentClient(serverURL, token string, r *runner.SingboxRunner) *AgentClient {
	return &AgentClient{
		serverURL: serverURL,
		token:     token,
		runner:    r,
		collector: collector.NewSystemCollector(),
	}
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
	if err := conn.WriteJSON(authMsg); err != nil {
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
		log.Printf("[Agent] 认证被主控拒绝: %s", authResult.Error)
		return nil
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
				if err := c.runner.ApplyConfig(&config); err != nil {
					log.Printf("[Agent] 应用配置失败: %v", err)
				} else {
					log.Println("[Agent] 新配置已成功加载并在 Sing-box 生效！")
				}
			}

		case common.MsgTypeCutoffUser:
			var req struct {
				UUID string `json:"uuid"`
			}
			if err := json.Unmarshal(msg.Payload, &req); err == nil && req.UUID != "" {
				c.runner.CutoffUser(req.UUID)
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
			if err := conn.WriteJSON(msg); err != nil {
				return
			}

			// 采集流量增量并上报
			usersTraffic := c.runner.CollectTraffic()
			if len(usersTraffic) > 0 {
				tMsg, _ := common.NewWSMessage(common.MsgTypeTraffic, common.TrafficReportPayload{Users: usersTraffic})
				_ = conn.WriteJSON(tMsg)
			}
		}
	}
}

func cleanURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "http://" + raw
	}
	return raw
}
