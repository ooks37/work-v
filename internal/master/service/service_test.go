package service

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"work-v/internal/master/model"
)

func TestGenerateX25519KeyPair(t *testing.T) {
	priv, pub, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair failed: %v", err)
	}
	if len(priv) != 43 {
		t.Errorf("expected 43 chars base64 RawURL private key, got %d chars: %s", len(priv), priv)
	}
	if len(pub) != 43 {
		t.Errorf("expected 43 chars base64 RawURL public key, got %d chars: %s", len(pub), pub)
	}
	// Verify it decodes cleanly to 32 bytes
	privBytes, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil || len(privBytes) != 32 {
		t.Errorf("failed to decode private key as 32-byte RawURL base64: %v", err)
	}
	pubBytes, err := base64.RawURLEncoding.DecodeString(pub)
	if err != nil || len(pubBytes) != 32 {
		t.Errorf("failed to decode public key as 32-byte RawURL base64: %v", err)
	}
}

func TestGetOrCreateDefaultInbounds(t *testing.T) {
	node := &model.Node{
		ID:      1,
		Name:    "测试核心节点",
		Address: "156.224.28.20",
	}
	inbounds := GetOrCreateDefaultInbounds(node)
	if len(inbounds) < 4 {
		t.Fatalf("expected at least 4 default inbounds, got %d", len(inbounds))
	}

	// Verify ports do not conflict with Nginx 80 or 443 and are 5-digit random ports
	for _, in := range inbounds {
		if in.ListenPort == 80 || in.ListenPort == 443 {
			t.Errorf("inbound %s port %d conflicts with Nginx standard web ports (80/443)", in.Tag, in.ListenPort)
		}
		if in.ListenPort < 10000 || in.ListenPort > 65535 {
			t.Errorf("inbound %s port %d is not a 5-digit random port (expected 10000-65535)", in.Tag, in.ListenPort)
		}
	}
}

func TestGenerateNodeShareLinks(t *testing.T) {
	node := &model.Node{
		ID:      1,
		Name:    "香港自适应节点",
		Address: "156.224.28.20",
	}
	userUUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	username := "vip_user"

	inbounds := GetOrCreateDefaultInbounds(node)
	for i := range inbounds {
		inbounds[i].Enabled = true
	}
	data, _ := json.Marshal(inbounds)
	node.InboundsJSON = string(data)

	links := GenerateNodeShareLinks(node, userUUID, username)
	if len(links) == 0 {
		t.Fatalf("expected non-empty share links, got 0")
	}

	hasReality := false
	hasHy2 := false
	hasShadowsocks := false
	hasTrojan := false
	hasVlessWS := false
	for _, l := range links {
		if strings.HasPrefix(l.Link, "vless://") {
			if strings.Contains(l.Link, "security=reality") {
				hasReality = true
			}
			if strings.Contains(l.Link, "type=ws") {
				hasVlessWS = true
			}
		}
		if strings.HasPrefix(l.Link, "hysteria2://") {
			hasHy2 = true
		}
		if strings.HasPrefix(l.Link, "ss://") {
			hasShadowsocks = true
		}
		if strings.HasPrefix(l.Link, "trojan://") {
			hasTrojan = true
		}
	}

	if !hasReality {
		t.Errorf("missing vless reality share link")
	}
	if !hasHy2 {
		t.Errorf("missing hysteria 2 share link")
	}
	if !hasShadowsocks {
		t.Errorf("missing shadowsocks share link")
	}
	if !hasTrojan {
		t.Errorf("missing trojan share link")
	}
	if !hasVlessWS {
		t.Errorf("missing vless-ws share link")
	}
}

func TestBatchUserOperations(t *testing.T) {
	// Setup SQLite
	dbPath := "test_service.db"
	defer os.Remove(dbPath)
	_, err := model.InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	// 1. Batch Create Users
	users, err := BatchCreateUsers("tester", 3, 50, 30)
	if err != nil {
		t.Fatalf("BatchCreateUsers failed: %v", err)
	}
	if len(users) != 3 {
		t.Fatalf("expected 3 users, got %d", len(users))
	}

	// Check each user
	for _, u := range users {
		if !strings.HasPrefix(u.Username, "tester_") {
			t.Errorf("expected username prefix tester_, got %s", u.Username)
		}
		if u.TrafficLimit != 50*1024*1024*1024 {
			t.Errorf("expected 50GB limit, got %d", u.TrafficLimit)
		}
		if u.Status != "active" {
			t.Errorf("expected active status, got %s", u.Status)
		}
	}

	// Manually set traffic on users
	model.DB.Model(&model.User{}).Where("1 = 1").Update("used_traffic", 1024*1024)

	// 2. Reset All Users Traffic
	if err := ResetAllUsersTraffic(); err != nil {
		t.Fatalf("ResetAllUsersTraffic failed: %v", err)
	}

	var count int64
	model.DB.Model(&model.User{}).Where("used_traffic > 0").Count(&count)
	if count != 0 {
		t.Errorf("expected 0 users with used_traffic > 0 after reset, got %d", count)
	}
}
