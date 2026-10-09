package service

import (
	"encoding/base64"
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

	// Verify ports do not conflict with Nginx 80 or 443
	for _, in := range inbounds {
		if in.ListenPort == 80 || in.ListenPort == 443 {
			t.Errorf("inbound %s port %d conflicts with Nginx standard web ports (80/443)", in.Tag, in.ListenPort)
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

	links := GenerateNodeShareLinks(node, userUUID, username)
	if len(links) == 0 {
		t.Fatalf("expected non-empty share links, got 0")
	}

	hasReality := false
	hasHy2 := false
	for _, l := range links {
		if strings.HasPrefix(l.Link, "vless://") {
			hasReality = true
			if !strings.Contains(l.Link, "security=reality") {
				t.Errorf("vless link missing reality param: %s", l.Link)
			}
			if !strings.Contains(l.Link, "156.224.28.20") {
				t.Errorf("vless link missing node address: %s", l.Link)
			}
		}
		if strings.HasPrefix(l.Link, "hysteria2://") {
			hasHy2 = true
			if !strings.Contains(l.Link, "156.224.28.20:8443") {
				t.Errorf("hysteria2 link missing port: %s", l.Link)
			}
		}
	}

	if !hasReality {
		t.Errorf("missing vless reality share link")
	}
	if !hasHy2 {
		t.Errorf("missing hysteria 2 share link")
	}
}
