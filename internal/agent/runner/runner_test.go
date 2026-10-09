package runner

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"work-v/internal/common"
)

func TestGenerateSingboxJSON(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "workv_runner_test*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	payload := &common.NodeConfigPayload{
		ConfigHash: "testhash123",
		Users: []common.UserProfile{
			{
				ID:       1,
				Username: "vip_user",
				UUID:     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				Password: "testpassword",
				Status:   "active",
			},
		},
		Inbounds: []common.InboundConfig{
			{
				Type:       "vless",
				Tag:        "vless-reality-in",
				ListenPort: 2083,
				Enabled:    true,
				Options: map[string]any{
					"server_name": "gateway.icloud.com",
					"dest":        "gateway.icloud.com:443",
					"private_key": "GFNY7WrCAo4m2guHkgcPe08N13yNE5lOJYtwW4_9ZVI",
					"short_id":    "317928a0",
				},
			},
			{
				Type:       "hysteria2",
				Tag:        "hy2-in",
				ListenPort: 8443,
				Enabled:    true,
				Options:    map[string]any{},
			},
			{
				Type:       "grpc-reality",
				Tag:        "grpc-reality-in",
				ListenPort: 2053,
				Enabled:    true,
				Options: map[string]any{
					"private_key": "e09a67791131e371d1b55def2366330f9153ca7641dac06f0c4d32b80a8a8d49", // hex format to test auto-conversion
				},
			},
			{
				Type:       "tuic",
				Tag:        "tuic-in",
				ListenPort: 8444,
				Enabled:    true,
				Options:    map[string]any{},
			},
		},
	}

	sbBytes, err := generateSingboxJSON(payload, tmpDir)
	if err != nil {
		t.Fatalf("generateSingboxJSON failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(sbBytes, &parsed); err != nil {
		t.Fatalf("generated JSON is invalid: %v\nJSON: %s", err, string(sbBytes))
	}

	inbounds, ok := parsed["inbounds"].([]any)
	if !ok || len(inbounds) != 4 {
		t.Fatalf("expected 4 inbounds in parsed config, got %d", len(inbounds))
	}

	// Verify hex key was converted to base64 URL format (not 64 chars hex)
	jsonStr := string(sbBytes)
	if strings.Contains(jsonStr, "e09a67791131e371d1b55def2366330f9153ca7641dac06f0c4d32b80a8a8d49") {
		t.Errorf("expected hex key to be converted to Base64 URL format")
	}
}
