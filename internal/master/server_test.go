package master

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"work-v/internal/master/model"
)

func TestQRCodeEndpoint(t *testing.T) {
	// Setup in-memory SQLite DB for testing
	dbPath := "test_qr.db"
	defer os.Remove(dbPath)
	_, err := model.InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	r := SetupRouter(nil)

	// Test missing text param
	reqEmpty, _ := http.NewRequest("GET", "/api/v1/qrcode", nil)
	wEmpty := httptest.NewRecorder()
	r.ServeHTTP(wEmpty, reqEmpty)
	if wEmpty.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for empty text, got %d", wEmpty.Code)
	}

	// Test valid text param
	reqValid, _ := http.NewRequest("GET", "/api/v1/qrcode?text=vless://test-uuid@1.1.1.1:2083", nil)
	wValid := httptest.NewRecorder()
	r.ServeHTTP(wValid, reqValid)

	if wValid.Code != http.StatusOK {
		t.Errorf("Expected 200 for valid text, got %d", wValid.Code)
	}

	contentType := wValid.Header().Get("Content-Type")
	if contentType != "image/png" {
		t.Errorf("Expected Content-Type image/png, got %s", contentType)
	}

	body := wValid.Body.Bytes()
	if len(body) < 8 {
		t.Fatalf("Body too short to be PNG")
	}

	// Check PNG magic bytes: 0x89 'P' 'N' 'G' 0x0D 0x0A 0x1A 0x0A
	pngHeader := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.Equal(body[:8], pngHeader) {
		t.Errorf("Response body does not contain PNG header magic bytes")
	}
}
