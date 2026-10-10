package master

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"work-v/internal/master/middleware"
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

func TestForbidRegistrationAndAdminOnlyUsers(t *testing.T) {
	dbPath := "test_reg_forbid.db"
	defer os.Remove(dbPath)
	_, err := model.InitDB(dbPath)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}

	r := SetupRouter(nil)

	// 1. Verify /register returns 403 Forbidden
	for _, method := range []string{"GET", "POST"} {
		req, _ := http.NewRequest(method, "/register", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 for %s /register, got %d", method, w.Code)
		}
	}

	// 2. Verify /api/v1/register returns 403 Forbidden
	for _, method := range []string{"GET", "POST"} {
		req, _ := http.NewRequest(method, "/api/v1/register", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 for %s /api/v1/register, got %d", method, w.Code)
		}
	}

	// 3. Verify /api/v1/auth/register returns 403 Forbidden
	for _, method := range []string{"GET", "POST"} {
		req, _ := http.NewRequest(method, "/api/v1/auth/register", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("Expected 403 for %s /api/v1/auth/register, got %d", method, w.Code)
		}
	}

	// 4. Verify /api/v1/admin/users cannot be accessed without admin token
	// 4.1 Without safe entrance -> 403 Forbidden
	reqNoSafe, _ := http.NewRequest("POST", "/api/v1/admin/users", strings.NewReader(`{"username":"hacker"}`))
	reqNoSafe.Header.Set("Content-Type", "application/json")
	wNoSafe := httptest.NewRecorder()
	r.ServeHTTP(wNoSafe, reqNoSafe)
	if wNoSafe.Code != http.StatusForbidden {
		t.Errorf("Expected 403 without safe entrance, got %d", wNoSafe.Code)
	}

	// 4.2 With safe entrance but without admin JWT token -> 401 Unauthorized
	safePath := middleware.GlobalSafeEntrance.SafePath
	reqNoAuth, _ := http.NewRequest("POST", "/api/v1/admin/users", strings.NewReader(`{"username":"hacker"}`))
	reqNoAuth.Header.Set("Content-Type", "application/json")
	reqNoAuth.Header.Set("X-Safe-Entrance", safePath)
	wNoAuth := httptest.NewRecorder()
	r.ServeHTTP(wNoAuth, reqNoAuth)
	if wNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 without admin token, got %d", wNoAuth.Code)
	}
}

