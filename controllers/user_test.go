package controllers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
)

func TestRegister_DisabledByDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	saved := config.Cfg
	t.Cleanup(func() { config.Cfg = saved })

	config.Cfg.Auth.RegistrationEnabled = nil

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/auth/register",
		strings.NewReader(`{"email":"user@test.example","password":"secret123"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	Register(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", w.Code)
	}
}

func TestRegister_EnabledRequiresDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	saved := config.Cfg
	t.Cleanup(func() { config.Cfg = saved })

	enabled := true
	config.Cfg.Auth.RegistrationEnabled = &enabled

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/auth/register",
		strings.NewReader(`{"email":"not-an-email","password":"x"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	Register(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 for invalid input when registration enabled", w.Code)
	}
}
