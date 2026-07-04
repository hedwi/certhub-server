package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
)

func TestCertIssueRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	saved := config.Cfg
	t.Cleanup(func() { config.Cfg = saved })

	config.Cfg.RateLimit.CertIssuePerHour = 2

	handler := CertIssueRateLimitMiddleware()

	run := func() (int, bool) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/domains/1/certificate/issue", nil)
		c.Set("userID", uint(42))
		handler(c)
		return w.Code, !c.IsAborted()
	}

	if code, ok := run(); code != http.StatusOK || !ok {
		t.Fatalf("first request: code=%d allowed=%v", code, ok)
	}
	if code, ok := run(); code != http.StatusOK || !ok {
		t.Fatalf("second request: code=%d allowed=%v", code, ok)
	}
	if code, ok := run(); code != http.StatusTooManyRequests || ok {
		t.Fatalf("third request: code=%d allowed=%v, want 429 blocked", code, ok)
	}
}

func TestCertIssueRateLimitMiddleware_Disabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	saved := config.Cfg
	t.Cleanup(func() { config.Cfg = saved })

	config.Cfg.RateLimit.CertIssuePerHour = -1

	handler := CertIssueRateLimitMiddleware()
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/certificates/generate", nil)
		c.Set("userID", uint(1))
		handler(c)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: code=%d, want pass-through", i+1, w.Code)
		}
	}
}
