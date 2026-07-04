package integration_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hedwi/certhub-server/config"
	"github.com/hedwi/certhub-server/controllers"
	"github.com/hedwi/certhub-server/models"
	"github.com/hedwi/certhub-server/routes"
	"github.com/hedwi/certhub-server/services"
	"github.com/hedwi/certhub-server/utils"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type apiResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type domainDTO struct {
	ID string `json:"id"`
}

type cnameConfigDTO struct {
	Verified    bool    `json:"verified"`
	LiveChecked bool    `json:"liveChecked"`
	VerifiedAt  *string `json:"verifiedAt"`
}

type integrationEnv struct {
	t      *testing.T
	server *httptest.Server
	client *http.Client
}

func setupIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	gin.SetMode(gin.TestMode)
	controllers.ResetTestState()

	savedCfg := config.Cfg
	t.Cleanup(func() { config.Cfg = savedCfg })

	devMode := true
	regEnabled := true
	config.Cfg = config.Config{
		Server: config.ServerConfig{
			AllowedOrigins: []string{"http://localhost"},
		},
		Auth: config.AuthConfig{
			RegistrationEnabled: &regEnabled,
		},
		Session: config.SessionConfig{
			Secret:   "integration-test-secret",
			MaxAge:   86400,
			Path:     "/",
			HttpOnly: true,
			Name:     "certhub_session",
			SameSite: "lax",
		},
		Domain: config.DomainConfig{
			CNameTarget: "cname.test.example",
		},
		Security: config.SecurityConfig{
			DevMode: &devMode,
		},
		RateLimit: config.RateLimitConfig{
			Enabled:          false,
			CertIssuePerHour: -1,
		},
		Renewal: config.RenewalConfig{
			MaxConcurrentJobs: 10,
		},
	}

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{},
		&models.Domain{},
		&models.Certificate{},
		&models.AcmeAccount{},
		&models.DeployTarget{},
		&models.DeployJob{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	config.DB = db

	if err := services.InitCrypto(); err != nil {
		t.Fatalf("init crypto: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}

	router := routes.SetupRouter()
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	env := &integrationEnv{
		t:      t,
		server: server,
		client: &http.Client{Jar: jar},
	}

	env.registerUser("user@test.example", "secret123")
	return env
}

func (e *integrationEnv) registerUser(email, password string) {
	e.t.Helper()
	body := `{"email":"` + email + `","password":"` + password + `"}`
	resp, parsed := e.request(http.MethodPost, "/api/auth/register", body)
	if resp.StatusCode != http.StatusOK || parsed.Code != utils.CodeSuccess {
		e.t.Fatalf("register failed: status=%d code=%d message=%q", resp.StatusCode, parsed.Code, parsed.Message)
	}
}

func (e *integrationEnv) request(method, path, body string) (*http.Response, apiResponse) {
	e.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.server.URL+path, reader)
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatalf("do request: %v", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("read body: %v", err)
	}

	var parsed apiResponse
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &parsed); err != nil {
			e.t.Fatalf("decode response %q: %v", string(raw), err)
		}
	}
	return resp, parsed
}

func (e *integrationEnv) createDomain(name string) models.Domain {
	e.t.Helper()
	resp, parsed := e.request(http.MethodPost, "/api/domains", `{"name":"`+name+`"}`)
	if resp.StatusCode != http.StatusOK || parsed.Code != utils.CodeSuccess {
		e.t.Fatalf("create domain failed: status=%d code=%d message=%q", resp.StatusCode, parsed.Code, parsed.Message)
	}

	var dto domainDTO
	if err := json.Unmarshal(parsed.Data, &dto); err != nil {
		e.t.Fatalf("decode domain dto: %v", err)
	}

	id, err := strconv.ParseUint(dto.ID, 10, 64)
	if err != nil {
		e.t.Fatalf("parse domain id: %v", err)
	}

	var domain models.Domain
	if err := config.DB.First(&domain, uint(id)).Error; err != nil {
		e.t.Fatalf("load domain: %v", err)
	}
	return domain
}

func domainIDPath(domain models.Domain) string {
	return strconv.FormatUint(uint64(domain.ID), 10)
}

func TestIssueCertificate_MalformedJSON_Returns400(t *testing.T) {
	env := setupIntegrationEnv(t)
	domain := env.createDomain("malformed-json.example.com")

	resp, parsed := env.request(http.MethodPost, "/api/domains/"+domainIDPath(domain)+"/certificate/issue", "{not-json")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", resp.StatusCode)
	}
	if parsed.Code != 1 {
		t.Fatalf("code=%d, want 1", parsed.Code)
	}
	if parsed.Message == "" {
		t.Fatal("expected error message for malformed JSON")
	}
}

func TestIssueCertificate_EmptyBody_AllowsDefaultForceRenew(t *testing.T) {
	env := setupIntegrationEnv(t)
	domain := env.createDomain("empty-body.example.com")

	resp, parsed := env.request(http.MethodPost, "/api/domains/"+domainIDPath(domain)+"/certificate/issue", "")
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(strings.ToLower(parsed.Message), "json") {
		t.Fatalf("empty body should not fail JSON bind, got message=%q", parsed.Message)
	}
}

func TestIssueCertificate_ValidJSON_BindsForceRenew(t *testing.T) {
	env := setupIntegrationEnv(t)
	domain := env.createDomain("force-renew.example.com")

	resp, parsed := env.request(http.MethodPost, "/api/domains/"+domainIDPath(domain)+"/certificate/issue", `{"forceRenew":true}`)
	if resp.StatusCode == http.StatusBadRequest && strings.Contains(strings.ToLower(parsed.Message), "json") {
		t.Fatalf("valid JSON should bind, got message=%q", parsed.Message)
	}
	_ = parsed
}

func TestGetCname_LiveCheckDefaultsFalseWithoutDNS(t *testing.T) {
	env := setupIntegrationEnv(t)
	pending := env.createDomain("pending-cname.example.com")

	resp, parsed := env.request(http.MethodGet, "/api/domains/"+domainIDPath(pending)+"/cname", "")
	if resp.StatusCode != http.StatusOK || parsed.Code != utils.CodeSuccess {
		t.Fatalf("get cname failed: status=%d code=%d message=%q", resp.StatusCode, parsed.Code, parsed.Message)
	}

	var cfg cnameConfigDTO
	if err := json.Unmarshal(parsed.Data, &cfg); err != nil {
		t.Fatalf("decode cname dto: %v", err)
	}
	if cfg.Verified {
		t.Fatal("pending domain should not be verified in GET /cname response")
	}
	if !cfg.LiveChecked {
		t.Fatal("expected default GET /cname to perform live DNS check")
	}

	if err := config.DB.Model(&pending).Update("status", "verified").Error; err != nil {
		t.Fatalf("set verified: %v", err)
	}

	resp, parsed = env.request(http.MethodGet, "/api/domains/"+domainIDPath(pending)+"/cname", "")
	if resp.StatusCode != http.StatusOK || parsed.Code != utils.CodeSuccess {
		t.Fatalf("get cname failed after verify status: status=%d code=%d", resp.StatusCode, parsed.Code)
	}
	if err := json.Unmarshal(parsed.Data, &cfg); err != nil {
		t.Fatalf("decode cname dto: %v", err)
	}
	if cfg.Verified {
		t.Fatal("DB-only verified status should not show verified=true when live DNS fails")
	}
	if !cfg.LiveChecked {
		t.Fatal("expected live DNS check")
	}
}

func TestGetCname_LiveFalseUsesStoredStatus(t *testing.T) {
	env := setupIntegrationEnv(t)
	pending := env.createDomain("stored-status.example.com")

	if err := config.DB.Model(&pending).Update("status", "verified").Error; err != nil {
		t.Fatalf("set verified: %v", err)
	}

	resp, parsed := env.request(http.MethodGet, "/api/domains/"+domainIDPath(pending)+"/cname?live=false", "")
	if resp.StatusCode != http.StatusOK || parsed.Code != utils.CodeSuccess {
		t.Fatalf("get cname failed: status=%d code=%d", resp.StatusCode, parsed.Code)
	}

	var cfg cnameConfigDTO
	if err := json.Unmarshal(parsed.Data, &cfg); err != nil {
		t.Fatalf("decode cname dto: %v", err)
	}
	if !cfg.Verified {
		t.Fatal("expected stored verified=true when live=false")
	}
	if cfg.LiveChecked {
		t.Fatal("expected liveChecked=false when live=false")
	}
}
