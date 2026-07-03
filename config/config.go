package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

const defaultSessionSecret = "certhub-secret-change-in-production"

// Config 应用配置
type Config struct {
	Server    ServerConfig    `toml:"server"`
	Database  DatabaseConfig  `toml:"database"`
	Session   SessionConfig   `toml:"session"`
	ACME      ACMEConfig      `toml:"acme"`
	DNS       DNSConfig       `toml:"dns"`
	Domain    DomainConfig    `toml:"domain"`
	Security  SecurityConfig  `toml:"security"`
	RateLimit RateLimitConfig `toml:"ratelimit"`
	Renewal   RenewalConfig   `toml:"renewal"`
	Deploy    DeployConfig    `toml:"deploy"`
}

// RenewalConfig controls automatic certificate renewal.
type RenewalConfig struct {
	Enabled                *bool  `toml:"enabled"`
	CheckInterval          string `toml:"check_interval"`           // e.g. "1h", "30m"
	RenewBeforeDays        int    `toml:"renew_before_days"`        // renew when expiry is within this many days
	GeneratingTimeout      string `toml:"generating_timeout"`       // e.g. "15m"; reset stuck generating domains after this
	GeneratingCheckInterval string `toml:"generating_check_interval"` // how often to scan for stuck generating domains
}

// IsEnabled reports whether auto-renewal is on (default true).
func (r RenewalConfig) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// GeneratingTimeoutDuration returns how long a generating job may run before rollback.
func (r RenewalConfig) GeneratingTimeoutDuration() time.Duration {
	return parseDurationDefault(r.GeneratingTimeout, 15*time.Minute)
}

// GeneratingCheckIntervalDuration returns how often stuck generating domains are scanned.
func (r RenewalConfig) GeneratingCheckIntervalDuration() time.Duration {
	return parseDurationDefault(r.GeneratingCheckInterval, 5*time.Minute)
}

func parseDurationDefault(value string, fallback time.Duration) time.Duration {
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return d
}

// DeployConfig controls certificate deploy API availability.
type DeployConfig struct {
	Enabled *bool `toml:"enabled"`
}

// IsEnabled reports whether the deploy API is exposed (default false).
func (d DeployConfig) IsEnabled() bool {
	if d.Enabled == nil {
		return false
	}
	return *d.Enabled
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port           string   `toml:"port"`
	Addr           string   `toml:"addr"`
	AllowedOrigins []string `toml:"allowed_origins"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Host     string `toml:"host"`
	Port     string `toml:"port"`
	User     string `toml:"user"`
	Password string `toml:"password"`
	DBName   string `toml:"dbname"`
	SSLMode  string `toml:"sslmode"`
}

// SessionConfig 会话配置
type SessionConfig struct {
	Secret   string `toml:"secret"`
	MaxAge   int    `toml:"max_age"`
	Path     string `toml:"path"`
	HttpOnly bool   `toml:"http_only"`
	Secure   bool   `toml:"secure"`
	SameSite string `toml:"same_site"` // lax, strict, none
	Name     string `toml:"name"`
}

// ACMEConfig ACME 证书配置
type ACMEConfig struct {
	CAURL string `toml:"ca_url"`
}

// DNSConfig DNS 提供商配置
type DNSConfig struct {
	Provider   string           `toml:"provider"`
	AuthZone   string           `toml:"auth_zone"` // Cloudflare zone for CNAME delegation (e.g. yourservice.com)
	Cloudflare CloudflareConfig `toml:"cloudflare"`
}

// CloudflareConfig Cloudflare DNS 配置
type CloudflareConfig struct {
	APIEmail string `toml:"api_email"`
	APIKey   string `toml:"api_key"`
	APIToken string `toml:"api_token"`
}

// DomainConfig 域名相关配置
type DomainConfig struct {
	CNameTarget string `toml:"cname_target"` // base delegation host (e.g. cname.yourservice.com)
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	EncryptionKey string `toml:"encryption_key"` // base64-encoded 32-byte AES-256 key
	DevMode       *bool  `toml:"dev_mode"`       // allow unencrypted key storage (local dev only)
}

// IsDevMode reports whether dev-only relaxations are enabled.
// CERTHUB_DEV env var (true/1) overrides config when set.
func (s SecurityConfig) IsDevMode() bool {
	if v, ok := os.LookupEnv("CERTHUB_DEV"); ok {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	if s.DevMode == nil {
		return false
	}
	return *s.DevMode
}

// RateLimitConfig 速率限制配置
type RateLimitConfig struct {
	Enabled           bool `toml:"enabled"`
	RequestsPerMinute int  `toml:"requests_per_minute"`
}

var Cfg Config

func init() {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "./config.toml"
	}
	if err := Load(path); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
}

// Load 从 TOML 文件加载配置
func Load(path string) error {
	if path == "" {
		path = "./config.toml"
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if _, err := toml.DecodeFile(absPath, &Cfg); err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config file %s not found, using defaults. Create config.toml from config.example.toml", absPath)
			setDefaults()
			return nil
		}
		return err
	}
	applyDefaults()
	return nil
}

func setDefaults() {
	Cfg = Config{
		Server: ServerConfig{
			Port: "8080",
			Addr: "",
		},
		Database: DatabaseConfig{
			Host:     "localhost",
			Port:     "5432",
			User:     "postgres",
			Password: "",
			DBName:   "certhub",
			SSLMode:  "disable",
		},
		Session: SessionConfig{
			Secret:   defaultSessionSecret,
			MaxAge:   86400 * 30,
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
			SameSite: "lax",
			Name:     "certhub_session",
		},
		ACME: ACMEConfig{
			CAURL: "https://acme-v02.api.letsencrypt.org/directory",
		},
		DNS: DNSConfig{
			Provider: "cloudflare",
		},
		Domain: DomainConfig{
			CNameTarget: "cname.yourservice.com",
		},
		RateLimit: RateLimitConfig{
			Enabled:           true,
			RequestsPerMinute: 60,
		},
		Renewal: RenewalConfig{
			CheckInterval:           "1h",
			RenewBeforeDays:         30,
			GeneratingTimeout:       "15m",
			GeneratingCheckInterval: "5m",
		},
	}
}

func applyDefaults() {
	if Cfg.Server.Port == "" {
		Cfg.Server.Port = "8080"
	}
	if Cfg.Database.Port == "" {
		Cfg.Database.Port = "5432"
	}
	if Cfg.Database.SSLMode == "" {
		Cfg.Database.SSLMode = "disable"
	}
	if Cfg.Session.Secret == "" {
		Cfg.Session.Secret = defaultSessionSecret
	}
	if Cfg.Session.MaxAge == 0 {
		Cfg.Session.MaxAge = 86400 * 30
	}
	if Cfg.Session.Path == "" {
		Cfg.Session.Path = "/"
	}
	if Cfg.Session.Name == "" {
		Cfg.Session.Name = "certhub_session"
	}
	if Cfg.Session.SameSite == "" {
		Cfg.Session.SameSite = "lax"
	}
	if Cfg.ACME.CAURL == "" {
		Cfg.ACME.CAURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if Cfg.Domain.CNameTarget == "" {
		Cfg.Domain.CNameTarget = "cname.yourservice.com"
	}
	if Cfg.RateLimit.RequestsPerMinute == 0 {
		Cfg.RateLimit.RequestsPerMinute = 60
	}
	if Cfg.Renewal.CheckInterval == "" {
		Cfg.Renewal.CheckInterval = "1h"
	}
	if Cfg.Renewal.RenewBeforeDays == 0 {
		Cfg.Renewal.RenewBeforeDays = 30
	}
	if Cfg.Renewal.GeneratingTimeout == "" {
		Cfg.Renewal.GeneratingTimeout = "15m"
	}
	if Cfg.Renewal.GeneratingCheckInterval == "" {
		Cfg.Renewal.GeneratingCheckInterval = "5m"
	}
}

// Validate checks critical configuration at startup.
func Validate() error {
	if err := validateSessionAndCORS(); err != nil {
		return err
	}
	if Cfg.DNS.AuthZone == "" {
		return fmt.Errorf("dns.auth_zone is required (Cloudflare zone for CNAME delegation, e.g. yourservice.com)")
	}
	cf := Cfg.DNS.Cloudflare
	if cf.APIToken == "" && (cf.APIEmail == "" || cf.APIKey == "") {
		return fmt.Errorf("cloudflare credentials required: set dns.cloudflare.api_token or api_email+api_key")
	}
	if Cfg.Security.EncryptionKey != "" {
		key, err := DecodeEncryptionKey(Cfg.Security.EncryptionKey)
		if err != nil {
			return fmt.Errorf("security.encryption_key: %w", err)
		}
		if len(key) != 32 {
			return fmt.Errorf("security.encryption_key must decode to 32 bytes")
		}
	} else if Cfg.Security.IsDevMode() {
		log.Println("WARNING: dev mode: security.encryption_key not set; private keys stored unencrypted")
	} else {
		return fmt.Errorf("security.encryption_key is required (set security.dev_mode = true or CERTHUB_DEV=1 only for local development)")
	}
	return nil
}

func isDefaultSessionSecret(secret string) bool {
	return secret == "" || secret == defaultSessionSecret
}

func validateSessionAndCORS() error {
	if Cfg.Security.IsDevMode() {
		if isDefaultSessionSecret(Cfg.Session.Secret) {
			log.Println("WARNING: dev mode: using default session secret")
		}
		if len(Cfg.Server.AllowedOrigins) == 0 {
			log.Println("WARNING: dev mode: server.allowed_origins not set; any origin may access the API with credentials")
		}
		return nil
	}

	if isDefaultSessionSecret(Cfg.Session.Secret) {
		return fmt.Errorf("session.secret must be set to a unique value in production")
	}
	if len(Cfg.Server.AllowedOrigins) == 0 {
		return fmt.Errorf("server.allowed_origins is required in production (list every trusted frontend origin)")
	}
	for _, origin := range Cfg.Server.AllowedOrigins {
		if origin == "*" {
			return fmt.Errorf("server.allowed_origins must not contain '*' when credentials are enabled")
		}
	}
	return nil
}

// DecodeEncryptionKey decodes a base64 encryption key from config.
func DecodeEncryptionKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateEncryptionKey returns a random 32-byte key encoded as base64.
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// DelegationTarget builds the per-domain CNAME delegation target FQDN.
func DelegationTarget(domainID uint) string {
	base := strings.TrimSuffix(Cfg.Domain.CNameTarget, ".")
	return fmt.Sprintf("%d.%s", domainID, base)
}
