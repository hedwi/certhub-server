package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

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
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port string `toml:"port"`
	Addr string `toml:"addr"`
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
			Secret:   "certhub-secret-change-in-production",
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
		Cfg.Session.Secret = "certhub-secret-change-in-production"
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
}

// Validate checks critical configuration at startup.
func Validate() error {
	if Cfg.Session.Secret == "certhub-secret-change-in-production" {
		log.Println("WARNING: using default session secret; change session.secret in production")
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
	} else {
		log.Println("WARNING: security.encryption_key not set; private keys stored unencrypted")
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
