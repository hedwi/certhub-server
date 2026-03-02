package config

import (
	"log"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config 应用配置
type Config struct {
	Server   ServerConfig   `toml:"server"`
	Database DatabaseConfig `toml:"database"`
	Session  SessionConfig  `toml:"session"`
	ACME     ACMEConfig     `toml:"acme"`
	DNS      DNSConfig      `toml:"dns"`
	Domain   DomainConfig   `toml:"domain"`
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
	Name     string `toml:"name"`
}

// ACMEConfig ACME 证书配置
type ACMEConfig struct {
	CAURL string `toml:"ca_url"`
}

// DNSConfig DNS 提供商配置
type DNSConfig struct {
	Provider string         `toml:"provider"`
	Cloudflare CloudflareConfig `toml:"cloudflare"`
}

// CloudflareConfig Cloudflare DNS 配置
type CloudflareConfig struct {
	APIEmail string `toml:"api_email"`
	APIKey   string `toml:"api_key"`
	APIToken string `toml:"api_token"` // API Token 优先于 api_email+api_key
}

// DomainConfig 域名相关配置
type DomainConfig struct {
	CNameTarget string `toml:"cname_target"`
}

var Cfg Config

func init() {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "./config.toml"
	}
	Load(path)
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
			MaxAge:   86400 * 30, // 30 days
			Path:     "/",
			HttpOnly: true,
			Secure:   false,
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
	if Cfg.ACME.CAURL == "" {
		Cfg.ACME.CAURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if Cfg.Domain.CNameTarget == "" {
		Cfg.Domain.CNameTarget = "cname.yourservice.com"
	}
}
