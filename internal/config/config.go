package config

import (
	"fmt"
	"regexp"
	"time"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server" reload:"true"`
	Database DatabaseConfig `mapstructure:"database"`
	App      AppConfig      `mapstructure:"app" reload:"true"`
}

type ServerConfig struct {
	Host       string         `mapstructure:"host"`
	Port       int            `mapstructure:"port"`
	Production bool           `mapstructure:"production" reload:"true"`
	CORSURL    []string       `mapstructure:"cors-url" reload:"true"`
	Security   SecurityConfig `mapstructure:"security" reload:"true"`
}

type SecurityConfig struct {
	JWTSecret string `mapstructure:"jwt-secret" reload:"true"`
}

type DatabaseConfig struct {
	Host         string `mapstructure:"host"`
	Port         int    `mapstructure:"port"`
	Username     string `mapstructure:"username"`
	Password     string `mapstructure:"password"`
	DatabaseName string `mapstructure:"database-name"`
	SSLMode      string `mapstructure:"ssl-mode"`
}

type AppConfig struct {
	TokenExpiry   time.Duration  `mapstructure:"token-expiry" reload:"true"`
	TOTPIssuer    string         `mapstructure:"totp-issuer" reload:"true"`
	TeamSize      int            `mapstructure:"team-size" reload:"true"`
	EmailRegex    string         `mapstructure:"email-regex" reload:"true"`
	CompiledEmail *regexp.Regexp `mapstructure:"-"`
	Ban           BanConfig      `mapstructure:"ban" reload:"true"`
	AppCache      CacheConfig    `mapstructure:"cache"`
}

type CacheConfig struct {
	InApp                 bool          `mapstructure:"in-app"`
	ServiceUrl            string        `mapstructure:"service-url"`
	ServiceType           string        `mapstructure:"service-type"`
	InternalCacheSize     int           `mapstructure:"internal-cache-size"`
	InternalCacheDuration time.Duration `mapstructure:"internal-cache-duration"`
}

type BanConfig struct {
	UserBan            bool          `mapstructure:"enable-user-ban" reload:"true"`
	TeamBan            bool          `mapstructure:"enable-team-ban" reload:"true"`
	InitialBanDuration time.Duration `mapstructure:"initial-ban-duration" reload:"true"`
	BanGrowthFactor    float64       `mapstructure:"ban-growth-factor" reload:"true"`
	MaxBanDuration     time.Duration `mapstructure:"max-ban-duration" reload:"true"`
}

func (cfg *Config) Validate() error {
	cache := cfg.App.AppCache
	if cache.InApp {
		if cache.ServiceType != "redis" {
			return fmt.Errorf("only supported service is redis")
		} else if cache.ServiceType == "" {
			return fmt.Errorf("service-url cannot be empty")
		}
	}
	return nil
}
