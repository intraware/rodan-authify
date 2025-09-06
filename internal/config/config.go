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
	MaxTries     int    `mapstructure:"max-tries"`
}

type AppConfig struct {
	TokenExpiry       time.Duration  `mapstructure:"token-expiry" reload:"true"`
	TeamSize          int            `mapstructure:"team-size" reload:"true"`
	EmailRegex        string         `mapstructure:"email-regex" reload:"true"`
	CompiledEmail     *regexp.Regexp `mapstructure:"-"`
	AllowLeavingTeam  bool           `mapstructure:"allow-leave-team"`
	AllowOutsideEmail bool           `mapstructure:"allow-outside-email"`
	EmailsCSV         string         `mapstructure:"emails-csv"`

	Email    EmailConfig `mapstructure:"email" reload:"true"`
	OAuth    OAuthConfig `mapstructure:"oauth" reload:"true"`
	TOTP     TOTPConfig  `mapstructure:"totp" reload:"true"`
	Ban      BanConfig   `mapstructure:"ban" reload:"true"`
	AppCache CacheConfig `mapstructure:"cache"`
}

type EmailConfig struct {
	Enabled                   bool                `mapstructure:"enabled"`
	AgentEmail                string              `mapstructure:"agent-email" reload:"true"`
	AllowedEmailRegex         string              `mapstructure:"allowed-email-regex" reload:"true"`
	AllowedEmailCompilexRegex *regexp.Regexp      `mapstructure:"-"`
	Provider                  EmailProviderConfig `mapstructure:"provider" reload:"true"`
}

type EmailProviderConfig struct {
	Type     string `mapstructure:"type" reload:"true"`
	Host     string `mapstructure:"host" reload:"true"`
	Port     int    `mapstructure:"port" reload:"true"`
	Username string `mapstructure:"username" reload:"true"`
	Password string `mapstructure:"password" reload:"true"`

	// Microsoft Graph (if used)
	TenantID     string `mapstructure:"tenant-id" reload:"true"`
	ClientID     string `mapstructure:"client_id" reload:"true"`
	ClientSecret string `mapstructure:"client_secret" reload:"true"`
}

type OAuthConfig struct {
	Enabled     bool                           `mapstructure:"enabled"`
	RedirectURL string                         `mapstructure:"redirect_url" reload:"true"`
	Providers   map[string]OAuthProviderConfig `mapstructure:"providers" reload:"true"`
}

type OAuthProviderConfig struct {
	ClientID     string   `mapstructure:"client_id" reload:"true"`
	ClientSecret string   `mapstructure:"client_secret" reload:"true"`
	Scopes       []string `mapstructure:"scopes" reload:"true"`
	AuthURL      string   `mapstructure:"auth_url" reload:"true"`
	TokenURL     string   `mapstructure:"token_url" reload:"true"`
	UserInfoURL  string   `mapstructure:"userinfo_url" reload:"true"`
}

type TOTPConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Issuer    string `mapstructure:"issuer"`
	Digits    int    `mapstructure:"digits"`
	Period    uint   `mapstructure:"period"`
	Algorithm string `mapstructure:"algorithm"`
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
		} else if cache.ServiceUrl == "" {
			return fmt.Errorf("service-url cannot be empty")
		}
	}
	if cfg.App.EmailRegex != "" {
		re, err := regexp.Compile(cfg.App.EmailRegex)
		if err != nil {
			return fmt.Errorf("invalid email regex: %w", err)
		}
		cfg.App.CompiledEmail = re
	}
	if cfg.App.Email.Enabled {
		if cfg.App.Email.Provider.Type == "" {
			return fmt.Errorf("email auth requires a provider type (smtp or microsoft-graph)")
		}
		if cfg.App.Email.Provider.Type != "smtp" && cfg.App.Email.Provider.Type != "microsoft-graph" {
			return fmt.Errorf("unsupported email provider type: %s (must be 'smtp' or 'microsoft-graph')", cfg.App.Email.Provider.Type)
		}
	}
	if cfg.App.OAuth.Enabled {
		if len(cfg.App.OAuth.Providers) == 0 {
			return fmt.Errorf("oauth auth requires at least one provider under [app.oauth.providers]")
		}
	}
	if cfg.App.TOTP.Enabled {
		if cfg.App.TOTP.Issuer == "" {
			return fmt.Errorf("totp auth requires an issuer")
		}
		if cfg.App.TOTP.Digits != 6 && cfg.App.TOTP.Digits != 8 {
			return fmt.Errorf("totp digits must be 6 or 8, got %d", cfg.App.TOTP.Digits)
		}
		if cfg.App.TOTP.Period == 0 {
			return fmt.Errorf("totp period must be > 0")
		}
	}
	return nil
}
