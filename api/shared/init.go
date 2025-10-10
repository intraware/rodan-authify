package shared

import (
	"time"

	"github.com/intraware/rodan-authify/internal/cache"
	"github.com/intraware/rodan-authify/internal/config"
	"github.com/intraware/rodan-authify/internal/models"
)

func ptr[T any](v T) *T { return &v }

func Init(config *config.AppConfig) {
	UserCache = cache.NewCache[uint, models.User](&cache.CacheOpts{
		TimeToLive:    3 * time.Minute,
		CleanInterval: ptr(time.Hour * 2),
		Revaluate:     ptr(true),
		Prefix:        "user-cache",
	})
	TeamCache = cache.NewCache[uint, models.Team](&cache.CacheOpts{
		TimeToLive:    3 * time.Minute,
		CleanInterval: ptr(time.Hour * 2),
		Revaluate:     ptr(true),
		Prefix:        "team-cache",
	})
	LoginCache = cache.NewCache[string, models.User](&cache.CacheOpts{
		TimeToLive:    2 * time.Minute,
		CleanInterval: ptr(time.Hour * 2),
		Revaluate:     ptr(true),
		Prefix:        "login-cache",
	})
	ResetPasswordCache = cache.NewCache[string, models.User](&cache.CacheOpts{
		TimeToLive:    time.Duration(config.TokenExpiry) * time.Minute,
		CleanInterval: ptr(time.Hour * 2),
		Revaluate:     ptr(true),
		Prefix:        "reset-password-cache",
	})
	BanHistoryCache = cache.NewCache[string, models.BanHistory](&cache.CacheOpts{
		TimeToLive:    10 * time.Minute,
		CleanInterval: ptr(time.Hour * 2),
		Revaluate:     ptr(true),
		Prefix:        "ban-history-cache",
	})
	TOTPCache = cache.NewCache[string, models.UserTOTPMeta](&cache.CacheOpts{
		TimeToLive:    3 * time.Minute,
		CleanInterval: ptr(time.Hour),
		Revaluate:     ptr(true),
		Prefix:        "totp-cache",
	})
	OAuthCache = cache.NewCache[uint, models.UserOauthMeta](&cache.CacheOpts{
		TimeToLive:    3 * time.Minute,
		CleanInterval: ptr(time.Hour),
		Revaluate:     ptr(true),
		Prefix:        "oauth-cache",
	})
	OauthStateCache = cache.NewCache[string, struct{}](&cache.CacheOpts{
		TimeToLive:    5 * time.Minute,
		CleanInterval: ptr(time.Hour),
		Revaluate:     ptr(false),
		Prefix:        "oauth-state-cache",
	})
}

func init() {
	allowLogin.Store(true)
	allowSignUp.Store(true)
}
