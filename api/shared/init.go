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
	})
	TeamCache = cache.NewCache[uint, models.Team](&cache.CacheOpts{
		TimeToLive:    3 * time.Minute,
		CleanInterval: ptr(time.Hour * 2),
		Revaluate:     ptr(true),
	})
	LoginCache = cache.NewCache[string, models.User](&cache.CacheOpts{
		TimeToLive:    2 * time.Minute,
		CleanInterval: ptr(time.Hour * 2),
		Revaluate:     ptr(true),
	})
	ResetPasswordCache = cache.NewCache[string, models.User](&cache.CacheOpts{
		TimeToLive:    time.Duration(config.TokenExpiry) * time.Minute,
		CleanInterval: ptr(time.Hour * 2),
		Revaluate:     ptr(true),
	})
	BanHistoryCache = cache.NewCache[string, models.BanHistory](&cache.CacheOpts{
		TimeToLive:    10 * time.Minute,
		CleanInterval: ptr(time.Hour * 2),
		Revaluate:     ptr(true),
	})
	TOTPCache = cache.NewCache[string, models.UserTOTPMeta](&cache.CacheOpts{
		TimeToLive:    3 * time.Minute,
		CleanInterval: ptr(time.Hour),
		Revaluate:     ptr(true),
	})
	OAuthCache = cache.NewCache[uint, models.UserOauthMeta](&cache.CacheOpts{
		TimeToLive:    3 * time.Minute,
		CleanInterval: ptr(time.Hour),
		Revaluate:     ptr(true),
	})
}
