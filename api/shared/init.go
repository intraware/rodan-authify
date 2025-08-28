package shared

import (
	"time"

	"github.com/intraware/rodan-authify/internal/cache"
	"github.com/intraware/rodan-authify/internal/config"
	"github.com/intraware/rodan-authify/internal/models"
)

func Init(config *config.AppConfig) {
	ResetPasswordCache = cache.NewCache[string, models.User](&cache.CacheOpts{
		TimeToLive:    time.Duration(config.TokenExpiry) * time.Minute,
		CleanInterval: ptr(time.Hour * 2),
		Revaluate:     ptr(true),
	})
}
