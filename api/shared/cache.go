package shared

import (
	"time"

	"github.com/intraware/rodan-authify/internal/cache"
	"github.com/intraware/rodan-authify/internal/models"
)

var UserCache = cache.NewCache[int, models.User](&cache.CacheOpts{
	TimeToLive:    3 * time.Minute,
	CleanInterval: ptr(time.Hour * 2),
	Revaluate:     ptr(true),
})

var TeamCache = cache.NewCache[int, models.Team](&cache.CacheOpts{
	TimeToLive:    3 * time.Minute,
	CleanInterval: ptr(time.Hour * 2),
	Revaluate:     ptr(true),
})

var LoginCache = cache.NewCache[string, models.User](&cache.CacheOpts{
	TimeToLive:    2 * time.Minute,
	CleanInterval: ptr(time.Hour * 2),
	Revaluate:     ptr(true),
})

var ResetPasswordCache cache.Cache[string, models.User]

func ptr[T any](v T) *T { return &v }
