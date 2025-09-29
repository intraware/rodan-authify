package shared

import (
	"github.com/intraware/rodan-authify/internal/cache"
	"github.com/intraware/rodan-authify/internal/models"
)

var UserCache cache.Cache[uint, models.User]
var TeamCache cache.Cache[uint, models.Team]
var LoginCache cache.Cache[string, models.User]
var ResetPasswordCache cache.Cache[string, models.User]
var BanHistoryCache cache.Cache[string, models.BanHistory]
var TOTPCache cache.Cache[string, models.UserTOTPMeta]
var OAuthCache cache.Cache[uint, models.UserOauthMeta]
