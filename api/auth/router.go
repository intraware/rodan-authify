package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/internal/utils/values"
)

func LoadAuth(r *gin.RouterGroup) {
	authRouter := r.Group("/auth")
	authRouter.POST("/signup", signUp)
	authRouter.POST("/login", login)
	cfg := values.GetConfig().App
	if cfg.Email.Enabled && cfg.TOTP.Enabled {
		authRouter.POST("/forgot-password", forgotPassword)
		authRouter.POST("/reset-password/:token", resetPassword)
	}
	if cfg.OAuth.Enabled {
		authRouter.GET("/oauth/login", oauthLogin)       // redirect to provider
		authRouter.GET("/oauth/callback", oauthCallback) // provider callback
		authRouter.GET("/oauth/logout", oauthLogout)     // optional logout handler
	}
}
