package auth

import (
	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/internal/utils/middleware"
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
		oauthRouter := authRouter.Group("/oauth")
		oauthRouter.GET("/:provider/login", oauthLogin)       // redirect to provider
		oauthRouter.GET("/:provider/callback", oauthCallback) // provider callback
		oauthRouter.GET("/:provider/link", middleware.AuthRequired, oauthLink)
		oauthRouter.GET("/:provider/link/callback", oauthLinkCallBack)
	}
}
