package user

import (
	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/internal/utils/middleware"
	"github.com/intraware/rodan-authify/internal/utils/values"
)

func LoadUser(r *gin.RouterGroup) {
	userRouter := r.Group("/user")

	protectedRouter := userRouter.Group("/", middleware.AuthRequired)
	protectedRouter.GET("/me", middleware.CacheMiddleware, getMyProfile)
	protectedRouter.PATCH("/edit", updateProfile)
	protectedRouter.DELETE("/delete", deleteProfile)
	if values.GetConfig().App.TOTP.Enabled {
		protectedRouter.GET("/totp-qr", middleware.CacheMiddleware, profileTOTP)
		protectedRouter.GET("/backup-code", profileBackupCode)
	}
	userRouter.GET("/:id", middleware.CacheMiddleware, getUserProfile)
	if values.GetConfig().App.OAuth.Enabled {
		userRouter.GET("/providers", listOAuthProviders)
		protectedRouter.GET("/oauth", getUserOAuth)       // e.g. { provider: "github", username: "octocat" }
		protectedRouter.DELETE("/oauth", unlinkUserOAuth) // unlink OAuth (fallback to password if supported)
	}
}
