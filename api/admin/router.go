package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/internal/config"
	"github.com/intraware/rodan-authify/internal/types"
)

func LoadAdminRouter(r *gin.RouterGroup, adminCfg config.AdminConfig) {
	adminRouter := r.Group(adminCfg.Endpoint)
	adminRouter.Use(func(ctx *gin.Context) {
		apiKeyHeader := ctx.GetHeader("x-api-key")
		if apiKeyHeader == "" {
			ctx.JSON(http.StatusUnauthorized, types.ErrorResponse{Error: "APIKey header is required"})
			ctx.Abort()
			return
		}
		if apiKeyHeader != adminCfg.HashedAPIKey {
			ctx.JSON(http.StatusUnauthorized, types.ErrorResponse{Error: "Invalid Token"})
			ctx.Abort()
			return
		}
		ctx.Next()
	})
	adminRouter.POST("/auth/login/close", closeLogin)
	adminRouter.POST("/auth/login/open", openLogin)
	adminRouter.POST("/auth/signup/close", closeSignup)
	adminRouter.POST("/auth/signup/open", oepnSignup)
}
