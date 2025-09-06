package team

import (
	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/internal/utils/middleware"
	"github.com/intraware/rodan-authify/internal/utils/values"
)

func LoadTeam(r *gin.RouterGroup) {
	teamRouter := r.Group("/team")

	teamRouter.GET("/:id", middleware.CacheMiddleware, getTeam)

	protectedRouter := teamRouter.Group("/", middleware.AuthRequired)
	protectedRouter.POST("/create", createTeam)
	protectedRouter.POST("/join/:id", joinTeam)
	protectedRouter.GET("/me", middleware.CacheMiddleware, getMyTeam)
	protectedRouter.PATCH("/edit", editTeam)
	protectedRouter.DELETE("/delete", deleteTeam)
	if values.GetConfig().App.AllowLeavingTeam {
		protectedRouter.POST("/leave", leaveTeam)
	}
}
