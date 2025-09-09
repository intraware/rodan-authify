package api

import (
	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/api/auth"
	"github.com/intraware/rodan-authify/api/shared"
	"github.com/intraware/rodan-authify/api/team"
	"github.com/intraware/rodan-authify/api/user"
	"github.com/intraware/rodan-authify/internal/utils/values"
)

func LoadRoutes(r *gin.Engine) {
	apiRouter := r.Group("/api")

	auth.LoadAuth(apiRouter)
	team.LoadTeam(apiRouter)
	user.LoadUser(apiRouter)
	shared.Init(&values.GetConfig().App)
	apiRouter.GET("/ping", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"msg": "pong"})
	})
}
