package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/api/shared"
	"github.com/intraware/rodan-authify/internal/types"
)

func closeLogin(ctx *gin.Context) {
	shared.SetLogin(false)
	ctx.JSON(http.StatusOK, types.SuccessResponse{Message: "Login closed for everyone"})
}
func openLogin(ctx *gin.Context) {
	shared.SetLogin(true)
	ctx.JSON(http.StatusOK, types.SuccessResponse{Message: "Login opened for everyone"})
}
func closeSignup(ctx *gin.Context) {
	shared.SetSignup(false)
	ctx.JSON(http.StatusOK, types.SuccessResponse{Message: "Signup closed for everyone"})
}
func openSignup(ctx *gin.Context) {
	shared.SetSignup(true)
	ctx.JSON(http.StatusOK, types.SuccessResponse{Message: "Signup opened for everyone"})
}
