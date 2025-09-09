package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/api/shared"
	"github.com/intraware/rodan-authify/internal/models"
	"github.com/intraware/rodan-authify/internal/types"
	"github.com/intraware/rodan-authify/internal/utils"
	"github.com/intraware/rodan-authify/internal/utils/values"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// signUp godoc
// @Summary      Sign up new user
// @Description  Registers a new user account in the system
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        user  body      signUpRequest   true  "User registration data"
// @Success      201   {object}  authResponse
// @Failure      400   {object}  types.ErrorResponse
// @Failure      409   {object}  types.ErrorResponse
// @Failure      500   {object}  types.ErrorResponse
// @Router       /auth/signup [post]
func signUp(ctx *gin.Context) {
	appCfg := values.GetConfig().App
	auditLog := utils.Logger.WithField("type", "audit")
	var req signUpRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":  "sign_up",
			"status": "failure",
			"reason": "invalid_json",
			"ip":     ctx.ClientIP(),
		}).Warn("Invalid signup input")
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Failed to parse the body"})
		return
	}
	if !appCfg.CompiledEmail.MatchString(req.Email) {
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Bad email ID provided"})
		return
	}
	var existingUser models.User
	if err := models.DB.Where("email = ?", req.Email).First(&existingUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) && !appCfg.AllowOutsideEmail {
			auditLog.WithFields(logrus.Fields{
				"event":    "sign_up",
				"status":   "failure",
				"reason":   "outside_email",
				"username": req.Username,
				"email":    req.Email,
				"ip":       ctx.ClientIP(),
			}).Warn("User tried to sign up with outside email")
			ctx.JSON(http.StatusForbidden, types.ErrorResponse{Error: "outside email not allowed"})
			return
		}
	}
	if existingUser.ID > 0 && existingUser.Active {
		auditLog.WithFields(logrus.Fields{
			"event":    "sign_up",
			"status":   "failure",
			"reason":   "user_already_active",
			"username": req.Username,
			"email":    req.Email,
			"ip":       ctx.ClientIP(),
		}).Warn("User already exists during signup")
		ctx.JSON(http.StatusConflict, types.ErrorResponse{Error: "User with same email or username or email exists"})
		return
	}
	var user models.User
	if existingUser.ID > 0 {
		existingUser.Username = req.Username
		existingUser.SetPassword(req.Password)
		existingUser.AvatarURL = req.AvatarURL
		existingUser.Active = true
		if err := models.DB.Save(&existingUser).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":    "sign_up",
				"status":   "failure",
				"reason":   "db_error",
				"username": req.Username,
				"email":    req.Email,
				"ip":       ctx.ClientIP(),
				"error":    err.Error(),
			}).Error("Failed to update user in DB during signup")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to create user"})
			return
		}
		user = existingUser
	} else if appCfg.AllowOutsideEmail {
		newUser := models.User{
			Username:  req.Username,
			Email:     req.Email,
			Password:  req.Password,
			AvatarURL: req.AvatarURL,
			Active:    true,
		}
		if err := models.DB.Create(&newUser).Error; err != nil {
			if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "UNIQUE") {
				auditLog.WithFields(logrus.Fields{
					"event":    "sign_up",
					"status":   "failure",
					"reason":   "duplicate_user",
					"username": req.Username,
					"email":    req.Email,
					"ip":       ctx.ClientIP(),
				}).Warn("User already exists during signup")
				ctx.JSON(http.StatusConflict, types.ErrorResponse{Error: "User with same email or username or email exists"})
				return
			}
			auditLog.WithFields(logrus.Fields{
				"event":    "sign_up",
				"status":   "failure",
				"reason":   "db_error",
				"username": req.Username,
				"email":    req.Email,
				"ip":       ctx.ClientIP(),
				"error":    err.Error(),
			}).Error("Failed to create user in DB during signup")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to create user"})
			return
		}
		user = newUser
	}
	token, err := utils.GenerateJWT(0, user.ID, user.Username, values.GetConfig().Server.Security.JWTSecret)
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "sign_up",
			"status":   "failure",
			"reason":   "token_generation_failed",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Failed to generate JWT token during signup")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to generate token"})
		return
	}
	userInfo := userInfo{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		AvatarURL: user.AvatarURL,
		TeamID:    user.TeamID,
	}
	auditLog.WithFields(logrus.Fields{
		"event":    "sign_up",
		"status":   "success",
		"user_id":  user.ID,
		"username": user.Username,
		"email":    user.Email,
		"ip":       ctx.ClientIP(),
	}).Info("User signed up successfully")
	ctx.JSON(http.StatusCreated, authResponse{
		Token: token,
		User:  userInfo,
	})
}

// login godoc
// @Summary      User login
// @Description  Authenticates a user and returns an access token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        credentials  body      loginRequest  true  "Login credentials"
// @Success      200          {object}  authResponse
// @Failure      400          {object}  types.ErrorResponse
// @Failure      401          {object}  types.ErrorResponse
// @Failure      403          {object}  types.ErrorResponse
// @Failure      500          {object}  types.ErrorResponse
// @Router       /auth/login [post]
func login(ctx *gin.Context) {
	auditLog := utils.Logger.WithField("type", "audit")
	var req loginRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":  "login",
			"status": "failure",
			"reason": "invalid_json",
			"ip":     ctx.ClientIP(),
		}).Warn("Invalid login input")
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Failed to parse request body"})
		return
	}
	var user models.User
	cacheHit := false
	if user, cacheHit := shared.LoginCache.Get(req.Username); cacheHit {
		if err := models.DB.Where("username = ?", req.Username).Preload("Team").First(&user).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				auditLog.WithFields(logrus.Fields{
					"event":    "login",
					"status":   "failure",
					"reason":   "user_not_found",
					"username": req.Username,
					"ip":       ctx.ClientIP(),
				}).Warn("User not found during login")
				ctx.JSON(http.StatusUnauthorized, types.ErrorResponse{Error: "Invalid username or password"})
				return
			}
			auditLog.WithFields(logrus.Fields{
				"event":    "login",
				"status":   "failure",
				"reason":   "db_error",
				"username": req.Username,
				"ip":       ctx.ClientIP(),
				"error":    err.Error(),
			}).Error("Database error during login")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Database error"})
			return
		} else {
			shared.LoginCache.Set(req.Username, user)
		}
	}
	if user.Ban {
		auditLog.WithFields(logrus.Fields{
			"event":    "login",
			"status":   "failure",
			"reason":   "banned",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
		}).Warn("Banned user attempted login")
		ctx.JSON(http.StatusForbidden, types.ErrorResponse{Error: "Account is banned"})
		return
	}
	if user.Team.Ban {
		auditLog.WithFields(logrus.Fields{
			"event":     "login",
			"status":    "failure",
			"reason":    "banned",
			"user_id":   user.ID,
			"username":  user.Username,
			"team_id":   user.Team.ID,
			"team_name": user.Team.Name,
			"ip":        ctx.ClientIP(),
		}).Warn("Banned user attempted login")
		ctx.JSON(http.StatusForbidden, types.ErrorResponse{Error: "Team is banned"})
		return
	}
	if !user.Active {
		auditLog.WithFields(logrus.Fields{
			"event":     "login",
			"status":    "failure",
			"reason":    "inactive",
			"user_id":   user.ID,
			"username":  user.Username,
			"team_id":   user.Team.ID,
			"team_name": user.Team.Name,
			"ip":        ctx.ClientIP(),
		}).Warn("Inactive user attempted login")
		ctx.JSON(http.StatusForbidden, types.ErrorResponse{Error: "User is not active"})
		return
	}
	isValid, err := user.ComparePassword(req.Password)
	if err != nil || !isValid {
		auditLog.WithFields(logrus.Fields{
			"event":    "login",
			"status":   "failure",
			"reason":   "invalid_password",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
			"error": func() string {
				if err != nil {
					return err.Error()
				} else {
					return ""
				}
			},
		}).Warn("Invalid password during login")
		ctx.JSON(http.StatusUnauthorized, types.ErrorResponse{Error: "Invalid username or password"})
		return
	}
	token, err := utils.GenerateJWT(*user.TeamID, user.ID, user.Username, values.GetConfig().Server.Security.JWTSecret)
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "login",
			"status":   "failure",
			"reason":   "token_generation_failed",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Failed to generate JWT token during login")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to generate token"})
		return
	}
	userInfo := userInfo{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		AvatarURL: user.AvatarURL,
		TeamID:    user.TeamID,
	}
	auditLog.WithFields(logrus.Fields{
		"event":    "login",
		"status":   "success",
		"user_id":  user.ID,
		"username": user.Username,
		"email":    user.Email,
		"ip":       ctx.ClientIP(),
		"cache":    cacheHit,
	}).Info("User logged in successfully")
	ctx.JSON(http.StatusOK, authResponse{
		Token: token,
		User:  userInfo,
	})
}
