package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/api/shared"
	"github.com/intraware/rodan-authify/internal/models"
	"github.com/intraware/rodan-authify/internal/types"
	"github.com/intraware/rodan-authify/internal/utils"
	"github.com/intraware/rodan-authify/internal/utils/values"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

func oauthLogin(ctx *gin.Context) {
	oauthCfg := values.GetConfig().App.OAuth
	auditLog := utils.Logger.WithField("type", "audit")
	providerName := ctx.Param("provider")
	if !oauthCfg.Enabled {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_login",
			"status":   "failure",
			"reason":   "oauth_disabled",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
		}).Warn("OAuth is not enabled in config")
		ctx.JSON(http.StatusForbidden, types.ErrorResponse{Error: "OAuth is not enabled in config"})
		return
	}
	if _, ok := oauthCfg.Providers[providerName]; !ok {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_login",
			"status":   "failure",
			"reason":   "unsupported_provider",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
		}).Warn("Unsupported OAuth provider")
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Unsupported OAuth provider"})
		return
	}
	conf := buildOAuthConfig(providerName, &oauthCfg)
	random := make([]byte, 64)
	if _, err := rand.Read(random); err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_login",
			"status":   "failure",
			"reason":   "state_generation_failed",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Failed to generate state config")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to generate state config"})
		return
	}
	state := fmt.Sprintf("login:%s", hex.EncodeToString(random))
	authURL := conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	shared.OauthStateCache.Set(state, struct{}{})
	auditLog.WithFields(logrus.Fields{
		"event":    "oauth_login",
		"status":   "success",
		"provider": providerName,
		"ip":       ctx.ClientIP(),
	}).Info("OAuth login initiated")
	ctx.Redirect(http.StatusFound, authURL)
}

func oauthCallback(ctx *gin.Context) {
	cfg := values.GetConfig()
	appCfg := cfg.App
	oauthCfg := appCfg.OAuth
	secretCfg := cfg.Server.Security
	auditLog := utils.Logger.WithField("type", "audit")
	providerName := ctx.Param("provider")
	conf := buildOAuthConfig(providerName, &oauthCfg)
	state := ctx.Query("state")
	if _, ok := shared.OauthStateCache.Get(state); !ok {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_callback",
			"status":   "failure",
			"reason":   "invalid_state",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
		}).Warn("Invalid or expired state")
		ctx.JSON(http.StatusForbidden, types.ErrorResponse{Error: "Not authorized"})
		return
	}
	shared.OauthStateCache.Delete(state)
	code := ctx.Query("code")
	if code == "" {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_callback",
			"status":   "failure",
			"reason":   "missing_code",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
		}).Warn("Missing code in callback")
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Missing code in callback"})
		return
	}
	token, err := conf.Exchange(ctx, code)
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_callback",
			"status":   "failure",
			"reason":   "token_exchange_failed",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Failed to exchange code for token")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to exchange code for token"})
		return
	}
	client := conf.Client(ctx, token)
	userModel, providerID, err := buildUserModel(client, oauthCfg.Providers[providerName])
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":      "oauth_callback",
			"status":     "failure",
			"reason":     "fetch_user_data_failed",
			"provider":   providerName,
			"ip":         ctx.ClientIP(),
			"error":      err.Error(),
			"providerID": providerID,
		}).Error("Failed to fetch user data from provider")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to fetch user data from provider"})
		return
	}
	var user models.User
	err = models.DB.Transaction(func(tx *gorm.DB) error {
		var existingUser models.User
		if err := tx.Where("email = ?", userModel.Email).First(&existingUser).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) && !appCfg.AllowOutsideEmail {
				return fmt.Errorf("outside emails are not allowed")
			}
		}
		oauthMeta := models.UserOauthMeta{
			Provider:     providerName,
			ProviderID:   providerID,
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			Expiry:       token.Expiry,
		}
		if existingUser.ID > 0 && existingUser.Active {
			var linkedOAuth models.UserOauthMeta
			err := tx.Where("provider = ? AND provider_id = ?", providerName, providerID).First(&linkedOAuth).Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
					return fmt.Errorf("OAuth account not linked. Please link it first before logging in")
				}
				return fmt.Errorf("failed to fetch OAuth details")
			}
			user = existingUser
		} else if existingUser.ID > 0 {
			existingUser.Username = userModel.Username
			existingUser.AvatarURL = userModel.AvatarURL
			existingUser.Active = true
			if err := tx.Save(&existingUser).Error; err != nil {
				return fmt.Errorf("failed to update user")
			}
			oauthMeta.UserID = existingUser.ID
			if err := tx.Create(&oauthMeta).Error; err != nil {
				return fmt.Errorf("failed to link OAuth account")
			}
			user = existingUser
		} else if appCfg.AllowOutsideEmail {
			newUser := models.User{
				Username:  userModel.Username,
				Email:     userModel.Email,
				AvatarURL: userModel.AvatarURL,
				Active:    true,
			}
			if err := tx.Create(&newUser).Error; err != nil {
				return fmt.Errorf("failed to create user")
			}
			oauthMeta.UserID = newUser.ID
			if err := tx.Create(&oauthMeta).Error; err != nil {
				return fmt.Errorf("failed to link OAuth account")
			}
			user = newUser
		} else {
			return fmt.Errorf("registration not allowed")
		}
		return nil
	})
	if err != nil {
		status := "failure"
		reason := "unknown"
		if err.Error() == "outside emails are not allowed" || err.Error() == "registration not allowed" || err.Error() == "OAuth account not linked. Please link it first before logging in" {
			reason = err.Error()
		} else {
			reason = "db_error"
		}
		auditLog.WithFields(logrus.Fields{
			"event":      "oauth_callback",
			"status":     status,
			"reason":     reason,
			"provider":   providerName,
			"email":      userModel.Email,
			"username":   userModel.Username,
			"providerID": providerID,
			"ip":         ctx.ClientIP(),
			"error":      err.Error(),
		}).Warn("OAuth callback failure")
		if reason == "db_error" {
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: err.Error()})
		} else {
			ctx.JSON(http.StatusForbidden, types.ErrorResponse{Error: err.Error()})
		}
		return
	}
	var teamID uint
	if user.TeamID != nil {
		teamID = *user.TeamID
	}
	jwtToken, err := utils.GenerateJWT(teamID, user.ID, user.Username, secretCfg.JWTSecret)
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_callback",
			"status":   "failure",
			"reason":   "token_generation_failed",
			"user_id":  user.ID,
			"provider": providerName,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Failed to generate JWT token after OAuth callback")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to generate token"})
		return
	}
	userInfo := userInfo{
		ID:        user.ID,
		Username:  user.Username,
		AvatarURL: user.AvatarURL,
		TeamID:    user.TeamID,
	}
	auditLog.WithFields(logrus.Fields{
		"event":      "oauth_callback",
		"status":     "success",
		"user_id":    user.ID,
		"email":      user.Email,
		"username":   user.Username,
		"provider":   providerName,
		"providerID": providerID,
		"ip":         ctx.ClientIP(),
	}).Info("OAuth login successful")
	ctx.JSON(http.StatusOK, authResponse{
		Token: jwtToken,
		User:  userInfo,
	})
}

func oauthLink(ctx *gin.Context) {
	oauthCfg := values.GetConfig().App.OAuth
	auditLog := utils.Logger.WithField("type", "audit")
	providerName := ctx.Param("provider")

	if !oauthCfg.Enabled {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_link",
			"status":   "failure",
			"reason":   "oauth_disabled",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
		}).Warn("OAuth is not enabled in config")
		ctx.JSON(http.StatusForbidden, types.ErrorResponse{Error: "OAuth is not enabled in config"})
		return
	}
	if _, ok := oauthCfg.Providers[providerName]; !ok {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_link",
			"status":   "failure",
			"reason":   "unsupported_provider",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
		}).Warn("Unsupported OAuth provider")
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Unsupported OAuth provider"})
		return
	}
	conf := buildOauthLinkConfig(providerName, &oauthCfg)
	random := make([]byte, 64)
	if _, err := rand.Read(random); err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_link",
			"status":   "failure",
			"reason":   "state_generation_failed",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Failed to generate state config")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to generate state config"})
		return
	}
	userID := ctx.GetUint("user_id")
	state := fmt.Sprintf("link:%s:%d:%s", providerName, userID, hex.EncodeToString(random))
	authURL := conf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	shared.OauthStateCache.Set(state, struct{}{})
	auditLog.WithFields(logrus.Fields{
		"event":    "oauth_link",
		"status":   "success",
		"provider": providerName,
		"user_id":  userID,
		"ip":       ctx.ClientIP(),
	}).Info("OAuth link initiated")
	ctx.Redirect(http.StatusFound, authURL)
}

func oauthLinkCallBack(ctx *gin.Context) {
	oauthCfg := values.GetConfig().App.OAuth
	auditLog := utils.Logger.WithField("type", "audit")
	providerName := ctx.Param("provider")
	conf := buildOauthLinkConfig(providerName, &oauthCfg)
	state := ctx.Query("state")
	if _, ok := shared.OauthStateCache.Get(state); !ok {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_link_callback",
			"status":   "failure",
			"reason":   "invalid_state",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
		}).Warn("Invalid or expired state")
		ctx.JSON(http.StatusForbidden, types.ErrorResponse{Error: "Invalid or expired state"})
		return
	}
	shared.OauthStateCache.Delete(state)
	parts := strings.Split(state, ":")
	if len(parts) < 4 {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_link_callback",
			"status":   "failure",
			"reason":   "invalid_state_format",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
		}).Warn("Invalid state format")
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Invalid state format"})
		return
	}
	userID, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_link_callback",
			"status":   "failure",
			"reason":   "invalid_user_id",
			"provider": providerName,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Warn("Invalid user ID in state")
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Invalid user ID in state"})
		return
	}
	code := ctx.Query("code")
	if code == "" {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_link_callback",
			"status":   "failure",
			"reason":   "missing_code",
			"provider": providerName,
			"user_id":  userID,
			"ip":       ctx.ClientIP(),
		}).Warn("Missing code in callback")
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Missing code in callback"})
		return
	}
	token, err := conf.Exchange(ctx, code)
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_link_callback",
			"status":   "failure",
			"reason":   "token_exchange_failed",
			"provider": providerName,
			"user_id":  userID,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Failed to exchange code for token")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to exchange code for token"})
		return
	}
	client := conf.Client(ctx, token)
	_, providerID, err := buildUserModel(client, oauthCfg.Providers[providerName])
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":      "oauth_link_callback",
			"status":     "failure",
			"reason":     "fetch_user_data_failed",
			"provider":   providerName,
			"user_id":    userID,
			"ip":         ctx.ClientIP(),
			"error":      err.Error(),
			"providerID": providerID,
		}).Error("Failed to fetch provider user data")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to fetch provider user data"})
		return
	}
	var existingMeta models.UserOauthMeta
	if err := models.DB.Where("provider = ? AND provider_id = ?", providerName, providerID).First(&existingMeta).Error; err == nil {
		auditLog.WithFields(logrus.Fields{
			"event":      "oauth_link_callback",
			"status":     "failure",
			"reason":     "already_linked",
			"provider":   providerName,
			"user_id":    userID,
			"ip":         ctx.ClientIP(),
			"providerID": providerID,
		}).Warn("OAuth account already linked to another user")
		ctx.JSON(http.StatusConflict, types.ErrorResponse{Error: "This OAuth account is already linked to another user"})
		return
	} else if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		auditLog.WithFields(logrus.Fields{
			"event":    "oauth_link_callback",
			"status":   "failure",
			"reason":   "db_error",
			"provider": providerName,
			"user_id":  userID,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Database error during OAuth link callback")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Database error"})
		return
	}
	oauthMeta := models.UserOauthMeta{
		UserID:       uint(userID),
		Provider:     providerName,
		ProviderID:   providerID,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Expiry:       token.Expiry,
	}
	if err := models.DB.Create(&oauthMeta).Error; err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":      "oauth_link_callback",
			"status":     "failure",
			"reason":     "link_failed",
			"provider":   providerName,
			"user_id":    userID,
			"ip":         ctx.ClientIP(),
			"error":      err.Error(),
			"providerID": providerID,
		}).Error("Failed to link OAuth account")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to link OAuth account"})
		return
	}
	auditLog.WithFields(logrus.Fields{
		"event":      "oauth_link_callback",
		"status":     "success",
		"provider":   providerName,
		"user_id":    userID,
		"ip":         ctx.ClientIP(),
		"providerID": providerID,
	}).Info("OAuth account linked successfully")
	ctx.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Successfully linked %s account", providerName),
		"user_id": userID,
	})
}
