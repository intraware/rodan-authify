package user

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/api/shared"
	"github.com/intraware/rodan-authify/internal/models"
	"github.com/intraware/rodan-authify/internal/types"
	"github.com/intraware/rodan-authify/internal/utils"
	"github.com/intraware/rodan-authify/internal/utils/values"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func listOAuthProviders(ctx *gin.Context) {
	oauthCfg := values.GetConfig().App.OAuth
	keys := make([]string, 0, len(oauthCfg.Providers))
	for k := range oauthCfg.Providers {
		keys = append(keys, k)
	}
	ctx.JSON(http.StatusOK, providersList{Providers: keys})
}

func getUserOAuth(ctx *gin.Context) {
	auditLog := utils.Logger.WithField("type", "audit")
	userID := ctx.GetUint("user_id")
	var user models.User
	cacheHit := false
	if user, cacheHit = shared.UserCache.Get(userID); !cacheHit {
		if err := models.DB.First(&user, userID).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":   "get_user_oauth",
				"status":  "failure",
				"reason":  "db_error",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
				"error":   err.Error(),
			}).Error("Failed to fetch user in getUserOAuth")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to get the user"})
			return
		}
		shared.UserCache.Set(userID, user)
	}
	var userOauth models.UserOauthMeta
	var ok bool
	if userOauth, ok = shared.OAuthCache.Get(user.ID); !ok {
		if err := models.DB.Where("user_id = ?", user.ID).First(&userOauth).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				ctx.JSON(http.StatusOK, gin.H{"oauth": nil})
				return
			}
			auditLog.WithFields(logrus.Fields{
				"event":   "get_user_oauth",
				"status":  "failure",
				"reason":  "db_error",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
				"error":   err.Error(),
			}).Error("Failed to fetch oauth metadta in getUserOAuth")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to get the user oauth metadata"})
			return
		}
		shared.OAuthCache.Set(user.ID, userOauth)
	}
	ctx.JSON(http.StatusOK, gin.H{
		"provider":   userOauth.Provider,
		"providerId": userOauth.ProviderID,
		"expiry":     userOauth.Expiry,
	})
}

func unlinkUserOAuth(ctx *gin.Context) {
	auditLog := utils.Logger.WithField("type", "audit")
	userID := ctx.GetUint("user_id")
	var user models.User
	if user, cacheHit := shared.UserCache.Get(userID); !cacheHit {
		if err := models.DB.First(&user, userID).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":   "unlink_user_oauth",
				"status":  "failure",
				"reason":  "db_error",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
				"error":   err.Error(),
			}).Error("Failed to fetch user in unlinkUserOAuth")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to get the user"})
			return
		}
		shared.UserCache.Set(userID, user)
	}
	var userOauth models.UserOauthMeta
	var ok bool
	if userOauth, ok = shared.OAuthCache.Get(user.ID); !ok {
		if err := models.DB.Where("user_id = ?", user.ID).First(&userOauth).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":   "unlink_user_oauth",
				"status":  "failure",
				"reason":  "db_error",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
				"error":   err.Error(),
			}).Error("Failed to fetch oauth metadata in unlinkUserOAuth")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to get the user oauth metadata"})
			return
		}
		shared.OAuthCache.Set(user.ID, userOauth)
	}
	err := models.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(&userOauth).Error; err != nil {
			return fmt.Errorf("delete_user_oauth: %w", err)
		}
		user.Active = false
		if err := tx.Model(&user).Update("active", false).Error; err != nil {
			return fmt.Errorf("update_user: %w", err)
		}
		return nil
	})
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":   "unlink_user_oauth",
			"status":  "failure",
			"user_id": userID,
			"ip":      ctx.ClientIP(),
			"error":   err.Error(),
		}).Error("Failed to unlink oauth account in transaction")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to unlink oauth account"})
		return
	}
	shared.OAuthCache.Delete(user.ID)
	shared.UserCache.Delete(user.ID)
	auditLog.WithFields(logrus.Fields{
		"event":   "unlink_user_oauth",
		"status":  "success",
		"user_id": userID,
		"ip":      ctx.ClientIP(),
	}).Info("Successfully unlinked oauth account")
	ctx.JSON(http.StatusOK, types.SuccessResponse{Message: "OAuth account unlinked successfully"})
}
