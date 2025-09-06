package user

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/api/shared"
	"github.com/intraware/rodan-authify/internal/models"
	"github.com/intraware/rodan-authify/internal/types"
	"github.com/intraware/rodan-authify/internal/utils"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func getMyProfile(ctx *gin.Context) {
	auditLog := utils.Logger.WithField("type", "audit")
	userID := ctx.GetInt("user_id")
	var user models.User
	cacheHit := false
	if user, cacheHit := shared.UserCache.Get(userID); !cacheHit {
		if err := models.DB.First(&user, userID).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":   "get_my_profile",
				"status":  "failure",
				"reason":  "user_not_found",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
			}).Warn("User not found in getMyProfile")
			ctx.JSON(http.StatusNotFound, types.ErrorResponse{Error: "User not found"})
			return
		} else {
			shared.UserCache.Set(user.ID, user)
		}
	}
	userInfo := userInfo{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		AvatarURL: user.AvatarURL,
		TeamID:    user.TeamID,
	}
	auditLog.WithFields(logrus.Fields{
		"event":    "get_my_profile",
		"status":   "success",
		"user_id":  user.ID,
		"username": user.Username,
		"ip":       ctx.ClientIP(),
		"cache":    cacheHit,
	}).Info("Fetched own profile")
	ctx.JSON(http.StatusOK, userInfo)
}

func getUserProfile(ctx *gin.Context) {
	auditLog := utils.Logger.WithField("type", "audit")
	userIDStr := ctx.Param("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":  "get_user_profile",
			"status": "failure",
			"reason": "invalid_user_id",
			"input":  userIDStr,
			"ip":     ctx.ClientIP(),
		}).Warn("Invalid user ID in getUserProfile")
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Invalid user ID"})
		return
	}
	var user models.User
	cacheHit := false
	if user, cacheHit := shared.UserCache.Get(userID); !cacheHit {
		if err := models.DB.First(&user, userID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				auditLog.WithFields(logrus.Fields{
					"event":   "get_user_profile",
					"status":  "failure",
					"reason":  "user_not_found",
					"user_id": userID,
					"ip":      ctx.ClientIP(),
				}).Warn("User not found in getUserProfile")
				ctx.JSON(http.StatusNotFound, types.ErrorResponse{Error: "User not found"})
				return
			}
			auditLog.WithFields(logrus.Fields{
				"event":   "get_user_profile",
				"status":  "failure",
				"reason":  "db_error",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
				"error":   err.Error(),
			}).Error("Database error in getUserProfile")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Database error"})
			return
		} else {
			shared.UserCache.Set(userID, user)
		}
	}
	userInfo := userInfo{
		ID:        user.ID,
		Username:  user.Username,
		AvatarURL: user.AvatarURL,
		TeamID:    user.TeamID,
	}
	auditLog.WithFields(logrus.Fields{
		"event":    "get_user_profile",
		"status":   "success",
		"user_id":  user.ID,
		"username": user.Username,
		"ip":       ctx.ClientIP(),
		"cache":    cacheHit,
	}).Info("Fetched other user's profile")
	ctx.JSON(http.StatusOK, userInfo)
}

func updateProfile(ctx *gin.Context) {
	auditLog := utils.Logger.WithField("type", "audit")
	userID := ctx.GetInt("user_id")
	var input updateUserRequest
	if err := ctx.ShouldBindJSON(&input); err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":   "update_profile",
			"status":  "failure",
			"reason":  "invalid_json",
			"user_id": userID,
			"ip":      ctx.ClientIP(),
		}).Warn("Invalid input in updateProfile")
		ctx.JSON(http.StatusBadRequest, types.ErrorResponse{Error: "Invalid input"})
		return
	}
	var user models.User
	cacheHit := false
	if user, cacheHit := shared.UserCache.Get(userID); !cacheHit {
		if err := models.DB.First(&user, userID).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":   "update_profile",
				"status":  "failure",
				"reason":  "user_not_found",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
			}).Warn("User not found in updateProfile")
			ctx.JSON(http.StatusNotFound, types.ErrorResponse{Error: "User not found"})
			return
		}
	}
	oldUsername := user.Username
	oldAvatarURL := user.AvatarURL
	if input.Username != nil {
		user.Username = *input.Username
	}
	if input.AvatarURL != nil {
		user.AvatarURL = *input.AvatarURL
	}
	if err := models.DB.Save(&user).Error; err != nil {
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate") {
			auditLog.WithFields(logrus.Fields{
				"event":        "update_profile",
				"status":       "failure",
				"reason":       "duplicate_username_or_github",
				"user_id":      user.ID,
				"old_username": oldUsername,
				"new_username": user.Username,
				"old_avatar":   oldAvatarURL,
				"new_avatar":   user.AvatarURL,
				"ip":           ctx.ClientIP(),
				"cache":        cacheHit,
				"error":        err.Error(),
			}).Warn("Username or AvatarURL already in use in updateProfile")
			ctx.JSON(http.StatusConflict, types.ErrorResponse{Error: "Username or AvatarURL already in use"})
			return
		}
		auditLog.WithFields(logrus.Fields{
			"event":   "update_profile",
			"status":  "failure",
			"reason":  "db_error",
			"user_id": user.ID,
			"ip":      ctx.ClientIP(),
			"error":   err.Error(),
		}).Error("Failed to update profile in DB")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to update profile"})
		return
	}
	shared.UserCache.Delete(userID)
	auditLog.WithFields(logrus.Fields{
		"event":        "update_profile",
		"status":       "success",
		"user_id":      user.ID,
		"old_username": oldUsername,
		"new_username": user.Username,
		"old_avatar":   oldAvatarURL,
		"new_avatar":   user.AvatarURL,
		"ip":           ctx.ClientIP(),
		"cache":        cacheHit,
	}).Info("Profile updated successfully")
	ctx.JSON(http.StatusOK, types.SuccessResponse{Message: "Profile updated successfully"})
}

func deleteProfile(ctx *gin.Context) {
	auditLog := utils.Logger.WithField("type", "audit")
	userID := ctx.GetInt("user_id")
	result := models.DB.Delete(&models.User{}, userID)
	if result.Error != nil {
		auditLog.WithFields(logrus.Fields{
			"event":   "delete_profile",
			"status":  "failure",
			"reason":  "db_error",
			"user_id": userID,
			"ip":      ctx.ClientIP(),
			"error":   result.Error.Error(),
		}).Error("Failed to delete user in deleteProfile")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Internal server error"})
		return
	}
	shared.UserCache.Delete(userID)
	if result.RowsAffected == 0 {
		auditLog.WithFields(logrus.Fields{
			"event":   "delete_profile",
			"status":  "failure",
			"reason":  "not_found_or_already_deleted",
			"user_id": userID,
			"ip":      ctx.ClientIP(),
		}).Warn("User not found or already deleted in deleteProfile")
		ctx.JSON(http.StatusNotFound, types.ErrorResponse{Error: "User not found or already deleted"})
		return
	}
	auditLog.WithFields(logrus.Fields{
		"event":   "delete_profile",
		"status":  "success",
		"user_id": userID,
		"ip":      ctx.ClientIP(),
	}).Info("User deleted successfully")
	ctx.JSON(http.StatusOK, types.SuccessResponse{Message: "User deleted successfully"})
}
