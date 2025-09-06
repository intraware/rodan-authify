package user

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/api/shared"
	"github.com/intraware/rodan-authify/internal/cache"
	"github.com/intraware/rodan-authify/internal/models"
	"github.com/intraware/rodan-authify/internal/types"
	"github.com/intraware/rodan-authify/internal/utils"
	"github.com/sirupsen/logrus"
	"github.com/skip2/go-qrcode"
)

func ptr[T any](v T) *T { return &v }

var TOTPCache = cache.NewCache[int, models.UserTOTPMeta](&cache.CacheOpts{
	TimeToLive:    3 * time.Minute,
	CleanInterval: ptr(time.Hour),
	Revaluate:     ptr(true),
})

func profileTOTP(ctx *gin.Context) {
	auditLog := utils.Logger.WithField("type", "audit")
	userID := ctx.GetInt("user_id")
	var user models.User
	cacheHit := false
	if user, cacheHit = shared.UserCache.Get(userID); !cacheHit {
		if err := models.DB.First(&user, userID).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":   "profile_totp",
				"status":  "failure",
				"reason":  "db_error",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
				"error":   err.Error(),
			}).Error("Failed to fetch user in profileTOTP")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to fetch user"})
			return
		}
		shared.UserCache.Set(userID, user)
	}
	var userTotp models.UserTOTPMeta
	if userTotp, ok := TOTPCache.Get(user.ID); !ok {
		if err := models.DB.Where("user_id = ?", user.ID).First(&userTotp).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":   "profile_totp",
				"status":  "failure",
				"reason":  "db_error",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
				"error":   err.Error(),
			}).Error("Failed to fetch user data in TOTP Metadata")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to fetch user"})
			return
		}
		TOTPCache.Set(user.ID, userTotp)
	}
	totpURL, _ := userTotp.TOTPUrl()
	png, err := qrcode.Encode(totpURL, qrcode.Medium, 256)
	if err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":   "profile_totp",
			"status":  "failure",
			"reason":  "qrcode_generation_failed",
			"user_id": userID,
			"ip":      ctx.ClientIP(),
			"error":   err.Error(),
		}).Error("Failed to generate QR code in profileTOTP")
		ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to generate QR code"})
		return
	}
	auditLog.WithFields(logrus.Fields{
		"event":   "profile_totp",
		"status":  "success",
		"user_id": userID,
		"ip":      ctx.ClientIP(),
		"cache":   cacheHit,
	}).Info("TOTP QR code generated for profile")
	ctx.Header("Content-Type", "image/png")
	ctx.Writer.Write(png)
}

func profileBackupCode(ctx *gin.Context) {
	auditLog := utils.Logger.WithField("type", "audit")
	userID := ctx.GetInt("user_id")
	var user models.User
	cacheHit := false
	if user, cacheHit = shared.UserCache.Get(userID); !cacheHit {
		if err := models.DB.First(&user, userID).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":   "profile_backup_code",
				"status":  "failure",
				"reason":  "db_error",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
				"error":   err.Error(),
			}).Error("Failed to fetch user in profileBackupCode")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to fetch user"})
			return
		}
		shared.UserCache.Set(userID, user)
	}
	var userTotp models.UserTOTPMeta
	if userTotp, ok := TOTPCache.Get(user.ID); !ok {
		if err := models.DB.Where("user_id = ?", user.ID).First(&userTotp).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":   "profile_totp",
				"status":  "failure",
				"reason":  "db_error",
				"user_id": userID,
				"ip":      ctx.ClientIP(),
				"error":   err.Error(),
			}).Error("Failed to fetch user data in TOTP Metadata")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to fetch user"})
			return
		}
		TOTPCache.Set(user.ID, userTotp)
	}
	auditLog.WithFields(logrus.Fields{
		"event":   "profile_backup_code",
		"status":  "success",
		"user_id": userID,
		"ip":      ctx.ClientIP(),
		"cache":   cacheHit,
	}).Info("Fetched backup code for profile")
	ctx.JSON(http.StatusOK, gin.H{"backup_code": userTotp.BackupCode})
}
