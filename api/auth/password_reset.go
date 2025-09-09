package auth

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/intraware/rodan-authify/api/shared"
	"github.com/intraware/rodan-authify/internal/models"
	"github.com/intraware/rodan-authify/internal/types"
	"github.com/intraware/rodan-authify/internal/utils"
	"github.com/intraware/rodan-authify/internal/utils/values"
	"github.com/sirupsen/logrus"
)

// forgotPassword godoc
// @Summary      Forgot password
// @Description  Initiates password reset process using email, OTP, or backup code.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        type     query     string                   false  "Reset method (email or totp)" Enums(email, totp) default(email)
// @Param        request  body      forgotPasswordRequest    true   "Forgot password request"
// @Success      200      {object}  resetTokenResponse
// @Failure      400      {object}  types.ErrorResponse
// @Failure      401      {object}  types.ErrorResponse
// @Failure      404      {object}  types.ErrorResponse
// @Failure      500      {object}  types.ErrorResponse
// @Router       /auth/forgot-password [post]
func forgotPassword(ctx *gin.Context) {
	var input forgotPasswordRequest
	appCfg := values.GetConfig().App
	var user models.User
	auditLog := utils.Logger.WithField("type", "audit")
	resetType := ctx.DefaultQuery("type", "email")
	if resetType == "email" && !appCfg.Email.Enabled {
		auditLog.WithFields(logrus.Fields{
			"event":     "forgot_password",
			"status":    "failure",
			"reason":    "email_service_disabled",
			"resetType": resetType,
			"ip":        ctx.ClientIP(),
		}).Warn("Email service not enabled")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Email service is not enabled"})
		return
	} else if resetType == "totp" && !appCfg.TOTP.Enabled {
		auditLog.WithFields(logrus.Fields{
			"event":     "forgot_password",
			"status":    "failure",
			"reason":    "totp_service_disabled",
			"resetType": resetType,
			"ip":        ctx.ClientIP(),
		}).Warn("TOTP service not enabled")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "TOTP service is not enabled"})
		return
	}
	if err := ctx.ShouldBindJSON(&input); err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":  "forgot_password",
			"status": "failure",
			"reason": "invalid_json",
			"ip":     ctx.ClientIP(),
		}).Warn("Invalid forgot password input")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	var otpSet, backupSet bool
	if resetType == "totp" {
		otpSet = input.OTP != nil && *input.OTP != ""
		backupSet = input.BackupCode != nil && *input.BackupCode != ""
		if (otpSet && backupSet) || (!otpSet && !backupSet) {
			auditLog.WithFields(logrus.Fields{
				"event":    "forgot_password",
				"status":   "failure",
				"reason":   "invalid_auth_method_selection",
				"username": input.Username,
				"ip":       ctx.ClientIP(),
			}).Warn("Invalid OTP/Backup Code usage")
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Provide either OTP or Backup Code, not both"})
			return
		}
	}
	var ok bool
	if user, ok = shared.LoginCache.Get(input.Username); ok {
		ctx.Set("message", fmt.Sprintf("User %d loaded from login cache", user.ID))
		auditLog.WithFields(logrus.Fields{
			"event":    "forgot_password",
			"status":   "info",
			"reason":   "cache_hit",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
		}).Info("User loaded from cache for password reset")
	} else {
		if err := models.DB.Where("username = ?", input.Username).First(&user).Error; err != nil {
			ctx.Set("message", err.Error())
			auditLog.WithFields(logrus.Fields{
				"event":    "forgot_password",
				"status":   "failure",
				"reason":   "user_not_found",
				"username": input.Username,
				"ip":       ctx.ClientIP(),
			}).Warn("User not found for forgot password")
			ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
			return
		}
	}
	if resetType == "email" {
		token, err := generateResetToken()
		if err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":    "forgot_password",
				"status":   "failure",
				"reason":   "token_generation_failed",
				"user_id":  user.ID,
				"username": user.Username,
				"ip":       ctx.ClientIP(),
				"error":    err.Error(),
			}).Error("Failed to generate password reset token")
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}
		shared.ResetPasswordCache.Set(token, user)
		if err := sendResetToken(user.Email, token); err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":    "forgot_password",
				"status":   "failure",
				"method":   "email",
				"username": user.Username,
				"email":    user.Email,
				"reason":   "send_email_failed",
				"ip":       ctx.ClientIP(),
			}).Error("Failed to send password reset email")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{
				Error: "Failed to send the email",
			})
			return
		}
		auditLog.WithFields(logrus.Fields{
			"event":    "forgot_password",
			"status":   "success",
			"method":   "email",
			"username": user.Username,
			"email":    user.Email,
			"ip":       ctx.ClientIP(),
		}).Info("Password reset email sent successfully")
		ctx.JSON(http.StatusOK, types.SuccessResponse{
			Message: "Reset token sent successfully to the mail",
		})
		return
	}
	var userTOTP models.UserTOTPMeta
	if userTOTP, ok = shared.TOTPCache.Get(user.Username); !ok {
		if err := models.DB.Where("user_id = ?", user.ID).First(&userTOTP).Error; err != nil {
			auditLog.WithFields(logrus.Fields{
				"event":   "profile_totp",
				"status":  "failure",
				"reason":  "db_error",
				"user_id": user.ID,
				"ip":      ctx.ClientIP(),
				"error":   err.Error(),
			}).Error("Failed to fetch user data in TOTP Metadata")
			ctx.JSON(http.StatusInternalServerError, types.ErrorResponse{Error: "Failed to fetch user"})
			return
		}
		shared.TOTPCache.Set(user.Username, userTOTP)
	}
	if otpSet && userTOTP.VerifyTOTP(*input.OTP) {
		ctx.Set("message", fmt.Sprintf("User %d resetting password using TOTP", user.ID))
		auditLog.WithFields(logrus.Fields{
			"event":    "forgot_password_auth",
			"status":   "success",
			"method":   "totp",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
		}).Info("Password reset authorized via TOTP")
	} else if backupSet && userTOTP.BackupCode == *input.BackupCode {
		ctx.Set("message", fmt.Sprintf("User %d resetting password using Backup code", user.ID))
		auditLog.WithFields(logrus.Fields{
			"event":    "forgot_password_auth",
			"status":   "success",
			"method":   "backup_code",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
		}).Info("Password reset authorized via Backup Code")
	} else {
		errMsg := "Invalid credentials"
		method := "unknown"
		if otpSet {
			errMsg = "Invalid OTP"
			method = "totp"
		} else if backupSet {
			errMsg = "Invalid Backup Code"
			method = "backup_code"
		}
		auditLog.WithFields(logrus.Fields{
			"event":    "forgot_password_auth",
			"status":   "failure",
			"reason":   "invalid_" + method,
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
		}).Warn("Failed password reset authentication")
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": errMsg})
		return
	}
	token, err := generateResetToken()
	if err != nil {
		ctx.Set("message", err.Error())
		auditLog.WithFields(logrus.Fields{
			"event":    "forgot_password",
			"status":   "failure",
			"reason":   "token_generation_failed",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Failed to generate password reset token")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	shared.ResetPasswordCache.Set(token, user)
	auditLog.WithFields(logrus.Fields{
		"event":    "forgot_password_token_issued",
		"status":   "success",
		"user_id":  user.ID,
		"username": user.Username,
		"ip":       ctx.ClientIP(),
	}).Info("Password reset token successfully issued")
	ctx.JSON(http.StatusOK, resetTokenResponse{
		ResetToken: token,
	})
}

// resetPassword godoc
// @Summary      Reset password
// @Description  Resets user password using a valid reset token
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        token    path      string               true  "Reset token"
// @Param        request  body      resetPasswordRequest true  "New password data"
// @Success      200      {object}  types.SuccessResponse
// @Failure      400      {object}  types.ErrorResponse
// @Failure      401      {object}  types.ErrorResponse
// @Failure      500      {object}  types.ErrorResponse
// @Router       /auth/reset-password/{token} [post]
func resetPassword(ctx *gin.Context) {
	token := ctx.Param("token")
	auditLog := utils.Logger.WithField("type", "audit")
	if token == "" {
		auditLog.WithFields(logrus.Fields{
			"event":  "reset_password",
			"status": "failure",
			"reason": "missing_token",
			"ip":     ctx.ClientIP(),
		}).Warn("Reset password request missing token")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Missing reset token"})
		return
	}
	user, ok := shared.ResetPasswordCache.Get(token)
	if !ok {
		auditLog.WithFields(logrus.Fields{
			"event":  "reset_password",
			"status": "failure",
			"reason": "invalid_or_expired_token",
			"token":  token,
			"ip":     ctx.ClientIP(),
		}).Warn("Reset password token invalid or expired")
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}
	var input resetPasswordRequest
	if err := ctx.ShouldBindJSON(&input); err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "reset_password",
			"status":   "failure",
			"reason":   "invalid_json",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
		}).Warn("Invalid input during password reset")
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}
	if err := user.SetPassword(input.Password); err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "reset_password",
			"status":   "failure",
			"reason":   "set_password_failed",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Failed to hash new password")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to set password"})
		return
	}
	if err := models.DB.Model(&user).Update("password", user.Password).Error; err != nil {
		auditLog.WithFields(logrus.Fields{
			"event":    "reset_password",
			"status":   "failure",
			"reason":   "db_update_failed",
			"user_id":  user.ID,
			"username": user.Username,
			"ip":       ctx.ClientIP(),
			"error":    err.Error(),
		}).Error("Failed to update password in DB")
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}
	shared.ResetPasswordCache.Delete(token)
	shared.LoginCache.Delete(user.Email)
	auditLog.WithFields(logrus.Fields{
		"event":    "reset_password",
		"status":   "success",
		"user_id":  user.ID,
		"username": user.Username,
		"ip":       ctx.ClientIP(),
	}).Info("Password reset successfully")
	ctx.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully"})
}
