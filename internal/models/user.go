package models

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/intraware/rodan-authify/internal/utils/values"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
	"gorm.io/gorm"
)

const (
	timeCost    = 1
	memoryCost  = 32 * 1024
	parallelism = 2
	saltLength  = 16
	keyLength   = 32
)

type User struct {
	gorm.Model
	Username  string `json:"username" gorm:"unique"`
	Password  string `json:"-"`
	Email     string `json:"email" gorm:"unique"`
	AvatarURL string `json:"avatar_url" gorm:"column:avatar_url;unique"`
	Active    bool   `json:"active" gorm:"default:false"`
	Ban       bool   `json:"ban" gorm:"default:false"`
	Blacklist bool   `json:"blacklist" gorm:"default:false"`
	TeamID    *uint  `json:"team_id" gorm:"column:team_id"`
	Team      *Team  `json:"team" gorm:"foreignKey:TeamID"`
}

type UserOauthMeta struct {
	gorm.Model
	UserID       uint   `gorm:"column:user_id;not null;index"`
	Provider     string `gorm:"not null"`
	ProviderID   string `gorm:"not null;unique"`
	AccessToken  string `gorm:"type:text"`
	RefreshToken string `gorm:"type:text"`
	Expiry       time.Time

	User *User `gorm:"foreignKey:UserID"`
}

type UserTOTPMeta struct {
	gorm.Model
	BackupCode string `gorm:"unique" json:"backup_code"`
	TOTPSecret string `gorm:"unique" json:"totp_secret"`
	UserID     uint   `gorm:"column:user_id;not null;index" json:"user_id"`

	User *User `gorm:"foreignKey:UserID"`
}

func (User) TableName() string {
	return "users"
}

func (UserTOTPMeta) TableName() string {
	return "user_totp_meta"
}

func (UserOauthMeta) TableName() string {
	return "user_oauth_meta"
}

func generateResetCode(length int) (string, error) {
	code := ""
	for range length {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		code += n.String()
	}
	return code, nil
}

func (ut *UserTOTPMeta) BeforeCreate(tx *gorm.DB) (err error) {
	if code, err := generateResetCode(12); err != nil {
		return err
	} else {
		ut.BackupCode = code
	}
	if key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      values.GetConfig().App.TOTP.Issuer,
		AccountName: ut.User.Username,
		Period:      60,
		Digits:      otp.Digits(otp.DigitsEight),
	}); err != nil {
		return err
	} else {
		ut.TOTPSecret = key.Secret()
	}
	return
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	err = u.SetPassword(u.Password)
	if err != nil {
		return
	}
	return
}

func (u *User) SetPassword(password string) (err error) {
	err = nil
	salt := make([]byte, saltLength)
	if _, err = rand.Read(salt); err != nil {
		return
	}
	hash := argon2.IDKey([]byte(password), salt, timeCost, memoryCost, uint8(parallelism), keyLength)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	encoded := fmt.Sprintf("$argon2id$v=19$t=%d$m=%d$p=%d$%s$%s",
		timeCost, memoryCost, parallelism, b64Salt, b64Hash)
	u.Password = encoded
	return
}

func (ut *UserTOTPMeta) TOTPUrl() (string, error) {
	issuer := values.GetConfig().App.TOTP.Issuer
	if key, err := otp.NewKeyFromURL(
		fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s",
			issuer, ut.User.Email, ut.TOTPSecret, issuer),
	); err != nil {
		return "", err
	} else {
		return key.URL(), nil
	}
}

func (ut *UserTOTPMeta) VerifyTOTP(otp string) bool {
	return totp.Validate(otp, ut.TOTPSecret)
}

func (u *User) ComparePassword(password string) (bool, error) {
	parts := strings.Split(u.Password, "$")
	if len(parts) != 7 {
		return false, fmt.Errorf("invalid hash format")
	}
	var t, m uint32
	var p uint8
	_, err := fmt.Sscanf(parts[3], "t=%d", &t)
	if err != nil {
		return false, fmt.Errorf("error parsing time: %w", err)
	}
	_, err = fmt.Sscanf(parts[4], "m=%d", &m)
	if err != nil {
		return false, fmt.Errorf("error parsing memory: %w", err)
	}
	_, err = fmt.Sscanf(parts[5], "p=%d", &p)
	if err != nil {
		return false, fmt.Errorf("error parsing parallelism: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[6])
	if err != nil {
		return false, fmt.Errorf("error decoding salt: %w", err)
	}
	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[7])
	if err != nil {
		return false, fmt.Errorf("error decoding hash: %w", err)
	}
	actualHash := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(expectedHash)))
	if bytes.Equal(actualHash, expectedHash) {
		return true, nil
	}
	return false, nil
}

func (u *User) BeforeDelete(tx *gorm.DB) (err error) {
	var team Team
	err = tx.First(&team, u.TeamID).Error
	if err != nil {
		return
	}
	if team.LeaderID == u.ID {
		err = tx.Exec(`
    UPDATE teams 
    SET leader_id = (
        SELECT id FROM users 
        WHERE team_id = ? AND id != ? AND deleted_at IS NULL
        ORDER BY created_at LIMIT 1
    ) 
    WHERE id = ?`,
			team.ID, u.ID, team.ID).Error
	}
	appCfg := values.GetConfig().App
	if appCfg.TOTP.Enabled {
		err = tx.Where("user_id = ?", u.ID).Delete(&UserTOTPMeta{}).Error
		if err != nil {
			return
		}
	}
	if appCfg.OAuth.Enabled {
		err = tx.Where("user_id = ?", u.ID).Delete(&UserOauthMeta{}).Error
		if err != nil {
			return
		}
	}
	return
}
