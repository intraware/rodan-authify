package models

import "gorm.io/gorm"

type BanHistory struct {
	gorm.Model
	UserID    *int   `json:"user_id"`
	TeamID    *int   `json:"team_id"`
	ExpiresAt int64  `json:"expires_at"`
	Context   string `json:"context"`
}
