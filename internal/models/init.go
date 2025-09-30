package models

import (
	"fmt"
	"os"
	"time"

	"github.com/intraware/rodan-authify/internal/config"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func Init(cfg *config.Config) {
	dbUrl := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%d sslmode=%s",
		cfg.Database.Host,
		cfg.Database.Username,
		cfg.Database.Password,
		cfg.Database.DatabaseName,
		cfg.Database.Port,
		cfg.Database.SSLMode,
	)
	if envDBURL := os.Getenv("DATABASE_URL"); envDBURL != "" {
		logrus.Warn("DATABASE_URL is set; overriding config values from TOML")
		dbUrl = envDBURL
	} else {
		logrus.Info("Using database config from TOML file")
	}
	logLevel := logger.Info
	if cfg.Server.Production {
		logLevel = logger.Silent
	}
	var err error
	maxRetries := cfg.Database.MaxTries
	for i := range maxRetries {
		DB, err = gorm.Open(postgres.Open(dbUrl), &gorm.Config{
			TranslateError: true,
			Logger:         logger.Default.LogMode(logLevel),
		})
		if err == nil {
			break
		}
		logrus.Errorf("Failed to connect to database (attempt %d/%d): %v", i+1, maxRetries, err)
		if i < maxRetries-1 {
			logrus.Println("Retrying in 5 seconds...")
			time.Sleep(5 * time.Second)
		}
	}
	if err != nil {
		logrus.Fatalf("Failed to connect to database after %d attempts: %v", maxRetries, err)
	}
	if err := DB.AutoMigrate(&User{}, &Team{}, &BanHistory{}); err != nil {
		logrus.Fatalf("Failed to migrate database: %v", err)
	}
	if !DB.Migrator().HasConstraint(&Team{}, "fk_teams_leader") {
		err := DB.Exec(`
        ALTER TABLE teams
        ADD CONSTRAINT fk_teams_leader
        FOREIGN KEY (leader_id) REFERENCES users(id)
        ON UPDATE CASCADE ON DELETE SET NULL
    `).Error
		if err != nil {
			logrus.Fatalf("Failed to add constraint: %v", err)
		} else {
			logrus.Infof("Constraint fk_teams_leader created successfully")
		}
	}
	appCfg := cfg.App
	if appCfg.OAuth.Enabled {
		if err := DB.AutoMigrate(&UserOauthMeta{}); err != nil {
			logrus.Fatalf("Failed to migrate database: %v", err)
		}
	}
	if appCfg.TOTP.Enabled {
		if err := DB.AutoMigrate(&UserTOTPMeta{}); err != nil {
			logrus.Fatalf("Failed to migrate database: %v", err)
		}
	}
	logrus.Println("Database initialized successfully")
}
