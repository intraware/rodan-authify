package email

import (
	"fmt"
	email_smtp "net/smtp"
	"time"

	"github.com/intraware/rodan-authify/internal/utils/email/microsoft"
	"github.com/intraware/rodan-authify/internal/utils/email/smtp"
	"github.com/intraware/rodan-authify/internal/utils/values"
)

type EmailDelivery interface {
	SendEmail(to, subject, body string) error
}

type Email struct {
	DeliveryAgent EmailDelivery
	limiter       <-chan time.Time
}

func NewEmail() (*Email, error) {
	emailCfg := values.GetConfig().App.Email
	if !emailCfg.Enabled {
		return nil, fmt.Errorf("Email is not configured")
	}
	var delivery EmailDelivery
	var err error
	switch emailCfg.Provider.Type {
	case "microsoft":
		msCfg := emailCfg.Provider
		delivery, err = microsoft.NewEmailDeliveryClient(
			emailCfg.AgentEmail,
			msCfg.TenantID,
			msCfg.ClientID,
			msCfg.ClientSecret,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to init microsoft client: %w", err)
		}
	case "smtp":
		addr := fmt.Sprintf("%s:%d", emailCfg.Provider.Host, emailCfg.Provider.Port)
		auth := email_smtp.PlainAuth("", emailCfg.Provider.Username, emailCfg.Provider.Password, emailCfg.Provider.Host)
		delivery = smtp.NewEmailDeliveryClient(
			addr,
			emailCfg.AgentEmail,
			auth,
		)
	default:
		return nil, fmt.Errorf("unknown email provider: %s", emailCfg.Provider.Type)
	}
	limiter := time.Tick(time.Second)
	return &Email{
		DeliveryAgent: delivery,
		limiter:       limiter,
	}, nil
}
