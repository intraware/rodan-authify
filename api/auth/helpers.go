package auth

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"

	"github.com/intraware/rodan-authify/internal/config"
	"github.com/intraware/rodan-authify/internal/models"
	"github.com/intraware/rodan-authify/internal/utils/email"
	"github.com/intraware/rodan-authify/internal/utils/values"
	"golang.org/x/oauth2"
)

func sendResetToken(userEmail, token string) error {
	emailCfg := values.GetConfig().App.Email
	emailObj, err := email.NewEmail()
	if err != nil {
		return fmt.Errorf("failed to init email service: %w", err)
	}
	if emailObj == nil {
		return fmt.Errorf("email service is disabled")
	}
	if !emailCfg.AllowedEmailCompilexRegex.MatchString(userEmail) {
		return fmt.Errorf("email does not match allowed regex")
	}
	tmpl, err := template.New("resetEmail").Parse(emailCfg.EmailTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}
	data := struct {
		Token string
	}{
		Token: token,
	}
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}
	return emailObj.DeliveryAgent.SendEmail(userEmail, emailCfg.EmailSubject, body.String())
}

func generateResetToken() (token string, err error) {
	random := make([]byte, 20)
	_, err = rand.Read(random)
	if err != nil {
		return
	}
	token = hex.EncodeToString(random)
	return
}

func buildOAuthConfig(providerName string, cfg *config.OAuthConfig) *oauth2.Config {
	providerConfig := cfg.Providers[providerName]
	return &oauth2.Config{
		ClientID:     providerConfig.ClientID,
		ClientSecret: providerConfig.ClientSecret,
		Scopes:       providerConfig.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  providerConfig.AuthURL,
			TokenURL: providerConfig.TokenURL,
		},
		RedirectURL: cfg.RedirectURL + providerName + "/callback",
	}
}

func buildOauthLinkConfig(providerName string, cfg *config.OAuthConfig) *oauth2.Config {
	providerConfig := cfg.Providers[providerName]
	return &oauth2.Config{
		ClientID:     providerConfig.ClientID,
		ClientSecret: providerConfig.ClientSecret,
		Scopes:       providerConfig.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  providerConfig.AuthURL,
			TokenURL: providerConfig.TokenURL,
		},
		RedirectURL: cfg.RedirectURL + providerName + "/link/callback",
	}
}

func buildUserModel(client *http.Client, providerConfig config.OAuthProviderConfig) (models.User, string, error) {
	var user models.User
	resp, err := client.Get(providerConfig.UserInfoURL)
	if err != nil {
		return user, "", fmt.Errorf("failed to fetch userinfo: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return user, "", fmt.Errorf("userinfo request failed: %s", string(body))
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return user, "", fmt.Errorf("failed to parse userinfo: %w", err)
	}
	getField := func(modelKey string) string {
		if jsonKey, ok := providerConfig.FieldMap[modelKey]; ok {
			if val, ok := raw[jsonKey]; ok {
				return fmt.Sprint(val)
			}
		}
		return ""
	}
	user = models.User{
		Username:  getField("username"),
		Email:     getField("email"),
		AvatarURL: getField("avatar_url"),
	}
	providerID := getField("provider_id")
	return user, providerID, nil
}
