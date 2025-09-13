package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/intraware/rodan-authify/internal/config"
	"github.com/intraware/rodan-authify/internal/models"
	"golang.org/x/oauth2"
)

func sendResetToken(email, token string) error

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
