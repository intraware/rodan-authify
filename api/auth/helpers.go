package auth

import (
	"crypto/rand"
	"encoding/hex"
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
