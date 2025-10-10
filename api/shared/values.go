package shared

import (
	"sync/atomic"
)

var allowLogin atomic.Bool
var allowSignUp atomic.Bool

func SetLogin(login bool) {
	allowLogin.Store(login)
}

func AllowLogin() bool {
	return allowLogin.Load()
}

func SetSignup(signup bool) {
	allowSignUp.Store(signup)
}

func AllowSignup() bool {
	return allowSignUp.Load()
}
