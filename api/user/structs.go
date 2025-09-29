package user

type userInfo struct {
	ID          uint    `json:"id" example:"42"`
	Username    string  `json:"username" example:"intraware"`
	Email       string  `json:"email" example:"example@intraware.org"`
	AvatarURL   string  `json:"avatar_url,omitempty" example:"https://.."`
	TeamID      *uint   `json:"team_id" example:"1"`
	FirstBlood  *[]uint `json:"first_blood,omitempty" example:"[1,2,3]"`
	SecondBlood *[]uint `json:"second_blood,omitempty" example:"[1,2,3]"`
	ThirdBlood  *[]uint `json:"third_blood,omitempty" example:"[1,2,3]"`
}

type updateUserRequest struct {
	Username  *string `json:"username"`
	AvatarURL *string `json:"avatar_url"`
}

type providersList struct {
	Providers []string `json:"providers" example:"[google,github,microsoft]"`
}
