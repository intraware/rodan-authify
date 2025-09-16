package smtp

import smtpPkg "net/smtp"

type EmailDeliveryClient struct {
	smtpSever  string
	agentEmail string
	auth       smtpPkg.Auth
}

func NewEmailDeliveryClient(smtpServer, agentEmail string, smtpAuth smtpPkg.Auth) *EmailDeliveryClient {
	return &EmailDeliveryClient{
		smtpSever:  smtpServer,
		agentEmail: agentEmail,
		auth:       smtpAuth,
	}
}

func (c *EmailDeliveryClient) SendEmail(to, subject, body string) error {
	return smtpPkg.SendMail(c.smtpSever, c.auth, c.agentEmail, []string{to}, []byte(
		"Subject: "+subject+"\r\n"+
			"Content-Type: text/plain; charset=UTF-8\r\n"+
			"\r\n"+
			body,
	))
}
