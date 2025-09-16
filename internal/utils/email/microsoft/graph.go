package microsoft

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type EmailDeliveryClient struct {
	client      http.Client
	sendMailUrl string
	accessToken string
}

type EmailPayload struct {
	Message         Message `json:"message"`
	SaveToSentItems bool    `json:"saveToSentItems"`
}

type Message struct {
	Subject      string      `json:"subject"`
	Body         Item        `json:"body"`
	ToRecipients []Recipient `json:"toRecipients"`
}

type Item struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type Recipient struct {
	EmailAddress Email `json:"emailAddress"`
}

type Email struct {
	Address string `json:"address"`
}

func NewEmailDeliveryClient(agentEmail, tenantID, clientID, clientSecret string) (*EmailDeliveryClient, error) {
	httpClient := http.Client{}
	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", "https://graph.microsoft.com/.default")
	data.Set("client_secret", clientSecret)
	data.Set("grant_type", "client_credentials")
	resp, err := httpClient.PostForm(endpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token error: %s", string(body))
	}
	var res map[string]any
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, fmt.Errorf("unmarshal error: %v", err)
	}
	token, ok := res["access_token"].(string)
	if !ok {
		return nil, fmt.Errorf("access_token not found in response")
	}
	return &EmailDeliveryClient{
		client:      httpClient,
		accessToken: token,
		sendMailUrl: fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s/sendMail", agentEmail),
	}, nil
}

func (m *EmailDeliveryClient) SendEmail(to, subject, body string) (err error) {
	jsonData, _ := json.Marshal(EmailPayload{
		Message: Message{
			Subject: subject,
			Body: Item{
				ContentType: "Text",
				Content:     body,
			},
			ToRecipients: []Recipient{
				{
					EmailAddress: Email{
						Address: to,
					},
				},
			},
		},
		SaveToSentItems: false,
	})
	req, _ := http.NewRequest("POST", m.sendMailUrl, bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+m.accessToken)
	req.Header.Set("Content-Type", "application/json")
	var resp *http.Response
	resp, err = m.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to send email, status code: %d, response: %s", resp.StatusCode, body)
	}
	return
}
