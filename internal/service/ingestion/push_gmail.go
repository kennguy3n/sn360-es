package ingestion

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GmailPushReceiver implements PushReceiver for Gmail via Google
// Cloud Pub/Sub push subscriptions. Gmail's users.watch API registers
// a Pub/Sub topic that receives notifications on mailbox changes.
type GmailPushReceiver struct {
	BaseURL     string
	TopicName   string
	HTTPClient  *http.Client
	TokenSource GmailTokenSource
}

// GmailTokenSource provides OAuth2 tokens for Gmail API calls.
type GmailTokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Kind returns "gmail".
func (g *GmailPushReceiver) Kind() string { return "gmail" }

// Subscribe registers a Gmail push watch for the given tenant.
// callbackURL is not directly used — Gmail routes through Pub/Sub.
// tenantID is required by the PushReceiver interface but Gmail's
// watch API derives the inbox from the OAuth identity, so we ignore
// it here.
func (g *GmailPushReceiver) Subscribe(ctx context.Context, _ string, _ string) (string, time.Time, error) {
	if g.TopicName == "" {
		return "", time.Time{}, errors.New("gmail push: topic_name is required")
	}

	endpoint := fmt.Sprintf("%s/gmail/v1/users/me/watch",
		g.baseURL())

	body := struct {
		TopicName string   `json:"topicName"`
		LabelIDs  []string `json:"labelIds"`
	}{
		TopicName: g.TopicName,
		LabelIDs:  []string{"INBOX"},
	}

	var resp struct {
		HistoryID  string `json:"historyId"`
		Expiration string `json:"expiration"` // ms since epoch
	}

	if err := g.do(ctx, http.MethodPost, endpoint, body, &resp); err != nil {
		return "", time.Time{}, fmt.Errorf("gmail push: watch: %w", err)
	}

	// Parse expiration (milliseconds since epoch).
	var expiresAt time.Time
	if resp.Expiration != "" {
		var ms int64
		if _, err := fmt.Sscanf(resp.Expiration, "%d", &ms); err == nil {
			expiresAt = time.UnixMilli(ms)
		}
	}
	if expiresAt.IsZero() {
		// Gmail watch defaults to ~7 days.
		expiresAt = time.Now().Add(7 * 24 * time.Hour)
	}

	return resp.HistoryID, expiresAt, nil
}

// Renew re-registers the Gmail watch. Gmail does not support
// in-place renewal — a new watch replaces the old one — so the
// previous subscriptionID is intentionally discarded.
func (g *GmailPushReceiver) Renew(ctx context.Context, tenantID, _ string, callbackURL string) (time.Time, error) {
	_, expiresAt, err := g.Subscribe(ctx, tenantID, callbackURL)
	return expiresAt, err
}

// gmailPubSubMessage is the Pub/Sub push delivery wrapper.
type gmailPubSubMessage struct {
	Message struct {
		Data        string `json:"data"`
		MessageID   string `json:"messageId"`
		PublishTime string `json:"publishTime"`
	} `json:"message"`
	Subscription string `json:"subscription"`
}

// gmailNotificationData is the decoded Pub/Sub data payload.
type gmailNotificationData struct {
	EmailAddress string `json:"emailAddress"`
	HistoryID    uint64 `json:"historyId"`
}

// HandleNotification processes a Gmail Pub/Sub push delivery.
// It decodes the notification, fetches new messages since the
// history ID, and returns them as RawEmails.
func (g *GmailPushReceiver) HandleNotification(ctx context.Context, tenantID string, payload json.RawMessage) ([]RawEmail, error) {
	var pubsub gmailPubSubMessage
	if err := json.Unmarshal(payload, &pubsub); err != nil {
		return nil, fmt.Errorf("gmail push: unmarshal pubsub: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(pubsub.Message.Data)
	if err != nil {
		return nil, fmt.Errorf("gmail push: decode data: %w", err)
	}

	var notif gmailNotificationData
	if err := json.Unmarshal(data, &notif); err != nil {
		return nil, fmt.Errorf("gmail push: unmarshal notification: %w", err)
	}

	if notif.EmailAddress == "" {
		return nil, nil
	}

	// Fetch recent messages via history list.
	emails, err := g.fetchRecentMessages(ctx, notif.EmailAddress, notif.HistoryID)
	if err != nil {
		return nil, fmt.Errorf("gmail push: fetch recent: %w", err)
	}

	// Tag with tenant ID.
	for i := range emails {
		if emails[i].TenantID == "" {
			emails[i].TenantID = tenantID
		}
	}
	return emails, nil
}

// fetchRecentMessages fetches messages added since the given history ID.
func (g *GmailPushReceiver) fetchRecentMessages(ctx context.Context, email string, historyID uint64) ([]RawEmail, error) {
	endpoint := fmt.Sprintf("%s/gmail/v1/users/%s/history?startHistoryId=%d&historyTypes=messageAdded",
		g.baseURL(), url.PathEscape(email), historyID)

	var resp struct {
		History []struct {
			MessagesAdded []struct {
				Message struct {
					ID string `json:"id"`
				} `json:"message"`
			} `json:"messagesAdded"`
		} `json:"history"`
	}

	if err := g.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return nil, err
	}

	var emails []RawEmail
	for _, h := range resp.History {
		for _, ma := range h.MessagesAdded {
			if ma.Message.ID == "" {
				continue
			}
			raw, err := g.fetchMessage(ctx, email, ma.Message.ID)
			if err != nil {
				continue // Best-effort.
			}
			emails = append(emails, raw)
		}
	}
	return emails, nil
}

// fetchMessage retrieves a single message by ID.
func (g *GmailPushReceiver) fetchMessage(ctx context.Context, email, messageID string) (RawEmail, error) {
	endpoint := fmt.Sprintf("%s/gmail/v1/users/%s/messages/%s?format=metadata&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Cc&metadataHeaders=Subject&metadataHeaders=Date",
		g.baseURL(), url.PathEscape(email), url.PathEscape(messageID))

	var resp struct {
		ID      string `json:"id"`
		Snippet string `json:"snippet"`
		Payload struct {
			Headers []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"headers"`
		} `json:"payload"`
		InternalDate string `json:"internalDate"`
	}

	if err := g.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return RawEmail{}, err
	}

	raw := RawEmail{
		ProviderMessageID: resp.ID,
		Mailbox:           email,
	}

	headers := make(map[string]string)
	for _, h := range resp.Payload.Headers {
		name := strings.ToLower(h.Name)
		headers[name] = h.Value
		switch name {
		case "from":
			raw.Sender = h.Value
		case "to":
			raw.Recipients = splitAddresses(h.Value)
		case "cc":
			raw.CC = splitAddresses(h.Value)
		case "subject":
			raw.Subject = h.Value
		}
	}
	raw.Headers = headers
	raw.Body = resp.Snippet

	if resp.InternalDate != "" {
		var ms int64
		if _, err := fmt.Sscanf(resp.InternalDate, "%d", &ms); err == nil {
			raw.ReceivedAt = time.UnixMilli(ms)
		}
	}
	if raw.ReceivedAt.IsZero() {
		raw.ReceivedAt = time.Now().UTC()
	}

	return raw, nil
}

func splitAddresses(s string) []string {
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (g *GmailPushReceiver) baseURL() string {
	if g.BaseURL != "" {
		return strings.TrimRight(g.BaseURL, "/")
	}
	return "https://gmail.googleapis.com"
}

func (g *GmailPushReceiver) do(ctx context.Context, method, endpoint string, in, out any) error {
	var bodyReader io.Reader
	if in != nil {
		buf, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	if g.TokenSource != nil {
		tok, terr := g.TokenSource.Token(ctx)
		if terr != nil {
			return fmt.Errorf("acquire token: %w", terr)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := g.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if rerr != nil {
		return fmt.Errorf("read body: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("api error: status %d body %s", resp.StatusCode, string(respBody))
	}
	if out == nil || len(respBody) == 0 {
		return nil
	}
	return json.Unmarshal(respBody, out)
}
