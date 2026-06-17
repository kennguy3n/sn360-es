package ingestion

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OutlookPushReceiver implements PushReceiver for Microsoft Graph
// Change Notifications. It manages subscription lifecycle and
// processes incoming notification payloads.
type OutlookPushReceiver struct {
	BaseURL     string
	HTTPClient  *http.Client
	TokenSource OutlookTokenSource

	// TenantList is the set of Azure AD tenant IDs this receiver
	// covers. Production wiring populates this from cfg.O365.TenantID.
	// Used by [PushManager.SetupSubscriptions] to avoid taking a
	// cross-product of Outlook's tenant namespace with Gmail's
	// domain namespace — every cross-product element would produce
	// either an invalid callback URL or a duplicate Graph
	// subscription that double-publishes notifications.
	TenantList []string

	// ClientStateForTenant returns the value the receiver should
	// stamp on subscription-create requests as clientState, and the
	// value it expects on inbound notification entries. It MUST be
	// the same function the edge-level signature verifier
	// ([handler.MicrosoftClientStateVerifier].ExpectedFor) consults,
	// otherwise the verifier rejects legitimate callbacks while
	// HandleNotification — invoked after verification — would accept
	// them, leaving the two halves out of sync.
	//
	// When nil, the receiver falls back to the legacy unguessable-only-
	// by-obscurity "sn360-es-"+tenantID string. Production wiring MUST
	// supply a function that mixes a deployment secret in (see
	// wire_infra.go's outlookClientStateForTenant helper) so the
	// clientState is not derivable from the tenant ID alone.
	ClientStateForTenant func(tenantID string) string
}

// Tenants returns the Azure AD tenant IDs this receiver covers. See
// [PushReceiver.Tenants] for the contract — in particular, no empty
// strings.
func (o *OutlookPushReceiver) Tenants() []string { return o.TenantList }

// clientStateFor returns the clientState the receiver expects for a
// given tenant. Centralised so Subscribe and HandleNotification
// cannot drift from each other.
func (o *OutlookPushReceiver) clientStateFor(tenantID string) string {
	if o.ClientStateForTenant != nil {
		return o.ClientStateForTenant(tenantID)
	}
	return "sn360-es-" + tenantID
}

// OutlookTokenSource provides OAuth2 tokens for Graph API calls.
type OutlookTokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Kind returns "outlook".
func (o *OutlookPushReceiver) Kind() string { return "outlook" }

// Subscribe creates a Microsoft Graph Change Notification subscription
// for new messages in all mailboxes of the tenant.
func (o *OutlookPushReceiver) Subscribe(ctx context.Context, tenantID string, callbackURL string) (string, time.Time, error) {
	if callbackURL == "" {
		return "", time.Time{}, errors.New("outlook push: callback_url is required")
	}

	endpoint := fmt.Sprintf("%s/v1.0/subscriptions", o.baseURL())

	expiresAt := time.Now().UTC().Add(48 * time.Hour) // Graph max for mail is ~4230 minutes

	body := struct {
		ChangeType         string `json:"changeType"`
		NotificationURL    string `json:"notificationUrl"`
		Resource           string `json:"resource"`
		ExpirationDateTime string `json:"expirationDateTime"`
		ClientState        string `json:"clientState,omitempty"`
	}{
		ChangeType:         "created",
		NotificationURL:    callbackURL,
		Resource:           "users/messages",
		ExpirationDateTime: expiresAt.Format(time.RFC3339),
		ClientState:        o.clientStateFor(tenantID),
	}

	var resp struct {
		ID                 string `json:"id"`
		ExpirationDateTime string `json:"expirationDateTime"`
	}

	if err := o.do(ctx, http.MethodPost, endpoint, body, &resp); err != nil {
		return "", time.Time{}, fmt.Errorf("outlook push: subscribe: %w", err)
	}

	if resp.ExpirationDateTime != "" {
		if t, err := time.Parse(time.RFC3339, resp.ExpirationDateTime); err == nil {
			expiresAt = t
		}
	}

	return resp.ID, expiresAt, nil
}

// Renew extends an existing Graph subscription. tenantID and
// callbackURL are part of the PushReceiver contract but Graph's PATCH
// /subscriptions/{id} only takes the new expiration — both are
// intentionally ignored.
func (o *OutlookPushReceiver) Renew(ctx context.Context, _, subscriptionID string, _ string) (time.Time, error) {
	endpoint := fmt.Sprintf("%s/v1.0/subscriptions/%s", o.baseURL(), url.PathEscape(subscriptionID))

	expiresAt := time.Now().UTC().Add(48 * time.Hour)

	body := struct {
		ExpirationDateTime string `json:"expirationDateTime"`
	}{
		ExpirationDateTime: expiresAt.Format(time.RFC3339),
	}

	var resp struct {
		ExpirationDateTime string `json:"expirationDateTime"`
	}

	if err := o.do(ctx, http.MethodPatch, endpoint, body, &resp); err != nil {
		return time.Time{}, fmt.Errorf("outlook push: renew: %w", err)
	}

	if resp.ExpirationDateTime != "" {
		if t, err := time.Parse(time.RFC3339, resp.ExpirationDateTime); err == nil {
			expiresAt = t
		}
	}

	return expiresAt, nil
}

// Unsubscribe DELETEs an existing Microsoft Graph subscription on
// shutdown so a restart does not leave a stale subscription
// delivering callbacks alongside a freshly created one. Graph
// returns 204 on success and 404 when the subscription has already
// been evicted (e.g. by natural expiry between the last Renew and
// now); both are treated as success because the desired post-state
// — "no subscription with this ID exists on the provider" — is
// satisfied in both cases.
//
// tenantID is part of the PushReceiver contract but Graph's
// per-subscription DELETE is keyed only by subscriptionID, so it
// is intentionally unused here.
func (o *OutlookPushReceiver) Unsubscribe(ctx context.Context, _, subscriptionID string) error {
	if subscriptionID == "" {
		// Defensive: PushManager never tracks an empty
		// subscriptionID, but if something upstream slipped one
		// in we'd otherwise call DELETE /v1.0/subscriptions/ on
		// the collection root and that's a different operation
		// entirely. Refuse loudly instead of guessing.
		return errors.New("outlook push: unsubscribe requires a non-empty subscription_id")
	}
	endpoint := fmt.Sprintf("%s/v1.0/subscriptions/%s", o.baseURL(), url.PathEscape(subscriptionID))

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("outlook push: unsubscribe: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if o.TokenSource != nil {
		tok, terr := o.TokenSource.Token(ctx)
		if terr != nil {
			return fmt.Errorf("outlook push: unsubscribe: acquire token: %w", terr)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := o.HTTPClient
	if client == nil {
		client = defaultPushHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("outlook push: unsubscribe: http: %w", err)
	}
	defer resp.Body.Close()
	// 204 No Content is the documented success response; 404 Not
	// Found means the subscription is already gone — both leave
	// the provider in the desired post-state.
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return fmt.Errorf("outlook push: unsubscribe: status %d body %s", resp.StatusCode, string(body))
}

// graphChangeNotification is the Graph webhook payload.
type graphChangeNotification struct {
	Value []struct {
		SubscriptionID string `json:"subscriptionId"`
		ChangeType     string `json:"changeType"`
		ClientState    string `json:"clientState"`
		Resource       string `json:"resource"`
		ResourceData   struct {
			ODataType string `json:"@odata.type"`
			ODataID   string `json:"@odata.id"`
			ID        string `json:"id"`
		} `json:"resourceData"`
	} `json:"value"`
}

// HandleNotification processes a Graph Change Notification payload.
// It validates the clientState on each notification entry to ensure
// the callback genuinely originated from a subscription we created.
func (o *OutlookPushReceiver) HandleNotification(ctx context.Context, tenantID string, payload json.RawMessage) ([]RawEmail, error) {
	var notif graphChangeNotification
	if err := json.Unmarshal(payload, &notif); err != nil {
		return nil, fmt.Errorf("outlook push: unmarshal: %w", err)
	}

	expectedState := o.clientStateFor(tenantID)

	var emails []RawEmail
	for _, v := range notif.Value {
		// Use a constant-time comparison even though [handler.MicrosoftClientStateVerifier]
		// has already verified the clientState at the HTTP edge with
		// crypto/subtle.ConstantTimeCompare. This branch is defense-in-
		// depth for call paths that reach HandleNotification without
		// passing through the edge verifier (unit tests, future internal
		// callers); matching the edge's timing-safety keeps the two
		// halves of the validation pipeline consistent so a future
		// refactor that drops the edge check does not silently reopen
		// a timing oracle. The error intentionally elides both the got
		// and want values so log scrapes cannot observe partial-match
		// progress across replays.
		if subtle.ConstantTimeCompare([]byte(v.ClientState), []byte(expectedState)) != 1 {
			return nil, errors.New("outlook push: clientState mismatch")
		}
		if v.ChangeType != "created" {
			continue
		}
		msgID := v.ResourceData.ID
		if msgID == "" {
			continue
		}
		// Extract the user email from the resource path.
		email := extractEmailFromResource(v.Resource)
		if email == "" {
			continue
		}
		raw, err := o.fetchMessage(ctx, email, msgID)
		if err != nil {
			continue
		}
		raw.TenantID = tenantID
		emails = append(emails, raw)
	}
	return emails, nil
}

// extractEmailFromResource parses the user email from a Graph
// resource path like "users/user@example.com/messages/AAA".
func extractEmailFromResource(resource string) string {
	parts := strings.Split(resource, "/")
	if len(parts) >= 2 && parts[0] == "users" {
		return parts[1]
	}
	return ""
}

// fetchMessage retrieves a single message by ID from Graph.
func (o *OutlookPushReceiver) fetchMessage(ctx context.Context, email, messageID string) (RawEmail, error) {
	endpoint := fmt.Sprintf("%s/v1.0/users/%s/messages/%s?$select=id,subject,from,toRecipients,ccRecipients,body,receivedDateTime,internetMessageHeaders",
		o.baseURL(), url.PathEscape(email), url.PathEscape(messageID))

	var resp struct {
		ID      string `json:"id"`
		Subject string `json:"subject"`
		From    struct {
			EmailAddress struct {
				Address string `json:"address"`
			} `json:"emailAddress"`
		} `json:"from"`
		ToRecipients []struct {
			EmailAddress struct {
				Address string `json:"address"`
			} `json:"emailAddress"`
		} `json:"toRecipients"`
		CCRecipients []struct {
			EmailAddress struct {
				Address string `json:"address"`
			} `json:"emailAddress"`
		} `json:"ccRecipients"`
		Body struct {
			ContentType string `json:"contentType"`
			Content     string `json:"content"`
		} `json:"body"`
		ReceivedDateTime string `json:"receivedDateTime"`
	}

	if err := o.do(ctx, http.MethodGet, endpoint, nil, &resp); err != nil {
		return RawEmail{}, err
	}

	raw := RawEmail{
		ProviderMessageID: resp.ID,
		Mailbox:           email,
		Sender:            resp.From.EmailAddress.Address,
		Subject:           resp.Subject,
	}

	for _, r := range resp.ToRecipients {
		if r.EmailAddress.Address != "" {
			raw.Recipients = append(raw.Recipients, r.EmailAddress.Address)
		}
	}
	for _, r := range resp.CCRecipients {
		if r.EmailAddress.Address != "" {
			raw.CC = append(raw.CC, r.EmailAddress.Address)
		}
	}

	if strings.EqualFold(resp.Body.ContentType, "html") {
		raw.HTMLBody = resp.Body.Content
	} else {
		raw.Body = resp.Body.Content
	}

	if resp.ReceivedDateTime != "" {
		if t, err := time.Parse(time.RFC3339, resp.ReceivedDateTime); err == nil {
			raw.ReceivedAt = t
		}
	}
	if raw.ReceivedAt.IsZero() {
		raw.ReceivedAt = time.Now().UTC()
	}

	return raw, nil
}

func (o *OutlookPushReceiver) baseURL() string {
	if o.BaseURL != "" {
		return strings.TrimRight(o.BaseURL, "/")
	}
	return "https://graph.microsoft.com"
}

func (o *OutlookPushReceiver) do(ctx context.Context, method, endpoint string, in, out any) error {
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

	if o.TokenSource != nil {
		tok, terr := o.TokenSource.Token(ctx)
		if terr != nil {
			return fmt.Errorf("acquire token: %w", terr)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := o.HTTPClient
	if client == nil {
		client = defaultPushHTTPClient
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
