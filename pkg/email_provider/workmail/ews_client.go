package workmail

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// EWSClient is the EWS SOAP plumbing reused by mailbox/banner/quarantine
// providers for WorkMail. WorkMail's EWS endpoint accepts AWS SigV4
// signing with the IAM credentials provisioned via the WorkMail
// Access Control Rule that allows "ews:*" actions.
//
// The client speaks the Exchange 2010_SP2 schema namespace, which is
// the latest version WorkMail supports.
type EWSClient struct {
	http        *http.Client
	signer      *Signer
	endpoint    string
	impersonate bool
}

// EWSClientConfig wires EWSClient.
type EWSClientConfig struct {
	HTTPClient *http.Client
	// Signer signs the EWS request with SigV4 against the "workmail"
	// service. WorkMail uses the same service name for both the
	// JSON API and the EWS endpoint.
	Signer *Signer
	// Endpoint overrides the EWS URL. Defaults to
	// https://ews.mail.<region>.awsapps.com/EWS/Exchange.asmx.
	Endpoint string
	Region   string
	// Impersonate controls whether the client emits the
	// ExchangeImpersonation SOAP header on every request. Default
	// is true — WorkMail's IAM identity acts on behalf of mailbox
	// owners via impersonation.
	Impersonate *bool
}

// NewEWSClient validates the config and returns the client.
func NewEWSClient(cfg EWSClientConfig) (*EWSClient, error) {
	if cfg.Signer == nil {
		return nil, errors.New("workmail: ews client requires a Signer")
	}
	if cfg.Region == "" && cfg.Endpoint == "" {
		return nil, errors.New("workmail: ews client requires a region or endpoint")
	}
	endpoint := strings.TrimSpace(cfg.Endpoint)
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://ews.mail.%s.awsapps.com/EWS/Exchange.asmx", cfg.Region)
	}
	http := cfg.HTTPClient
	if http == nil {
		http = newDefaultHTTPClient()
	}
	imp := true
	if cfg.Impersonate != nil {
		imp = *cfg.Impersonate
	}
	return &EWSClient{
		http:        http,
		signer:      cfg.Signer,
		endpoint:    endpoint,
		impersonate: imp,
	}, nil
}

func newDefaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

// EWSResponse is the generic decoded SOAP envelope. The Body field
// is left as raw XML so each operation can decode the parts it
// cares about.
type EWSResponse struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"Body"`
}

// Invoke posts a SOAP envelope containing the supplied request body
// and decodes the response. impersonateEmail, when non-empty, sets
// the ExchangeImpersonation header so the API call acts on behalf of
// that mailbox owner.
//
// requestBody must contain the SOAP body content (without the
// envelope/header wrapper). The function wraps it in the standard
// Exchange envelope automatically.
func (c *EWSClient) Invoke(ctx context.Context, impersonateEmail, requestBody string) ([]byte, error) {
	envelope := buildSOAPEnvelope(c.impersonate && impersonateEmail != "", impersonateEmail, requestBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(envelope))
	if err != nil {
		return nil, fmt.Errorf("workmail: build ews: %w", err)
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "")
	body := []byte(envelope)
	if err := c.signer.Sign(ctx, req, body); err != nil {
		return nil, fmt.Errorf("workmail: sign ews: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("workmail: ews http: %w", err)
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if rerr != nil {
		return nil, fmt.Errorf("workmail: read ews: %w", rerr)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("workmail: ews %d: %s", resp.StatusCode, truncate(string(respBody), 400))
	}
	var env EWSResponse
	if err := xml.Unmarshal(respBody, &env); err != nil {
		return nil, fmt.Errorf("workmail: decode ews: %w", err)
	}
	return env.Body.Inner, nil
}

// FindItems calls EWS FindItem against the named folder in
// impersonateEmail's mailbox and returns the matching ItemIds.
// receivedAfter is inclusive; pass time.Time{} to skip the filter.
func (c *EWSClient) FindItems(ctx context.Context, impersonateEmail, folder string, receivedAfter time.Time, limit int) ([]EWSItem, error) {
	if folder == "" {
		folder = "inbox"
	}
	if limit <= 0 {
		limit = 50
	}
	restriction := ""
	if !receivedAfter.IsZero() {
		restriction = fmt.Sprintf(`
      <m:Restriction>
        <t:IsGreaterThan>
          <t:FieldURI FieldURI="item:DateTimeReceived"/>
          <t:FieldURIOrConstant>
            <t:Constant Value="%s"/>
          </t:FieldURIOrConstant>
        </t:IsGreaterThan>
      </m:Restriction>`, receivedAfter.UTC().Format(time.RFC3339))
	}
	body := fmt.Sprintf(`
    <m:FindItem Traversal="Shallow">
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Subject"/>
          <t:FieldURI FieldURI="item:DateTimeReceived"/>
          <t:FieldURI FieldURI="message:From"/>
          <t:FieldURI FieldURI="message:ToRecipients"/>
          <t:FieldURI FieldURI="message:CcRecipients"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:IndexedPageItemView MaxEntriesReturned="%d" Offset="0" BasePoint="Beginning"/>
      %s
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="%s"/>
      </m:ParentFolderIds>
    </m:FindItem>`, limit, restriction, xmlEscape(folder))
	respBody, err := c.Invoke(ctx, impersonateEmail, body)
	if err != nil {
		return nil, fmt.Errorf("workmail: FindItem: %w", err)
	}
	return parseFindItems(respBody)
}

// EWSItem captures the IdOnly + headline fields returned by FindItem.
type EWSItem struct {
	ID           string
	ChangeKey    string
	Subject      string
	DateReceived time.Time
	From         string
	To           []string
	Cc           []string
}

// EWSMessageBody is the body shape used by GetItem / UpdateItem.
type EWSMessageBody struct {
	BodyType string // "HTML" or "Text"
	Content  string
}

// GetItem fetches the body of a message by ID.
func (c *EWSClient) GetItem(ctx context.Context, impersonateEmail, itemID string) (EWSMessageBody, error) {
	body := fmt.Sprintf(`
    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:BodyType>HTML</t:BodyType>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="item:Body"/>
          <t:FieldURI FieldURI="item:DateTimeReceived"/>
        </t:AdditionalProperties>
      </m:ItemShape>
      <m:ItemIds>
        <t:ItemId Id="%s"/>
      </m:ItemIds>
    </m:GetItem>`, xmlEscape(itemID))
	respBody, err := c.Invoke(ctx, impersonateEmail, body)
	if err != nil {
		return EWSMessageBody{}, fmt.Errorf("workmail: GetItem: %w", err)
	}
	return parseGetItemBody(respBody)
}

// UpdateBody replaces the message body via EWS UpdateItem.
//
// The body.BodyType field is normalised to one of the two EWS schema
// enum values ("HTML" or "Text") before being interpolated into the
// SOAP envelope. The enum-restriction is the primary defence: a
// BodyType that originated from a parsed EWS response (and therefore
// could in principle contain attacker-controlled XML if the response
// were tampered with mid-flight) is collapsed to a known-safe string,
// preventing any chance of XML injection into the outbound
// UpdateItem. itemID and Content are escaped via xmlEscape as the
// belt-and-braces layer.
func (c *EWSClient) UpdateBody(ctx context.Context, impersonateEmail, itemID string, body EWSMessageBody) error {
	xmlBody := fmt.Sprintf(`
    <m:UpdateItem ConflictResolution="AutoResolve" MessageDisposition="SaveOnly">
      <m:ItemChanges>
        <t:ItemChange>
          <t:ItemId Id="%s"/>
          <t:Updates>
            <t:SetItemField>
              <t:FieldURI FieldURI="item:Body"/>
              <t:Message>
                <t:Body BodyType="%s">%s</t:Body>
              </t:Message>
            </t:SetItemField>
          </t:Updates>
        </t:ItemChange>
      </m:ItemChanges>
    </m:UpdateItem>`, xmlEscape(itemID), normalizeEWSBodyType(body.BodyType), xmlEscape(body.Content))
	if _, err := c.Invoke(ctx, impersonateEmail, xmlBody); err != nil {
		return fmt.Errorf("workmail: UpdateItem body: %w", err)
	}
	return nil
}

// normalizeEWSBodyType collapses any caller-supplied or server-parsed
// BodyType value to one of the two EWS schema enum values: "HTML" or
// "Text". The EWS XSD permits only these two values (see
// types.xsd#BodyTypeType), so any other value would be rejected by
// WorkMail anyway. Forcing the value into this set at the boundary
// makes it impossible for a tampered response body to inject XML via
// the BodyType attribute (defence-in-depth alongside xmlEscape on the
// content fields).
func normalizeEWSBodyType(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "text":
		return "Text"
	default:
		return "HTML"
	}
}

// UpdateCategories sets the Categories property on a message via
// UpdateItem. Categories is an array of strings (Outlook-style
// category labels).
//
// Loop variable is named cat (not c) so it cannot shadow the EWSClient
// receiver — a future maintainer adding code inside the loop body
// that needs the receiver (e.g. for a nested c.Invoke call) won't
// accidentally pick up the string element instead.
func (c *EWSClient) UpdateCategories(ctx context.Context, impersonateEmail, itemID string, categories []string) error {
	var cats strings.Builder
	for _, cat := range categories {
		fmt.Fprintf(&cats, "<t:String>%s</t:String>", xmlEscape(cat))
	}
	xmlBody := fmt.Sprintf(`
    <m:UpdateItem ConflictResolution="AutoResolve" MessageDisposition="SaveOnly">
      <m:ItemChanges>
        <t:ItemChange>
          <t:ItemId Id="%s"/>
          <t:Updates>
            <t:SetItemField>
              <t:FieldURI FieldURI="item:Categories"/>
              <t:Message>
                <t:Categories>%s</t:Categories>
              </t:Message>
            </t:SetItemField>
          </t:Updates>
        </t:ItemChange>
      </m:ItemChanges>
    </m:UpdateItem>`, xmlEscape(itemID), cats.String())
	if _, err := c.Invoke(ctx, impersonateEmail, xmlBody); err != nil {
		return fmt.Errorf("workmail: UpdateItem categories: %w", err)
	}
	return nil
}

// CreateFolder creates a sub-folder under the user's root folder.
// Returns the new folder's EWS FolderId.
func (c *EWSClient) CreateFolder(ctx context.Context, impersonateEmail, parentFolder, displayName string) (string, error) {
	if parentFolder == "" {
		parentFolder = "msgfolderroot"
	}
	xmlBody := fmt.Sprintf(`
    <m:CreateFolder>
      <m:ParentFolderId>
        <t:DistinguishedFolderId Id="%s"/>
      </m:ParentFolderId>
      <m:Folders>
        <t:Folder>
          <t:DisplayName>%s</t:DisplayName>
        </t:Folder>
      </m:Folders>
    </m:CreateFolder>`, xmlEscape(parentFolder), xmlEscape(displayName))
	respBody, err := c.Invoke(ctx, impersonateEmail, xmlBody)
	if err != nil {
		return "", fmt.Errorf("workmail: CreateFolder: %w", err)
	}
	return parseCreatedFolderID(respBody)
}

// FindFolder looks for a sub-folder by DisplayName under the parent
// distinguished folder. Returns the folder ID or "" when not found.
func (c *EWSClient) FindFolder(ctx context.Context, impersonateEmail, parentFolder, displayName string) (string, error) {
	if parentFolder == "" {
		parentFolder = "msgfolderroot"
	}
	xmlBody := fmt.Sprintf(`
    <m:FindFolder Traversal="Deep">
      <m:FolderShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:AdditionalProperties>
          <t:FieldURI FieldURI="folder:DisplayName"/>
        </t:AdditionalProperties>
      </m:FolderShape>
      <m:Restriction>
        <t:IsEqualTo>
          <t:FieldURI FieldURI="folder:DisplayName"/>
          <t:FieldURIOrConstant>
            <t:Constant Value="%s"/>
          </t:FieldURIOrConstant>
        </t:IsEqualTo>
      </m:Restriction>
      <m:ParentFolderIds>
        <t:DistinguishedFolderId Id="%s"/>
      </m:ParentFolderIds>
    </m:FindFolder>`, xmlEscape(displayName), xmlEscape(parentFolder))
	respBody, err := c.Invoke(ctx, impersonateEmail, xmlBody)
	if err != nil {
		return "", fmt.Errorf("workmail: FindFolder: %w", err)
	}
	return parseFoundFolderID(respBody, displayName)
}

// MoveItem moves a message into the destination folder and returns
// the EWS ItemId of the message at its new location. EWS reissues
// the ItemId on every MoveItem (Exchange items are folder-scoped),
// so the caller MUST persist the returned id rather than reusing the
// input id for subsequent operations.
func (c *EWSClient) MoveItem(ctx context.Context, impersonateEmail, itemID, destinationFolderID string) (string, error) {
	xmlBody := fmt.Sprintf(`
    <m:MoveItem>
      <m:ToFolderId>
        <t:FolderId Id="%s"/>
      </m:ToFolderId>
      <m:ItemIds>
        <t:ItemId Id="%s"/>
      </m:ItemIds>
    </m:MoveItem>`, xmlEscape(destinationFolderID), xmlEscape(itemID))
	respBody, err := c.Invoke(ctx, impersonateEmail, xmlBody)
	if err != nil {
		return "", fmt.Errorf("workmail: MoveItem: %w", err)
	}
	newID, perr := parseMoveItemID(respBody)
	if perr != nil {
		return "", perr
	}
	if newID == "" {
		return itemID, nil
	}
	return newID, nil
}

// MoveItemToDistinguished moves a message into a distinguished folder
// (e.g. "inbox") rather than an arbitrary FolderId. Returns the new
// ItemId following the same EWS reissue rules as MoveItem.
func (c *EWSClient) MoveItemToDistinguished(ctx context.Context, impersonateEmail, itemID, distinguishedFolder string) (string, error) {
	xmlBody := fmt.Sprintf(`
    <m:MoveItem>
      <m:ToFolderId>
        <t:DistinguishedFolderId Id="%s"/>
      </m:ToFolderId>
      <m:ItemIds>
        <t:ItemId Id="%s"/>
      </m:ItemIds>
    </m:MoveItem>`, xmlEscape(distinguishedFolder), xmlEscape(itemID))
	respBody, err := c.Invoke(ctx, impersonateEmail, xmlBody)
	if err != nil {
		return "", fmt.Errorf("workmail: MoveItem distinguished: %w", err)
	}
	newID, perr := parseMoveItemID(respBody)
	if perr != nil {
		return "", perr
	}
	if newID == "" {
		return itemID, nil
	}
	return newID, nil
}

// buildSOAPEnvelope renders the SOAP envelope including the
// optional ExchangeImpersonation header.
func buildSOAPEnvelope(impersonate bool, email, body string) string {
	header := ""
	if impersonate && email != "" {
		header = fmt.Sprintf(`<soap:Header>
      <t:ExchangeImpersonation>
        <t:ConnectingSID>
          <t:PrimarySmtpAddress>%s</t:PrimarySmtpAddress>
        </t:ConnectingSID>
      </t:ExchangeImpersonation>
      <t:RequestServerVersion Version="Exchange2010_SP2"/>
    </soap:Header>`, xmlEscape(email))
	} else {
		header = `<soap:Header>
      <t:RequestServerVersion Version="Exchange2010_SP2"/>
    </soap:Header>`
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  %s
  <soap:Body>%s</soap:Body>
</soap:Envelope>`, header, body)
}

// xmlEscape minimally escapes XML special characters so the SOAP
// payloads we hand-build above don't break on user data.
func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
