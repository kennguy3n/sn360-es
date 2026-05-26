package workmail

import (
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
	"time"
)

// EWS responses live inside an m:FindItemResponse / m:GetItemResponse
// / m:CreateFolderResponse element. We decode the small subset of
// fields we need below.

type findItemResponseMessage struct {
	XMLName       xml.Name `xml:"FindItemResponseMessage"`
	ResponseClass string   `xml:"ResponseClass,attr"`
	RootFolder    struct {
		Items struct {
			Messages []ewsMessage `xml:"Message"`
		} `xml:"Items"`
	} `xml:"RootFolder"`
}

type ewsMessage struct {
	ItemID struct {
		ID        string `xml:"Id,attr"`
		ChangeKey string `xml:"ChangeKey,attr"`
	} `xml:"ItemId"`
	Subject      string `xml:"Subject"`
	DateReceived string `xml:"DateTimeReceived"`
	From         struct {
		Mailbox struct {
			EmailAddress string `xml:"EmailAddress"`
		} `xml:"Mailbox"`
	} `xml:"From"`
	ToRecipients struct {
		Mailbox []struct {
			EmailAddress string `xml:"EmailAddress"`
		} `xml:"Mailbox"`
	} `xml:"ToRecipients"`
	CcRecipients struct {
		Mailbox []struct {
			EmailAddress string `xml:"EmailAddress"`
		} `xml:"Mailbox"`
	} `xml:"CcRecipients"`
	Body struct {
		BodyType string `xml:"BodyType,attr"`
		Value    string `xml:",chardata"`
	} `xml:"Body"`
}

// parseFindItems extracts the items from an EWS FindItem response body.
func parseFindItems(raw []byte) ([]EWSItem, error) {
	var wrap struct {
		FindItemResponse struct {
			ResponseMessages struct {
				Find findItemResponseMessage `xml:"FindItemResponseMessage"`
			} `xml:"ResponseMessages"`
		} `xml:"FindItemResponse"`
	}
	if err := xml.Unmarshal(envelopeBody(raw), &wrap); err != nil {
		return nil, fmt.Errorf("workmail: parse FindItem: %w", err)
	}
	resp := wrap.FindItemResponse.ResponseMessages.Find
	if resp.ResponseClass != "" && resp.ResponseClass != "Success" {
		return nil, fmt.Errorf("workmail: FindItem class=%s", resp.ResponseClass)
	}
	msgs := resp.RootFolder.Items.Messages
	out := make([]EWSItem, 0, len(msgs))
	for _, m := range msgs {
		received, _ := time.Parse(time.RFC3339, m.DateReceived)
		item := EWSItem{
			ID:           m.ItemID.ID,
			ChangeKey:    m.ItemID.ChangeKey,
			Subject:      m.Subject,
			DateReceived: received.UTC(),
			From:         m.From.Mailbox.EmailAddress,
		}
		for _, t := range m.ToRecipients.Mailbox {
			item.To = append(item.To, t.EmailAddress)
		}
		for _, t := range m.CcRecipients.Mailbox {
			item.Cc = append(item.Cc, t.EmailAddress)
		}
		out = append(out, item)
	}
	return out, nil
}

// parseGetItemBody pulls the BodyType + Value pair out of a GetItem
// response.
func parseGetItemBody(raw []byte) (EWSMessageBody, error) {
	var wrap struct {
		GetItemResponse struct {
			ResponseMessages struct {
				Resp struct {
					ResponseClass string `xml:"ResponseClass,attr"`
					Items         struct {
						Messages []ewsMessage `xml:"Message"`
					} `xml:"Items"`
				} `xml:"GetItemResponseMessage"`
			} `xml:"ResponseMessages"`
		} `xml:"GetItemResponse"`
	}
	if err := xml.Unmarshal(envelopeBody(raw), &wrap); err != nil {
		return EWSMessageBody{}, fmt.Errorf("workmail: parse GetItem: %w", err)
	}
	if wrap.GetItemResponse.ResponseMessages.Resp.ResponseClass != "" &&
		wrap.GetItemResponse.ResponseMessages.Resp.ResponseClass != "Success" {
		return EWSMessageBody{}, fmt.Errorf("workmail: GetItem class=%s",
			wrap.GetItemResponse.ResponseMessages.Resp.ResponseClass)
	}
	msgs := wrap.GetItemResponse.ResponseMessages.Resp.Items.Messages
	if len(msgs) == 0 {
		return EWSMessageBody{}, errors.New("workmail: GetItem returned no messages")
	}
	return EWSMessageBody{BodyType: msgs[0].Body.BodyType, Content: msgs[0].Body.Value}, nil
}

// parseCreatedFolderID extracts the new folder's id from a
// CreateFolder response.
func parseCreatedFolderID(raw []byte) (string, error) {
	var wrap struct {
		CreateFolderResponse struct {
			ResponseMessages struct {
				Resp struct {
					ResponseClass string `xml:"ResponseClass,attr"`
					Folders       struct {
						Folder []struct {
							FolderID struct {
								ID        string `xml:"Id,attr"`
								ChangeKey string `xml:"ChangeKey,attr"`
							} `xml:"FolderId"`
						} `xml:"Folder"`
					} `xml:"Folders"`
				} `xml:"CreateFolderResponseMessage"`
			} `xml:"ResponseMessages"`
		} `xml:"CreateFolderResponse"`
	}
	if err := xml.Unmarshal(envelopeBody(raw), &wrap); err != nil {
		return "", fmt.Errorf("workmail: parse CreateFolder: %w", err)
	}
	resp := wrap.CreateFolderResponse.ResponseMessages.Resp
	if resp.ResponseClass != "" && resp.ResponseClass != "Success" {
		return "", fmt.Errorf("workmail: CreateFolder class=%s", resp.ResponseClass)
	}
	if len(resp.Folders.Folder) == 0 {
		return "", errors.New("workmail: CreateFolder returned no folder")
	}
	return resp.Folders.Folder[0].FolderID.ID, nil
}

// parseMoveItemID extracts the new ItemId.Id from a MoveItem
// response. EWS's MoveItem reissues the ItemId on success (because
// items are folder-scoped in Exchange); the caller persists the
// returned id so subsequent operations (e.g. release) reference the
// message that actually exists at the destination. Returns "" with
// nil error when the response is well-formed but omits the ItemId
// (an EWS-server quirk worth surfacing to the caller, which then
// falls back to the input id).
func parseMoveItemID(raw []byte) (string, error) {
	var wrap struct {
		MoveItemResponse struct {
			ResponseMessages struct {
				Resp struct {
					ResponseClass string `xml:"ResponseClass,attr"`
					Items         struct {
						Messages []struct {
							ItemID struct {
								ID        string `xml:"Id,attr"`
								ChangeKey string `xml:"ChangeKey,attr"`
							} `xml:"ItemId"`
						} `xml:"Message"`
					} `xml:"Items"`
				} `xml:"MoveItemResponseMessage"`
			} `xml:"ResponseMessages"`
		} `xml:"MoveItemResponse"`
	}
	if err := xml.Unmarshal(envelopeBody(raw), &wrap); err != nil {
		return "", fmt.Errorf("workmail: parse MoveItem: %w", err)
	}
	resp := wrap.MoveItemResponse.ResponseMessages.Resp
	if resp.ResponseClass != "" && resp.ResponseClass != "Success" {
		return "", fmt.Errorf("workmail: MoveItem class=%s", resp.ResponseClass)
	}
	if len(resp.Items.Messages) == 0 {
		return "", nil
	}
	return resp.Items.Messages[0].ItemID.ID, nil
}

// parseFoundFolderID looks for a folder with the given DisplayName
// in a FindFolder response and returns its FolderId or "".
func parseFoundFolderID(raw []byte, wantedName string) (string, error) {
	var wrap struct {
		FindFolderResponse struct {
			ResponseMessages struct {
				Resp struct {
					ResponseClass string `xml:"ResponseClass,attr"`
					RootFolder    struct {
						Folders struct {
							Folder []struct {
								FolderID struct {
									ID string `xml:"Id,attr"`
								} `xml:"FolderId"`
								DisplayName string `xml:"DisplayName"`
							} `xml:"Folder"`
						} `xml:"Folders"`
					} `xml:"RootFolder"`
				} `xml:"FindFolderResponseMessage"`
			} `xml:"ResponseMessages"`
		} `xml:"FindFolderResponse"`
	}
	if err := xml.Unmarshal(envelopeBody(raw), &wrap); err != nil {
		return "", fmt.Errorf("workmail: parse FindFolder: %w", err)
	}
	resp := wrap.FindFolderResponse.ResponseMessages.Resp
	if resp.ResponseClass != "" && resp.ResponseClass != "Success" {
		return "", fmt.Errorf("workmail: FindFolder class=%s", resp.ResponseClass)
	}
	for _, f := range resp.RootFolder.Folders.Folder {
		if strings.EqualFold(f.DisplayName, wantedName) {
			return f.FolderID.ID, nil
		}
	}
	return "", nil
}

// parseCategories extracts the item:Categories string list from a
// GetItem response.
func parseCategories(raw []byte) ([]string, error) {
	var wrap struct {
		GetItemResponse struct {
			ResponseMessages struct {
				Resp struct {
					ResponseClass string `xml:"ResponseClass,attr"`
					Items         struct {
						Messages []struct {
							Categories struct {
								Strings []string `xml:"String"`
							} `xml:"Categories"`
						} `xml:"Message"`
					} `xml:"Items"`
				} `xml:"GetItemResponseMessage"`
			} `xml:"ResponseMessages"`
		} `xml:"GetItemResponse"`
	}
	if err := xml.Unmarshal(envelopeBody(raw), &wrap); err != nil {
		return nil, fmt.Errorf("workmail: parse categories: %w", err)
	}
	msgs := wrap.GetItemResponse.ResponseMessages.Resp.Items.Messages
	if len(msgs) == 0 {
		return nil, nil
	}
	return msgs[0].Categories.Strings, nil
}

// envelopeBody wraps the inner XML in a synthetic root so the
// generated unmarshal struct (which expects `<XxxResponse>` at the
// top level) works whether or not the inner XML is prefixed with an
// XML declaration. EWSClient.Invoke already strips the SOAP
// envelope; this helper just makes sure xml.Unmarshal sees a single
// well-formed document.
func envelopeBody(raw []byte) []byte {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "<?xml") {
		// Drop the declaration; xml.Unmarshal on a child fragment
		// can't have it.
		idx := strings.Index(trimmed, "?>")
		if idx >= 0 {
			trimmed = trimmed[idx+2:]
		}
	}
	return []byte(trimmed)
}
