package webhook

import (
	"fmt"

	"github.com/kennguy3n/sn360-es/internal/repository"
)

// ContentTypeForFormat returns the HTTP Content-Type the customer
// endpoint will receive. SIEM ingest pipelines are picky about this
// because their parser dispatches on it.
func ContentTypeForFormat(f repository.WebhookSinkFormat) string {
	switch f {
	case repository.WebhookSinkFormatECS:
		return "application/json; charset=utf-8"
	case repository.WebhookSinkFormatCEF:
		// CEF wire format is plaintext (single-line records).
		// `application/x-cef` is what ArcSight Smart Connectors
		// advertise; receivers that don't recognise it fall back
		// to `text/plain`. We emit the former so the customer's
		// connector can route correctly.
		return "application/x-cef; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

// FormatEvent renders the event in the requested format.
//
// The returned byte slice is the *exact* payload the dispatcher
// will sign and POST. Callers must not mutate the slice between
// formatting and signing — the HMAC is computed over these bytes.
func FormatEvent(e *Event, f repository.WebhookSinkFormat) ([]byte, error) {
	switch f {
	case repository.WebhookSinkFormatECS:
		return formatECS(e)
	case repository.WebhookSinkFormatCEF:
		return formatCEF(e)
	default:
		return nil, fmt.Errorf("webhook: unsupported format %q", f)
	}
}
