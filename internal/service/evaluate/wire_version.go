package evaluate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/kennguy3n/sn360-es/pkg/events"
)

// CurrentWireVersion is the version of the evaluate request wire format.
// Bump this whenever the BatchMessage or EvaluateRequest shape changes
// in a way that old consumers cannot safely unmarshal.
const CurrentWireVersion = 1

// WireVersionHeader is the header key that carries the wire format version
// on published messages.
const WireVersionHeader = "wire-format-version"

// ErrWireVersionMismatch is returned when a consumer receives a message
// with a wire format version it cannot handle.
var ErrWireVersionMismatch = errors.New("evaluate: wire format version mismatch")

// VersionedMessage wraps a BatchMessage with wire format metadata.
type VersionedMessage struct {
	WireVersion int          `json:"wire_format_version"`
	Request     BatchMessage `json:"payload"`
}

// MarshalVersioned serialises a BatchMessage with the current wire
// format version embedded in the JSON and set as a message header.
func MarshalVersioned(msg BatchMessage) ([]byte, []events.PublishOption, error) {
	vm := VersionedMessage{
		WireVersion: CurrentWireVersion,
		Request:     msg,
	}
	data, err := json.Marshal(vm)
	if err != nil {
		return nil, nil, fmt.Errorf("wire_version: marshal: %w", err)
	}
	opts := []events.PublishOption{
		events.WithHeader(WireVersionHeader, fmt.Sprintf("%d", CurrentWireVersion)),
	}
	return data, opts, nil
}

// UnmarshalVersioned deserialises a VersionedMessage and checks the wire
// format version. Returns ErrWireVersionMismatch with a clear error
// message (not a silent unmarshal failure) when the version doesn't match.
func UnmarshalVersioned(data []byte) (BatchMessage, error) {
	var vm VersionedMessage
	if err := json.Unmarshal(data, &vm); err != nil {
		return BatchMessage{}, fmt.Errorf("wire_version: unmarshal: %w", err)
	}
	if vm.WireVersion != CurrentWireVersion {
		return BatchMessage{}, fmt.Errorf("%w: expected %d, got %d",
			ErrWireVersionMismatch, CurrentWireVersion, vm.WireVersion)
	}
	return vm.Request, nil
}

// VersionCheckMiddleware wraps a MessageHandler with wire format version
// validation. Messages with mismatched versions are rejected with a clear
// error instead of silently failing to unmarshal.
func VersionCheckMiddleware(next events.MessageHandler, log *slog.Logger) events.MessageHandler {
	return func(ctx context.Context, msg events.Message) error {
		headers := msg.Headers()
		versionStr, ok := headers[WireVersionHeader]
		if ok {
			var version int
			if _, err := fmt.Sscanf(versionStr, "%d", &version); err == nil {
				if version != CurrentWireVersion {
					log.WarnContext(ctx, "wire_version: rejecting message with mismatched version",
						slog.Int("expected", CurrentWireVersion),
						slog.Int("got", version),
						slog.String("subject", msg.Subject()))
					// Ack instead of nak to prevent infinite redelivery of
					// permanently incompatible messages.
					_ = msg.Ack()
					return nil
				}
			}
		}
		return next(ctx, msg)
	}
}

// VersionedPublisher wraps a Sink to automatically add wire format
// version headers to published messages.
type VersionedPublisher struct {
	inner Sink
}

// NewVersionedPublisher wraps a Sink with automatic version headers.
func NewVersionedPublisher(inner Sink) *VersionedPublisher {
	return &VersionedPublisher{inner: inner}
}

// Publish adds the wire version header and delegates to the inner sink.
func (p *VersionedPublisher) Publish(ctx context.Context, subject string, data []byte, opts ...events.PublishOption) error {
	opts = append(opts, events.WithHeader(WireVersionHeader, fmt.Sprintf("%d", CurrentWireVersion)))
	return p.inner.Publish(ctx, subject, data, opts...)
}

// compile-time assertion
var _ Sink = (*VersionedPublisher)(nil)
