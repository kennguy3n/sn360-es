// Package s3 provides the SN360-ES object-store interface.
//
// SN360-ES uses S3-compatible object storage for two things:
//
//   - encrypted overflow bodies referenced from EvaluateRequest.BodyRef
//     when the inline body exceeds the JetStream payload budget; and
//   - encrypted tenant credentials (OAuth refresh tokens, etc.) wrapped
//     by KMS data keys.
//
// The package exposes a narrow ObjectStore interface plus an in-memory
// implementation used by tests and the local docker-compose stack. A
// real AWS S3 implementation is registered behind a build tag in
// future work (`pkg/storage/s3/aws.go`) so that the AWS SDK is not a
// hard dependency of the core service binary.
package s3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// ErrObjectNotFound is returned when Get is called with an unknown key.
var ErrObjectNotFound = errors.New("s3: object not found")

// Object is a single stored object as returned by Get.
type Object struct {
	// Body holds the raw bytes. The caller owns the slice.
	Body []byte
	// ContentType mirrors the value passed to Put (default: empty).
	ContentType string
	// Metadata is a small user-defined map (mirrors S3 x-amz-meta-*).
	Metadata map[string]string
	// UpdatedAt is when the object was last written.
	UpdatedAt time.Time
}

// ObjectStore is the canonical SN360-ES object-store interface. Real
// implementations should be safe for concurrent use.
type ObjectStore interface {
	// Get fetches an object by bucket-relative key. Returns
	// ErrObjectNotFound when the key does not exist.
	Get(ctx context.Context, key string) (Object, error)
	// Put stores body under key, replacing any existing value.
	Put(ctx context.Context, key string, body []byte, opts ...PutOption) error
	// Delete removes the object at key. Returns nil if the key did
	// not exist (idempotent).
	Delete(ctx context.Context, key string) error
	// List returns keys with the given prefix, capped at limit.
	// limit <= 0 means "no cap (returns all keys)".
	List(ctx context.Context, prefix string, limit int) ([]string, error)
}

// PutOption mutates the per-call PutOptions.
type PutOption func(*PutOptions)

// PutOptions resolves all PutOption helpers.
type PutOptions struct {
	ContentType string
	Metadata    map[string]string
}

// WithContentType sets the content-type recorded with the object.
func WithContentType(s string) PutOption {
	return func(o *PutOptions) { o.ContentType = s }
}

// WithMetadata copies kv into the object metadata. Existing keys are
// overwritten.
func WithMetadata(kv map[string]string) PutOption {
	return func(o *PutOptions) {
		if o.Metadata == nil {
			o.Metadata = make(map[string]string, len(kv))
		}
		for k, v := range kv {
			o.Metadata[k] = v
		}
	}
}

// resolve applies all options to a fresh struct.
func resolvePutOptions(opts ...PutOption) PutOptions {
	p := PutOptions{}
	for _, o := range opts {
		o(&p)
	}
	return p
}

// InMemoryStore is a goroutine-safe in-process implementation of
// ObjectStore. It is used by tests and the local docker-compose stack
// where standing up a full S3 service is overkill.
type InMemoryStore struct {
	mu      sync.RWMutex
	objects map[string]Object
	clock   func() time.Time
}

// NewInMemoryStore returns a fresh InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		objects: make(map[string]Object),
		clock:   time.Now,
	}
}

// Get implements ObjectStore.
func (m *InMemoryStore) Get(_ context.Context, key string) (Object, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	obj, ok := m.objects[key]
	if !ok {
		return Object{}, ErrObjectNotFound
	}
	cp := obj
	cp.Body = append([]byte(nil), obj.Body...)
	cp.Metadata = copyMap(obj.Metadata)
	return cp, nil
}

// Put implements ObjectStore.
func (m *InMemoryStore) Put(_ context.Context, key string, body []byte, opts ...PutOption) error {
	if key == "" {
		return errors.New("s3: key is required")
	}
	cfg := resolvePutOptions(opts...)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = Object{
		Body:        append([]byte(nil), body...),
		ContentType: cfg.ContentType,
		Metadata:    copyMap(cfg.Metadata),
		UpdatedAt:   m.clock(),
	}
	return nil
}

// Delete implements ObjectStore.
func (m *InMemoryStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	return nil
}

// List implements ObjectStore.
func (m *InMemoryStore) List(_ context.Context, prefix string, limit int) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.objects))
	for k := range m.objects {
		if prefix == "" || hasPrefix(k, prefix) {
			out = append(out, k)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

// CopyStream is a convenience helper: read body from r into memory and
// Put it under key. Useful for streaming sources (file uploads, etc.).
func CopyStream(ctx context.Context, store ObjectStore, key string, r io.Reader, opts ...PutOption) error {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return err
	}
	return store.Put(ctx, key, buf.Bytes(), opts...)
}

func hasPrefix(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	return s[:len(prefix)] == prefix
}

func copyMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
