package s3

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"
)

func TestInMemoryStore_PutGetDelete(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryStore()
	if err := store.Put(ctx, "k1", []byte("hello"),
		WithContentType("text/plain"),
		WithMetadata(map[string]string{"x": "1"}),
	); err != nil {
		t.Fatalf("Put: %v", err)
	}
	obj, err := store.Get(ctx, "k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(obj.Body) != "hello" {
		t.Fatalf("body: %q", obj.Body)
	}
	if obj.ContentType != "text/plain" {
		t.Fatalf("content type: %q", obj.ContentType)
	}
	if obj.Metadata["x"] != "1" {
		t.Fatalf("metadata: %+v", obj.Metadata)
	}
	if err := store.Delete(ctx, "k1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, "k1"); !errors.Is(err, ErrObjectNotFound) {
		t.Fatalf("Get after delete: %v", err)
	}
}

func TestInMemoryStore_RequiresKey(t *testing.T) {
	store := NewInMemoryStore()
	if err := store.Put(context.Background(), "", nil); err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestInMemoryStore_List(t *testing.T) {
	ctx := context.Background()
	store := NewInMemoryStore()
	for _, k := range []string{"a/1", "a/2", "b/1"} {
		_ = store.Put(ctx, k, []byte(k))
	}
	keys, err := store.List(ctx, "a/", 0)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	sort.Strings(keys)
	if len(keys) != 2 || keys[0] != "a/1" || keys[1] != "a/2" {
		t.Fatalf("expected [a/1 a/2], got %v", keys)
	}
	limited, err := store.List(ctx, "", 1)
	if err != nil {
		t.Fatalf("List limited: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("expected 1, got %v", limited)
	}
}

func TestCopyStream(t *testing.T) {
	store := NewInMemoryStore()
	if err := CopyStream(context.Background(), store, "k", bytes.NewBufferString("data"),
		WithContentType("application/octet-stream"),
	); err != nil {
		t.Fatalf("CopyStream: %v", err)
	}
	obj, err := store.Get(context.Background(), "k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(obj.Body) != "data" || obj.ContentType != "application/octet-stream" {
		t.Fatalf("body: %+v", obj)
	}
}
