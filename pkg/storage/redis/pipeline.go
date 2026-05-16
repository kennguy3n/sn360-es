package redis

import (
	"context"
	"errors"

	goredis "github.com/redis/go-redis/v9"
)

// Pipeline is a thin builder around go-redis Pipeliner that records the
// command-to-key mapping so callers can recover ordered results. It is
// not safe for concurrent use; create one per logical batch.
//
// Typical use:
//
//	p := client.Pipeline()
//	p.QueueGet("tenant:abc:weights")
//	p.QueueHGetAll("tenant:abc:thresholds")
//	out, err := p.Exec(ctx)
//	weights := out.GetString("tenant:abc:weights")
//	thresholds := out.GetHash("tenant:abc:thresholds")
type Pipeline struct {
	pipe goredis.Pipeliner
	ops  []op
}

type opKind int

const (
	opGet opKind = iota
	opHGetAll
)

type op struct {
	kind opKind
	key  string
	// One of these will be non-nil after queuing depending on op kind.
	str  *goredis.StringCmd
	hash *goredis.MapStringStringCmd
}

// Pipeline returns a new Pipeline backed by this client.
func (c *Client) Pipeline() *Pipeline {
	return &Pipeline{pipe: c.rdb.Pipeline()}
}

// QueueGet schedules a GET for key.
func (p *Pipeline) QueueGet(key string) {
	cmd := p.pipe.Get(context.Background(), key)
	p.ops = append(p.ops, op{kind: opGet, key: key, str: cmd})
}

// QueueHGetAll schedules an HGETALL for key.
func (p *Pipeline) QueueHGetAll(key string) {
	cmd := p.pipe.HGetAll(context.Background(), key)
	p.ops = append(p.ops, op{kind: opHGetAll, key: key, hash: cmd})
}

// Len reports the number of queued operations.
func (p *Pipeline) Len() int { return len(p.ops) }

// Exec executes the pipeline. The returned Result is populated even when
// individual commands fail (e.g. missing key); callers should consult
// the per-key getters which return (zero, false, nil) for missing keys
// and (zero, false, err) for hard errors.
func (p *Pipeline) Exec(ctx context.Context) (*PipelineResult, error) {
	if len(p.ops) == 0 {
		return &PipelineResult{}, nil
	}
	if _, err := p.pipe.Exec(ctx); err != nil && !errors.Is(err, goredis.Nil) {
		// go-redis returns redis.Nil from Exec if ANY queued command
		// returned Nil. We treat that as soft and let per-key getters
		// surface the misses. Any other error is hard.
		return nil, err
	}
	res := &PipelineResult{
		strings: make(map[string]stringEntry, len(p.ops)),
		hashes:  make(map[string]hashEntry, len(p.ops)),
	}
	for _, o := range p.ops {
		switch o.kind {
		case opGet:
			v, err := o.str.Result()
			if errors.Is(err, goredis.Nil) {
				res.strings[o.key] = stringEntry{found: false}
				continue
			}
			res.strings[o.key] = stringEntry{value: v, found: err == nil, err: err}
		case opHGetAll:
			h, err := o.hash.Result()
			res.hashes[o.key] = hashEntry{value: h, found: err == nil && len(h) > 0, err: err}
		}
	}
	return res, nil
}

// PipelineResult bundles ordered results produced by Pipeline.Exec.
type PipelineResult struct {
	strings map[string]stringEntry
	hashes  map[string]hashEntry
}

type stringEntry struct {
	value string
	found bool
	err   error
}

type hashEntry struct {
	value map[string]string
	found bool
	err   error
}

// GetString returns the string value for key. found=false when the key
// was missing or wrong type.
func (r *PipelineResult) GetString(key string) (string, bool, error) {
	e, ok := r.strings[key]
	if !ok {
		return "", false, nil
	}
	return e.value, e.found, e.err
}

// GetHash returns the hash at key. found=false when missing/empty.
func (r *PipelineResult) GetHash(key string) (map[string]string, bool, error) {
	e, ok := r.hashes[key]
	if !ok {
		return nil, false, nil
	}
	return e.value, e.found, e.err
}
