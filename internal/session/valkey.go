package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"

	//arch:allow-session-store ADR-0052 — the BFF's own session state, never another context's data
	"github.com/redis/go-redis/v9"
)

// Valkey is the shared session store ADR-0049 decision 5 names, reached with a Redis-protocol
// client because Valkey is a drop-in replacement (ADR-0023).
//
// This is the one datastore the BFF is permitted to open, and ADR-0052 is the whole of that
// permission: a session record holds what the BFF minted at the OIDC callback — tenant, actor,
// roles, expiry — and nothing another context owns. Reading any other key through this client is
// still the cross-context access invariant 15 forbids.
//
// The record's absolute expiry is the key's TTL. The BFF sets it at creation and never extends it in
// place, so ADR-0049's expiry bound holds with no sweeper: an expired session is a key that is gone.
type Valkey struct {
	client redis.UniversalClient
	prefix string
}

// keyPrefix namespaces session keys so this store can share an instance with anything else without
// a collision, and so an operator can see what a key is for.
const keyPrefix = "gitfrok:session:"

// record is what a session is on the wire. RepositoryID is deliberately absent: a repository is
// per-request input, never something a session asserts, and a session that carried one could scope a
// read the browser never asked for.
type record struct {
	TenantID   string   `json:"tenant_id"`
	ActorID    string   `json:"actor_id"`
	RequestID  string   `json:"request_id"`
	ActorRoles []string `json:"actor_roles,omitempty"`
}

// NewValkey builds a store over an already-configured client. The caller owns the client's lifetime
// and its address, which is per-environment configuration (invariant 13).
func NewValkey(client redis.UniversalClient) *Valkey {
	return &Valkey{client: client, prefix: keyPrefix}
}

// Dial builds a client for addr and verifies it answers before returning. A configured store that
// cannot be reached is fatal to the caller by design (ADR-0052 decision 4): a BFF that quietly fell
// back to memory would look healthy while logging every user out on the next rollout.
func Dial(ctx context.Context, addr, password string) (*Valkey, error) {
	if addr == "" {
		return nil, errors.New("session: no Valkey address configured")
	}
	client := redis.NewClient(&redis.Options{Addr: addr, Password: password})
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("session: Valkey at %s did not answer: %w", addr, err)
	}
	return NewValkey(client), nil
}

// Close releases the underlying client.
func (v *Valkey) Close() error { return v.client.Close() }

func (v *Valkey) Create(ctx context.Context, read aggregate.ReadContext, ttl time.Duration) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(record{
		TenantID:   read.TenantID,
		ActorID:    read.ActorID,
		RequestID:  read.RequestID,
		ActorRoles: read.ActorRoles,
	})
	if err != nil {
		return "", err
	}
	// SetNX rather than Set: an identifier is 256 bits from a cryptographic source, so a collision
	// is not a real event — but if one ever happened, overwriting would silently re-point a live
	// session at another actor, and that is not a failure mode worth leaving open.
	ok, err := v.client.SetNX(ctx, v.prefix+id, body, ttl).Result()
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("session: identifier already in use")
	}
	return id, nil
}

func (v *Valkey) Load(ctx context.Context, id string) (aggregate.ReadContext, error) {
	if id == "" {
		return aggregate.ReadContext{}, ErrNoSession
	}
	body, err := v.client.Get(ctx, v.prefix+id).Bytes()
	if errors.Is(err, redis.Nil) {
		// Absent and expired are the same answer here, which is the point: a refusal must not say
		// which, or it reports whether an actor once existed.
		return aggregate.ReadContext{}, ErrNoSession
	}
	if err != nil {
		return aggregate.ReadContext{}, err
	}
	var rec record
	if err := json.Unmarshal(body, &rec); err != nil {
		// A record we cannot read is not a session. Failing closed keeps a corrupt or
		// foreign-written value from resolving to a partial identity.
		return aggregate.ReadContext{}, ErrNoSession
	}
	if rec.TenantID == "" || rec.ActorID == "" {
		return aggregate.ReadContext{}, ErrNoSession
	}
	return aggregate.ReadContext{
		TenantID:   rec.TenantID,
		ActorID:    rec.ActorID,
		RequestID:  rec.RequestID,
		ActorRoles: rec.ActorRoles,
	}, nil
}

func (v *Valkey) Delete(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	return v.client.Del(ctx, v.prefix+id).Err()
}

var _ Store = (*Valkey)(nil)
