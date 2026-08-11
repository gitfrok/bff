package session

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/gitfrok/bff/internal/aggregate"
)

// The Valkey store is proved against a real Valkey and nothing else. A fake speaking the same
// protocol would prove the calls are well-formed, which is not the claim — the claim is that a
// session survives a process restart, that expiry is the server's, and that a delete is immediate.
//
//	GITFROK_TEST_VALKEY_ADDR=127.0.0.1:6379 go test ./internal/session/
//
// Skipping without it is deliberate: a test that quietly passes without its infrastructure is
// evidence of nothing.
const valkeyAddrEnv = "GITFROK_TEST_VALKEY_ADDR"

func liveValkey(t *testing.T) *Valkey {
	t.Helper()
	addr := os.Getenv(valkeyAddrEnv)
	if addr == "" {
		t.Skipf("%s is not set — no live Valkey to prove anything against", valkeyAddrEnv)
	}
	store, err := Dial(t.Context(), addr, os.Getenv("GITFROK_TEST_VALKEY_PASSWORD"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestLiveValkeyRoundTrip(t *testing.T) {
	store := liveValkey(t)
	read := aggregate.ReadContext{
		TenantID: "tenant-a", ActorID: "actor-a", RequestID: "request-a",
		ActorRoles: []string{"reader", "member"},
	}

	id, err := store.Create(t.Context(), read, time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), id) })

	got, err := store.Load(t.Context(), id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.TenantID != read.TenantID || got.ActorID != read.ActorID || got.RequestID != read.RequestID {
		t.Errorf("identity did not survive the round trip: %+v", got)
	}
	//arch:allow-inline-authz asserting that stored bytes came back unchanged; grants nothing
	if len(got.ActorRoles) != 2 || got.ActorRoles[0] != "reader" || got.ActorRoles[1] != "member" {
		t.Errorf("roles did not survive the round trip: %+v", got.ActorRoles)
	}
}

// The store is what makes a session outlive the process that minted it. Two independent clients are
// the closest a test gets to a restart, and it is the property the in-memory store cannot have.
func TestLiveValkeySessionSurvivesAnotherProcess(t *testing.T) {
	store := liveValkey(t)
	id, err := store.Create(t.Context(), aggregate.ReadContext{TenantID: "t", ActorID: "a", RequestID: "r"}, time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), id) })

	other := liveValkey(t)
	if _, err := other.Load(t.Context(), id); err != nil {
		t.Fatalf("a second client could not resolve the session: %v", err)
	}
}

// ADR-0049 decision 4: revocation is deletion, and it is immediate.
func TestLiveValkeyDeleteIsImmediate(t *testing.T) {
	store := liveValkey(t)
	id, err := store.Create(t.Context(), aggregate.ReadContext{TenantID: "t", ActorID: "a", RequestID: "r"}, time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.Delete(t.Context(), id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.Load(t.Context(), id); !errors.Is(err, ErrNoSession) {
		t.Errorf("a deleted session must be gone, got %v", err)
	}
}

// Expiry is the server's, set once at creation. A key with no TTL would outlive the bound ADR-0049
// fixes, and nothing in a response would reveal it.
func TestLiveValkeyExpiryIsTheServersAndBounded(t *testing.T) {
	store := liveValkey(t)
	id, err := store.Create(t.Context(), aggregate.ReadContext{TenantID: "t", ActorID: "a", RequestID: "r"}, time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), id) })

	ttl, err := store.client.TTL(t.Context(), keyPrefix+id).Result()
	if err != nil {
		t.Fatalf("ttl: %v", err)
	}
	if ttl <= 0 || ttl > time.Minute {
		t.Errorf("expected a bounded server-side TTL, got %v", ttl)
	}
}

// ADR-0049 decision 5's idle half: using a session refreshes its window. Proved by letting the TTL
// visibly decay and checking a load pushes it back up.
func TestLiveValkeyLoadRefreshesTheIdleWindow(t *testing.T) {
	store := liveValkey(t)
	store.idle = 2 * time.Second

	id, err := store.Create(t.Context(), aggregate.ReadContext{TenantID: "t", ActorID: "a", RequestID: "r"}, time.Hour)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), id) })

	time.Sleep(1100 * time.Millisecond)
	before, err := store.client.PTTL(t.Context(), keyPrefix+id).Result()
	if err != nil {
		t.Fatalf("pttl: %v", err)
	}
	if before >= 1100*time.Millisecond {
		t.Fatalf("expected the idle window to have decayed, got %v", before)
	}
	if _, err := store.Load(t.Context(), id); err != nil {
		t.Fatalf("load: %v", err)
	}
	after, err := store.client.PTTL(t.Context(), keyPrefix+id).Result()
	if err != nil {
		t.Fatalf("pttl: %v", err)
	}
	if after <= before {
		t.Errorf("a load must refresh the idle window: %v then %v", before, after)
	}
}

// ...and the absolute deadline is not refreshable. Activity extends the idle window; nothing extends
// the record's own hard stop, so a busy session still retires on time.
func TestLiveValkeyUseCannotOutlastTheAbsoluteDeadline(t *testing.T) {
	store := liveValkey(t)
	store.idle = time.Hour // idle far longer than the absolute lifetime, so only the deadline can end it

	id, err := store.Create(t.Context(), aggregate.ReadContext{TenantID: "t", ActorID: "a", RequestID: "r"}, time.Second)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), id) })

	// Keep using it across the deadline. Each load refreshes the idle window and must not move the
	// deadline, so the session has to die anyway.
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		_, err = store.Load(t.Context(), id)
		if errors.Is(err, ErrNoSession) {
			return
		}
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Error("a session used continuously outlived its absolute deadline")
}

// A key whose TTL was extended out of band — a manual EXPIRE, a restored snapshot — must not
// resolve past the record's deadline. The record is the authority; the TTL is only the sweeper.
func TestLiveValkeyRecordDeadlineBeatsTheKeyTTL(t *testing.T) {
	store := liveValkey(t)
	id, err := store.Create(t.Context(), aggregate.ReadContext{TenantID: "t", ActorID: "a", RequestID: "r"}, time.Second)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), id) })

	if err := store.client.Expire(t.Context(), keyPrefix+id, time.Hour).Err(); err != nil {
		t.Fatalf("expire: %v", err)
	}
	time.Sleep(1100 * time.Millisecond)

	if _, err := store.Load(t.Context(), id); !errors.Is(err, ErrNoSession) {
		t.Errorf("expected the record's deadline to win, got %v", err)
	}
	if n, err := store.client.Exists(t.Context(), keyPrefix+id).Result(); err != nil || n != 0 {
		t.Errorf("a session past its deadline must be deleted, exists=%d err=%v", n, err)
	}
}

// A record written without a deadline is not a session. Failing closed keeps a foreign or
// half-migrated value from resolving to an identity with no hard stop at all.
func TestLiveValkeyRecordWithoutADeadlineIsRefused(t *testing.T) {
	store := liveValkey(t)
	key := keyPrefix + "deadlineless"
	if err := store.client.Set(t.Context(), key, `{"tenant_id":"t","actor_id":"a"}`, time.Minute).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _ = store.client.Del(context.Background(), key).Err() })

	if _, err := store.Load(t.Context(), "deadlineless"); !errors.Is(err, ErrNoSession) {
		t.Errorf("expected ErrNoSession, got %v", err)
	}
}

func TestLiveValkeyExpiredSessionIsNoSession(t *testing.T) {
	store := liveValkey(t)
	id, err := store.Create(t.Context(), aggregate.ReadContext{TenantID: "t", ActorID: "a", RequestID: "r"}, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		_, err = store.Load(t.Context(), id)
		if errors.Is(err, ErrNoSession) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("session outlived its TTL, last error %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// An unknown identifier and a corrupt record must both refuse, and must refuse the same way: the
// caller learns only that there is no usable session.
func TestLiveValkeyRefusesUnknownAndCorruptRecords(t *testing.T) {
	store := liveValkey(t)

	if _, err := store.Load(t.Context(), "never-issued"); !errors.Is(err, ErrNoSession) {
		t.Errorf("unknown identifier: expected ErrNoSession, got %v", err)
	}
	if _, err := store.Load(t.Context(), ""); !errors.Is(err, ErrNoSession) {
		t.Errorf("empty identifier: expected ErrNoSession, got %v", err)
	}

	// A value this store did not write — foreign, or corrupt — is not a partial identity.
	if err := store.client.Set(t.Context(), keyPrefix+"corrupt", "not json", time.Minute).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _ = store.client.Del(context.Background(), keyPrefix+"corrupt").Err() })
	if _, err := store.Load(t.Context(), "corrupt"); !errors.Is(err, ErrNoSession) {
		t.Errorf("corrupt record: expected ErrNoSession, got %v", err)
	}

	// A record missing the tenant is the dangerous shape: it would resolve to an actor with no
	// tenant scope, which invariant 1 forbids reaching a backend call at all.
	if err := store.client.Set(t.Context(), keyPrefix+"tenantless", `{"actor_id":"a"}`, time.Minute).Err(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _ = store.client.Del(context.Background(), keyPrefix+"tenantless").Err() })
	if _, err := store.Load(t.Context(), "tenantless"); !errors.Is(err, ErrNoSession) {
		t.Errorf("tenantless record: expected ErrNoSession, got %v", err)
	}
}

// A session never carries a repository: that is per-request input. If it did, a session could scope
// a read the browser never asked for.
func TestLiveValkeyNeverStoresARepository(t *testing.T) {
	store := liveValkey(t)
	id, err := store.Create(t.Context(), aggregate.ReadContext{
		TenantID: "t", ActorID: "a", RequestID: "r", RepositoryID: "should-not-persist",
	}, time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), id) })

	got, err := store.Load(t.Context(), id)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.RepositoryID != "" {
		t.Errorf("a session must not assert a repository, got %q", got.RepositoryID)
	}
}

// Dial is the startup gate ADR-0052 decision 4 requires: an unreachable configured store is an
// error, never a silent fallback.
func TestDialRefusesAnUnreachableStore(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := Dial(ctx, "127.0.0.1:1", ""); err == nil {
		t.Error("expected an error from an address nothing serves")
	}
	if _, err := Dial(ctx, "", ""); err == nil {
		t.Error("expected an error when no address is configured")
	}
}

// The Manager treats the two stores identically, so the browser path cannot depend on which one is
// configured. Proved through the Manager rather than the store to pin the seam that matters.
func TestManagerBehavesTheSameOnEitherStore(t *testing.T) {
	stores := map[string]Store{"memory": NewMemory()}
	if addr := os.Getenv(valkeyAddrEnv); addr != "" {
		stores["valkey"] = liveValkey(t)
	}
	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			manager := NewManager(store)
			read := aggregate.ReadContext{TenantID: "t", ActorID: "a", RequestID: "r"}
			id, err := manager.Begin(t.Context(), read)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			t.Cleanup(func() { _ = manager.Revoke(context.Background(), id) })
			if id == "" {
				t.Fatal("expected an identifier")
			}
			if err := manager.Revoke(t.Context(), id); err != nil {
				t.Fatalf("revoke: %v", err)
			}
			if _, err := store.Load(t.Context(), id); !errors.Is(err, ErrNoSession) {
				t.Errorf("revoked session still resolves: %v", err)
			}
		})
	}
}
