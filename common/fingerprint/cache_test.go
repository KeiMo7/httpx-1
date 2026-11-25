package fingerprint_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/httpx/common/fingerprint"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func TestCacheSingleFlight(t *testing.T) {
	cache := fingerprint.NewCache(64, nil)
	var calls atomic.Int32
	load := func() (any, error) {
		calls.Add(1)
		time.Sleep(10 * time.Millisecond)
		return "value", nil
	}

	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			if value, _, err := cache.GetOrLoad("key", load); err != nil || value != "value" {
				t.Errorf("unexpected result: %v %v", value, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := calls.Load(); got != 1 {
		t.Fatalf("expected one load, got %d", got)
	}
	stats := cache.Stats()
	if stats.Loads != 1 {
		t.Fatalf("expected one counted load, got %+v", stats)
	}
}

func TestCacheSharesError(t *testing.T) {
	cache := fingerprint.NewCache(16, nil)
	wantErr := errors.New("boom")
	var calls atomic.Int32
	load := func() (any, error) {
		calls.Add(1)
		time.Sleep(5 * time.Millisecond)
		return nil, wantErr
	}

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := cache.GetOrLoad("key", load)
			if !errors.Is(err, wantErr) {
				t.Errorf("waiters must receive the same error, got %v", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("expected one load, got %d", calls.Load())
	}
	// The failed result is cached: a following call within the TTL reuses it.
	if _, cached, err := cache.GetOrLoad("key", load); !cached || !errors.Is(err, wantErr) {
		t.Fatalf("negative cache miss: cached=%v err=%v", cached, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("the negative entry should be reused, got %d loads", calls.Load())
	}
}

func TestCacheNegativeExpiry(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	cache := fingerprint.NewCache(16, clock)
	wantErr := errors.New("boom")
	var calls atomic.Int32
	load := func() (any, error) {
		calls.Add(1)
		if calls.Load() == 1 {
			return nil, wantErr
		}
		return "ok", nil
	}

	if _, cached, err := cache.GetOrLoad("key", load); cached || !errors.Is(err, wantErr) {
		t.Fatalf("first load must run and fail: cached=%v err=%v", cached, err)
	}
	// within the negative TTL the failure is reused
	if _, cached, err := cache.GetOrLoad("key", load); !cached || !errors.Is(err, wantErr) {
		t.Fatalf("negative entry not reused: cached=%v err=%v", cached, err)
	}
	clock.advance(fingerprint.DefaultNegativeTTL + time.Second)
	// after the TTL the loader runs once more
	if value, cached, err := cache.GetOrLoad("key", load); cached || err != nil || value != "ok" {
		t.Fatalf("reload after expiry: cached=%v err=%v value=%v", cached, err, value)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected two loads, got %d", calls.Load())
	}
	// a successful result is not written back as a negative entry
	if _, cached, err := cache.GetOrLoad("key", load); !cached || err != nil {
		t.Fatalf("successful entry not reused: cached=%v err=%v", cached, err)
	}
}

func TestCacheEvictionOrder(t *testing.T) {
	cache := fingerprint.NewCache(2, nil)
	for _, key := range []string{"k1", "k2", "k3", "k4", "k5"} {
		key := key
		_, _, err := cache.GetOrLoad(key, func() (any, error) { return key, nil })
		if err != nil {
			t.Fatalf("load %s: %v", key, err)
		}
	}
	// With capacity 2, inserting k1..k5 count one eviction each after the
	// second insert, so the survivors are the last two inserted: k4 and k5.
	if evictions := cache.Stats().Evictions; evictions != 3 {
		t.Fatalf("expected 3 evictions for 5 inserts into a 2-slot cache, got %+v", cache.Stats())
	}
	// Verify the survivors while they are still in the cache, before the
	// misses below churn the eviction order.
	for _, key := range []string{"k4", "k5"} {
		key := key
		if _, cached, _ := cache.GetOrLoad(key, func() (any, error) { return key, nil }); !cached {
			t.Fatalf("%s should have survived", key)
		}
	}
	for _, key := range []string{"k1", "k2", "k3"} {
		key := key
		if _, cached, _ := cache.GetOrLoad(key, func() (any, error) { return key, nil }); cached {
			t.Fatalf("%s should have been evicted", key)
		}
	}
}

func TestCacheStats(t *testing.T) {
	cache := fingerprint.NewCache(4, nil)
	load := func() (any, error) { return "v", nil }
	_, cached, _ := cache.GetOrLoad("a", load)
	if cached {
		t.Fatalf("first call is a miss")
	}
	_, cached, _ = cache.GetOrLoad("a", load)
	if !cached {
		t.Fatalf("second call is a hit")
	}
	_, _, _ = cache.GetOrLoad("b", load)
	_, _, _ = cache.GetOrLoad("c", load)
	_, _, _ = cache.GetOrLoad("d", load)
	_, _, _ = cache.GetOrLoad("e", load)

	stats := cache.Stats()
	if stats.Hits != 1 || stats.Misses != 5 || stats.Loads != 5 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if stats.Evictions != 1 {
		t.Fatalf("expected one eviction, got %+v", stats)
	}
}

func TestCacheDisabledAtZero(t *testing.T) {
	cache := fingerprint.NewCache(0, nil)
	var calls atomic.Int32
	for i := 0; i < 3; i++ {
		_, cached, err := cache.GetOrLoad("k", func() (any, error) {
			calls.Add(1)
			return "v", nil
		})
		if err != nil || cached {
			t.Fatalf("disabled cache must not cache: cached=%v err=%v", cached, err)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("expected 3 loads, got %d", calls.Load())
	}
}

func TestCacheConcurrentKeys(t *testing.T) {
	cache := fingerprint.NewCache(8, nil)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := []string{"a", "b", "c", "d"}[(i)%4]
			_, _, err := cache.GetOrLoad(key, func() (any, error) { return key, nil })
			if err != nil {
				t.Errorf("load: %v", err)
			}
		}(i)
	}
	wg.Wait()
}
