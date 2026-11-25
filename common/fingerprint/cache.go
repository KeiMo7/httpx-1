package fingerprint

import (
	"fmt"
	"sync"
	"time"
)

// DefaultNegativeTTL is how long a failed load is remembered before the next
// call for the same key retries it.
const DefaultNegativeTTL = 5 * time.Second

// Clock is the time source of a Cache. It is injectable so tests can drive
// negative cache expiry without sleeping.
type Clock interface {
	Now() time.Time
}

// realClock is the default Clock, backed by the system clock.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// call is a single in-flight or finished load. Waiters close done and read
// value/err; the leader owns the load.
type call struct {
	done  chan struct{}
	value any
	err   error

	// bookkeeping for the LRU
	lastUsed uint64
	// negativeUntil is the time after which a failed load is retried.
	negativeUntil time.Time
	// failed marks entries produced by a failed load.
	failed bool
}

// CacheStats reports cache activity.
type CacheStats struct {
	Hits      int
	Misses    int
	Loads     int
	Evictions int
}

// Cache is a bounded, single-flight, concurrency-safe cache. Concurrent calls
// for one key execute the loader once and share its result and error.
type Cache struct {
	mu      sync.Mutex
	clock   Clock
	size    int
	entries map[string]*call
	uses    uint64 // monotonically increasing LRU stamp
	stats   CacheStats
}

// NewCache returns a cache holding at most size entries. A size of 0 (or less)
// disables caching: every call runs load. A nil clock selects the system
// clock.
func NewCache(size int, clock Clock) *Cache {
	if clock == nil {
		clock = realClock{}
	}
	return &Cache{
		clock:   clock,
		size:    size,
		entries: make(map[string]*call),
	}
}

// Stats returns a snapshot of the cache counters.
func (c *Cache) Stats() CacheStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// GetOrLoad returns the cached value of key, calling load once if there is no
// live entry. cached reports whether an existing entry was reused. A failed
// load is remembered for DefaultNegativeTTL and its error is shared with all
// concurrent waiters.
func (c *Cache) GetOrLoad(key string, load func() (any, error)) (value any, cached bool, err error) {
	if c.size <= 0 {
		v, err := load()
		return v, false, err
	}

	c.mu.Lock()
	if existing, ok := c.entries[key]; ok {
		if done := existing.done; done != nil {
			// A load is in flight: wait for it without holding the lock. The
			// channel is captured before unlocking: the leader clears the
			// field once it completes.
			c.mu.Unlock()
			<-done
			c.mu.Lock()
			if !existing.failed || c.clock.Now().Before(existing.negativeUntil) {
				c.stats.Hits++
				c.touch(existing)
				c.mu.Unlock()
				return existing.value, true, existing.err
			}
			// The negative entry expired: fall through and reload.
		} else if !existing.failed || c.clock.Now().Before(existing.negativeUntil) {
			c.stats.Hits++
			c.touch(existing)
			c.mu.Unlock()
			return existing.value, true, existing.err
		}
		// Dead negative entry: drop it and reload below.
		delete(c.entries, key)
	}

	c.stats.Misses++
	entry := &call{done: make(chan struct{})}
	c.entries[key] = entry
	c.touch(entry)
	c.stats.Loads++
	// Evict before running the load so a full cache never holds more than
	// its capacity. In-flight entries are skipped, so a concurrent load is
	// never dropped mid-flight.
	c.evict()
	c.mu.Unlock()

	v, loadErr := load()

	c.mu.Lock()
	entry.value = v
	entry.err = loadErr
	done := entry.done
	entry.done = nil
	close(done)
	if loadErr != nil {
		entry.failed = true
		entry.negativeUntil = c.clock.Now().Add(DefaultNegativeTTL)
		// A failed entry is kept for the negative TTL, but does not count
		// against the value capacity in a way that hides its own eviction.
		c.evict()
	}
	c.mu.Unlock()

	c.mu.Lock()
	c.touch(entry)
	c.evict()
	c.mu.Unlock()
	return v, false, loadErr
}

// touch marks an entry as the most recently used one. The mutex must be held.
func (c *Cache) touch(entry *call) {
	c.uses++
	entry.lastUsed = c.uses
}

// evict removes finished entries while the cache holds more than its
// capacity. The entry with the smallest (lastUsed, key) is dropped first.
// Entries with a load in flight are never evicted: dropping one would let a
// second load for the same key start and break single-flight. Such a cache may
// briefly exceed its capacity and is trimmed once the loads finish.
func (c *Cache) evict() {
	for len(c.entries) > c.size {
		var victimKey string
		var victim *call
		for key, entry := range c.entries {
			if entry.done != nil {
				continue
			}
			if victim == nil || entry.lastUsed < victim.lastUsed ||
				(entry.lastUsed == victim.lastUsed && key < victimKey) {
				victimKey = key
				victim = entry
			}
		}
		if victim == nil {
			return
		}
		debug := ""
		for k, e := range c.entries {
			debug += fmt.Sprintf(" %s:%d:%v", k, e.lastUsed, e.done != nil)
		}
		fmt.Println("EVICT", victimKey, "from", debug)
		delete(c.entries, victimKey)
		c.stats.Evictions++
	}
}

// String renders a CacheStats for debugging.
func (s CacheStats) String() string {
	return fmt.Sprintf("hits=%d misses=%d loads=%d evictions=%d", s.Hits, s.Misses, s.Loads, s.Evictions)
}
