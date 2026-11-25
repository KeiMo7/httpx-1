package runner

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrOrderTimeout is the error carried by a synthetic result when a slot was
// not pushed before OrderBuffer's timeout. It occupies its sequence number, so
// the output gap is filled without changing the order.
var ErrOrderTimeout = errors.New("order timeout")

// ErrOrderClosed is returned by Reserve once the buffer has been closed, or
// when the reserve context was canceled.
var ErrOrderClosed = errors.New("order buffer closed")

// ErrOrderSlotUnknown is returned when a slot that was never reserved, or that
// has already been emitted, is pushed or skipped.
var ErrOrderSlotUnknown = errors.New("order slot unknown")

// ErrOrderSlotDuplicate is returned when the same slot is pushed twice.
var ErrOrderSlotDuplicate = errors.New("order slot duplicate")

// ErrOrderBufferFull is returned when a reservation of n slots exceeds the
// window outright.
var ErrOrderBufferFull = errors.New("order buffer window too small")

// DefaultOrderWindow is the ordering layer capacity used when none is set.
const DefaultOrderWindow = 512

// Slot is the sequence number assigned to one dispatched probe.
type Slot uint64

// slotState is the one-way state of a slot: reserved -> pending -> emitted, or
// reserved -> skipped -> emitted. A synthetic timeout moves reserved straight
// to emitted.
type slotState uint8

const (
	stateReserved slotState = iota
	statePending
	stateSkipped
	stateEmitted
)

// slotEntry is one reserved sequence number.
type slotEntry struct {
	// reserved marks a live sequence number. An emitted entry is cleared and
	// its ring cell may be reused, so a stale Slot is rejected rather than
	// resolving to a later reservation.
	live  bool
	state slotState
	// result is the record stored by Push.
	result Result
	// reservedAt is when the slot was reserved, used by the timeout
	// synthesizer.
	reservedAt time.Time
}

// OrderBuffer emits dispatched results in reservation order. Producers may
// call Reserve, Push and Skip concurrently; the single consumer goroutine
// calls FlushReady and Drain.
//
// A slot is emitted only when every earlier slot has been emitted or skipped,
// so a slow probe never reorders the output. When a slot does not arrive
// before timeout, a synthetic failed result takes its place.
type OrderBuffer struct {
	// reserveMu serializes reservations so a multi-slot range is contiguous.
	reserveMu sync.Mutex
	// reserveChanged wakes Reserve calls waiting for room.
	reserveChanged chan struct{}
	// slotReady wakes the consumer.
	slotReady chan struct{}

	mu       sync.Mutex
	entries  []*slotEntry
	capacity int
	next     uint64 // first sequence number not yet emitted
	reserved uint64 // one past the highest reserved sequence number
	closed   bool
	canceled bool
	lastErr  error
	timeout  time.Duration
}

// NewOrderBuffer returns a buffer of window slots. A non-positive timeout
// disables the synthetic timeout result while running, so a missing slot
// blocks the output until Drain; tests use that to exercise the gap logic.
func NewOrderBuffer(window int, timeout time.Duration) *OrderBuffer {
	if window <= 0 {
		window = DefaultOrderWindow
	}
	return &OrderBuffer{
		capacity:       window,
		entries:        make([]*slotEntry, window),
		timeout:        timeout,
		reserveChanged: make(chan struct{}, 1),
		slotReady:      make(chan struct{}, 1),
	}
}

// Reserve reserves n consecutive slots and returns the first one. One target
// that expands into several method and path variants reserves one range for
// all of them. It blocks while the window is full, until ctx is canceled.
func (b *OrderBuffer) Reserve(ctx context.Context, n int) (Slot, error) {
	if n <= 0 {
		return 0, fmt.Errorf("reserve count must be positive, got %d", n)
	}
	if n > b.capacity {
		return 0, fmt.Errorf("%w: %d slots for a window of %d", ErrOrderBufferFull, n, b.capacity)
	}
	for {
		b.reserveMu.Lock()
		b.mu.Lock()
		if b.closed || b.canceled {
			b.mu.Unlock()
			b.reserveMu.Unlock()
			return 0, ErrOrderClosed
		}
		inFlight := b.reserved - b.next
		if inFlight+uint64(n) <= uint64(b.capacity) {
			first := Slot(b.reserved)
			now := time.Now()
			for i := 0; i < n; i++ {
				seq := b.reserved + uint64(i)
				b.entries[seq%uint64(b.capacity)] = &slotEntry{live: true, state: stateReserved, reservedAt: now}
			}
			b.reserved += uint64(n)
			b.mu.Unlock()
			b.reserveMu.Unlock()
			b.signalReady()
			return first, nil
		}
		b.mu.Unlock()
		b.reserveMu.Unlock()

		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("%w: %w", ErrOrderClosed, ctx.Err())
		case <-b.reserveChanged:
		}
	}
}

// Push stores the result of a slot. The slot must have been reserved; pushing
// it twice returns ErrOrderSlotDuplicate. The result's Sequence is set to the
// slot, so the caller does not have to know it.
func (b *OrderBuffer) Push(slot Slot, result Result) error {
	b.mu.Lock()
	entry, err := b.entryLocked(slot)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	switch entry.state {
	case stateReserved:
		entry.state = statePending
	case statePending:
		b.mu.Unlock()
		return fmt.Errorf("%w: %d pushed twice", ErrOrderSlotDuplicate, slot)
	default:
		b.mu.Unlock()
		return fmt.Errorf("%w: %d (state %d)", ErrOrderSlotUnknown, slot, entry.state)
	}
	result.Sequence = uint64(slot)
	entry.result = result
	b.mu.Unlock()
	b.signalReady()
	return nil
}

// Skip consumes a slot without emitting a result. A filtered record calls
// Skip so the slots after it can be emitted.
func (b *OrderBuffer) Skip(slot Slot) error {
	b.mu.Lock()
	entry, err := b.entryLocked(slot)
	if err != nil {
		b.mu.Unlock()
		return err
	}
	switch entry.state {
	case stateReserved:
		entry.state = stateSkipped
	case statePending:
		b.mu.Unlock()
		return fmt.Errorf("%w: %d already pushed", ErrOrderSlotDuplicate, slot)
	default:
		b.mu.Unlock()
		return fmt.Errorf("%w: %d (state %d)", ErrOrderSlotUnknown, slot, entry.state)
	}
	b.mu.Unlock()
	b.signalReady()
	return nil
}

// entryLocked returns the entry of a live slot. The mutex must be held.
func (b *OrderBuffer) entryLocked(slot Slot) (*slotEntry, error) {
	seq := uint64(slot)
	if seq < b.next || seq >= b.reserved {
		return nil, fmt.Errorf("%w: %d", ErrOrderSlotUnknown, slot)
	}
	entry := b.entries[seq%uint64(b.capacity)]
	if entry == nil || !entry.live {
		return nil, fmt.Errorf("%w: %d", ErrOrderSlotUnknown, slot)
	}
	return entry, nil
}

// FlushReady emits every slot of the contiguous prefix that is ready, in
// order. It stops at the first slot that is still waiting (and has not timed
// out, or has no synthetic result when timeout is disabled). FlushReady may
// only be called from the consumer goroutine.
func (b *OrderBuffer) FlushReady(emit func(Result) error) error {
	return b.flush(emit, false)
}

// Drain emits every remaining slot, synthesizing an order timeout result for
// slots whose probe never pushed. It must be called from the consumer
// goroutine after all producers are done.
func (b *OrderBuffer) Drain(emit func(Result) error) error {
	return b.flush(emit, true)
}

// Close stops new reservations. Slots already reserved can still drain.
func (b *OrderBuffer) Close() {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.signalReserve()
}

// Cancel stops new reservations and makes every blocked Reserve return an
// error; already reserved slots can still drain in order.
func (b *OrderBuffer) Cancel() {
	b.mu.Lock()
	b.canceled = true
	b.closed = true
	b.mu.Unlock()
	b.signalReserve()
	b.signalReady()
}

// Wait blocks until a slot becomes ready or the timeout expires. It returns
// false on the deadline. A zero timeout waits until a slot arrives.
func (b *OrderBuffer) Wait(timeout time.Duration) bool {
	var deadline <-chan time.Time
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		deadline = t.C
	}
	select {
	case <-b.slotReady:
		return true
	case <-deadline:
		return false
	}
}

// NextTimeout reports how long the consumer may wait before the earliest
// waiting slot times out. It returns 0 when no synthetic result can be made.
func (b *OrderBuffer) NextTimeout() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.timeout <= 0 || b.next >= b.reserved {
		return 0
	}
	entry := b.entries[b.next%uint64(b.capacity)]
	if entry == nil || !entry.live || entry.state == statePending || entry.state == stateSkipped {
		return 0
	}
	elapsed := time.Since(entry.reservedAt)
	if elapsed >= b.timeout {
		return time.Nanosecond
	}
	return b.timeout - elapsed
}

func (b *OrderBuffer) flush(emit func(Result) error, drain bool) error {
	for {
		b.mu.Lock()
		if b.lastErr != nil {
			err := b.lastErr
			b.mu.Unlock()
			return err
		}
		if b.next >= b.reserved {
			b.mu.Unlock()
			return nil
		}
		entry := b.entries[b.next%uint64(b.capacity)]
		if entry == nil || !entry.live {
			b.mu.Unlock()
			return fmt.Errorf("%w: %d", ErrOrderSlotUnknown, b.next)
		}
		seq := b.next
		var result Result
		emitNow := false
		switch entry.state {
		case statePending:
			result = entry.result
			result.Sequence = seq
			entry.live = false
			emitNow = true
		case stateSkipped:
			entry.live = false
		case stateEmitted:
			// Not reachable while the ring invariant holds; clear the cell so
			// the sequence still advances.
			entry.live = false
		case stateReserved:
			if !drain && b.timeout <= 0 {
				b.mu.Unlock()
				return nil
			}
			if !drain && time.Since(entry.reservedAt) < b.timeout {
				b.mu.Unlock()
				return nil
			}
			result = Result{
				Sequence: seq,
				Failed:   true,
				Error:    ErrOrderTimeout.Error(),
				Err:      ErrOrderTimeout,
			}
			entry.live = false
			emitNow = true
		}
		b.next++
		b.mu.Unlock()
		b.signalReserve()
		if !emitNow {
			continue
		}
		if err := emit(result); err != nil {
			b.fail(err)
			return err
		}
	}
}

// fail records the first sink error. Every later FlushReady or Drain returns
// it, so dispatch stops but already buffered records still drain in order.
func (b *OrderBuffer) fail(err error) {
	b.mu.Lock()
	if b.lastErr == nil {
		b.lastErr = err
	}
	b.canceled = true
	b.mu.Unlock()
	b.signalReserve()
}

// Pending returns the number of slots reserved but not yet emitted.
func (b *OrderBuffer) Pending() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return int(b.reserved - b.next)
}

// Reserved returns the number of slots reserved so far.
func (b *OrderBuffer) Reserved() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reserved
}

// Next returns the first sequence number that has not been emitted yet.
func (b *OrderBuffer) Next() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.next
}

// Err returns the first sink error recorded by FlushReady or Drain.
func (b *OrderBuffer) Err() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.lastErr
}

func (b *OrderBuffer) signalReady() {
	select {
	case b.slotReady <- struct{}{}:
	default:
	}
}

func (b *OrderBuffer) signalReserve() {
	select {
	case b.reserveChanged <- struct{}{}:
	default:
	}
}
