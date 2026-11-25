package runner

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func resultsOf(t *testing.T, buffer *OrderBuffer) []Result {
	t.Helper()
	var results []Result
	if err := buffer.Drain(func(result Result) error {
		results = append(results, result)
		return nil
	}); err != nil {
		t.Fatalf("drain: %v", err)
	}
	return results
}

func TestOrderBufferDeterministicPermutations(t *testing.T) {
	const slots = 10000
	for _, seed := range []int64{1, 2, 3} {
		buffer := NewOrderBuffer(slots+1, 0)
		first, err := buffer.Reserve(context.Background(), slots)
		require.NoError(t, err)
		require.Equal(t, Slot(0), first)

		order := make([]int, slots)
		for i := range order {
			order[i] = i
		}
		rng := rand.New(rand.NewSource(seed))
		rng.Shuffle(slots, func(i, j int) { order[i], order[j] = order[j], order[i] })

		var results []Result
		collect := func(result Result) error {
			results = append(results, result)
			return nil
		}
		for _, slot := range order {
			require.NoError(t, buffer.Push(Slot(slot), Result{URL: fmt.Sprintf("url-%d", slot)}))
			require.NoError(t, buffer.FlushReady(collect))
		}
		buffer.Close()
		require.NoError(t, buffer.Drain(collect))
		require.Len(t, results, slots)
		for i, result := range results {
			require.Equal(t, uint64(i), result.Sequence)
			require.Equal(t, fmt.Sprintf("url-%d", i), result.URL)
		}
	}
}

func TestOrderBufferWindowOne(t *testing.T) {
	buffer := NewOrderBuffer(1, 0)
	first, err := buffer.Reserve(context.Background(), 1)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = buffer.Reserve(ctx, 1)
	require.ErrorIs(t, err, ErrOrderClosed, "a full window blocks Reserve until its context expires")

	var got []Result
	require.NoError(t, buffer.Push(first, Result{URL: "one"}))
	require.NoError(t, buffer.FlushReady(func(result Result) error {
		got = append(got, result)
		return nil
	}))
	buffer.Close()
	require.NoError(t, buffer.Drain(func(Result) error { return nil }))
	require.Len(t, got, 1)
}

func TestOrderBufferTimeout(t *testing.T) {
	buffer := NewOrderBuffer(4, 20*time.Millisecond)
	first, err := buffer.Reserve(context.Background(), 1)
	require.NoError(t, err)
	second, err := buffer.Reserve(context.Background(), 1)
	require.NoError(t, err)

	require.NoError(t, buffer.Push(second, Result{URL: "second"}))
	time.Sleep(30 * time.Millisecond)

	var results []Result
	require.NoError(t, buffer.FlushReady(func(result Result) error {
		results = append(results, result)
		return nil
	}))
	buffer.Close()
	results = append(results, resultsOf(t, buffer)...)

	require.Len(t, results, 2)
	require.Equal(t, uint64(0), results[0].Sequence)
	require.True(t, results[0].Failed)
	require.Equal(t, "order timeout", results[0].Error)
	require.ErrorIs(t, results[0].Err, ErrOrderTimeout)
	require.Equal(t, uint64(1), results[1].Sequence)
	require.Equal(t, "second", results[1].URL)
	_ = first
}

func TestOrderBufferSkipInMiddle(t *testing.T) {
	buffer := NewOrderBuffer(4, 0)
	start, err := buffer.Reserve(context.Background(), 3)
	require.NoError(t, err)
	require.NoError(t, buffer.Push(start, Result{URL: "a"}))
	require.NoError(t, buffer.Skip(start+1))
	require.NoError(t, buffer.Push(start+2, Result{URL: "c"}))
	buffer.Close()
	results := resultsOf(t, buffer)
	require.Len(t, results, 2)
	require.Equal(t, "a", results[0].URL)
	require.Equal(t, "c", results[1].URL)
	require.Equal(t, uint64(2), results[1].Sequence)
}

func TestOrderBufferRejectsDuplicateAndUnknown(t *testing.T) {
	buffer := NewOrderBuffer(4, 0)
	slot, err := buffer.Reserve(context.Background(), 1)
	require.NoError(t, err)
	require.NoError(t, buffer.Push(slot, Result{URL: "a"}))
	require.ErrorIs(t, buffer.Push(slot, Result{URL: "b"}), ErrOrderSlotDuplicate)

	unknown := Slot(100)
	require.ErrorIs(t, buffer.Push(unknown, Result{}), ErrOrderSlotUnknown)
	require.ErrorIs(t, buffer.Skip(unknown), ErrOrderSlotUnknown)
}

func TestOrderBufferCancelDrainsInOrder(t *testing.T) {
	buffer := NewOrderBuffer(4, 0)
	slots := make([]Slot, 3)
	for i := range slots {
		slots[i], _ = buffer.Reserve(context.Background(), 1)
	}
	require.NoError(t, buffer.Push(slots[2], Result{URL: "three"}))
	require.NoError(t, buffer.Skip(slots[1]))
	buffer.Cancel()

	// The skipped middle slot produces no record, the first is filled as a
	// timeout and keeps its sequence, and "three" keeps sequence 2.
	results := resultsOf(t, buffer)
	require.Len(t, results, 2)
	require.Equal(t, uint64(0), results[0].Sequence)
	require.True(t, results[0].Failed)
	require.Equal(t, "three", results[1].URL)
	require.Equal(t, uint64(2), results[1].Sequence)
}

func TestOrderBufferConcurrentPush(t *testing.T) {
	const slots = 1000
	buffer := NewOrderBuffer(slots, time.Second)
	first, err := buffer.Reserve(context.Background(), slots)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < slots; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = buffer.Push(first+Slot(i), Result{URL: fmt.Sprintf("url-%d", i)})
		}(i)
	}
	wg.Wait()
	buffer.Close()

	var results []Result
	require.NoError(t, buffer.Drain(func(result Result) error {
		results = append(results, result)
		return nil
	}))
	require.Len(t, results, slots)
	for i, result := range results {
		require.Equal(t, uint64(i), result.Sequence)
		require.Equal(t, fmt.Sprintf("url-%d", i), result.URL)
	}
}

func TestOrderBufferSinkErrorStopsDispatch(t *testing.T) {
	buffer := NewOrderBuffer(4, 0)
	slot, err := buffer.Reserve(context.Background(), 1)
	require.NoError(t, err)
	require.NoError(t, buffer.Push(slot, Result{URL: "a"}))

	sinkErr := errors.New("disk full")
	err = buffer.FlushReady(func(Result) error { return sinkErr })
	require.ErrorIs(t, err, sinkErr)

	// A later flush keeps returning the same error.
	require.ErrorIs(t, buffer.FlushReady(func(Result) error { return nil }), sinkErr)
	require.ErrorIs(t, buffer.Err(), sinkErr)
	// Reserve on a failed buffer reports closed, so dispatch stops.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = buffer.Reserve(ctx, 1)
	require.ErrorIs(t, err, ErrOrderClosed)
}

func TestOrderBufferReserveContextCanceled(t *testing.T) {
	buffer := NewOrderBuffer(1, 0)
	_, err := buffer.Reserve(context.Background(), 1)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = buffer.Reserve(ctx, 1)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrOrderClosed)
}

func TestOrderBufferReserveTooLarge(t *testing.T) {
	buffer := NewOrderBuffer(2, 0)
	_, err := buffer.Reserve(context.Background(), 3)
	require.ErrorIs(t, err, ErrOrderBufferFull)
}

// A deterministic permutation produces the same ordered projection regardless
// of push order.
func TestOrderBufferOrderedProjection(t *testing.T) {
	const slots = 100
	projection := func(seed int64) []string {
		buffer := NewOrderBuffer(slots+1, 0)
		first, err := buffer.Reserve(context.Background(), slots)
		require.NoError(t, err)

		order := make([]int, slots)
		for i := range order {
			order[i] = i
		}
		rand.New(rand.NewSource(seed)).Shuffle(slots, func(i, j int) { order[i], order[j] = order[j], order[i] })
		var got []string
		collect := func(result Result) error {
			got = append(got, fmt.Sprintf("%04d %s %d", result.Sequence, result.URL, result.StatusCode))
			return nil
		}
		for _, i := range order {
			require.NoError(t, buffer.Push(first+Slot(i), Result{URL: fmt.Sprintf("%03d", i), StatusCode: 200}))
			if i%3 == 0 {
				require.NoError(t, buffer.FlushReady(collect))
			}
		}
		buffer.Close()
		require.NoError(t, buffer.Drain(collect))
		require.True(t, sort.SliceIsSorted(got, func(i, j int) bool { return got[i] < got[j] }),
			"the ordered projection must be sorted")
		return got
	}
	want := projection(7)
	for seed := int64(1); seed <= 5; seed++ {
		require.Equal(t, want, projection(seed))
	}
}

func TestOrderBufferAccessorsAndWait(t *testing.T) {
	buffer := NewOrderBuffer(4, 10*time.Millisecond)
	first, err := buffer.Reserve(context.Background(), 2)
	require.NoError(t, err)

	require.Equal(t, uint64(2), buffer.Reserved())
	require.Equal(t, uint64(0), buffer.Next())
	require.Equal(t, 2, buffer.Pending())
	require.NoError(t, buffer.Err())

	// NextTimeout reports a positive wait for a reserved, unpushed slot and
	// zero once it is pending.
	require.Positive(t, buffer.NextTimeout())
	require.NoError(t, buffer.Push(first, Result{}))
	require.Zero(t, buffer.NextTimeout(), "a pending slot does not time out")

	// Wait wakes when a slot becomes ready.
	go func() {
		time.Sleep(5 * time.Millisecond)
		_ = buffer.Push(first+1, Result{})
	}()
	select {
	case <-buffer.slotReady:
	default:
	}
	require.True(t, buffer.Wait(50*time.Millisecond))

	// Wait returns false on the deadline when no slot becomes ready.
	require.False(t, buffer.Wait(10*time.Millisecond))
}

func TestOrderBufferNewDefaults(t *testing.T) {
	buffer := NewOrderBuffer(0, 0)
	require.Equal(t, DefaultOrderWindow, buffer.capacity)
	require.Zero(t, buffer.timeout)
}

// Pending reservations never exceed the window: full windows block until the
// consumer drains them.
func TestOrderBufferWindowBound(t *testing.T) {
	buffer := NewOrderBuffer(8, 0)
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var reserved atomic.Uint32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			slot, err := buffer.Reserve(ctx, 2)
			if err != nil {
				return
			}
			reserved.Add(2)
			require.NoError(t, buffer.Push(slot, Result{URL: "x"}))
		}()
	}

	// Drain concurrently so blocked reservations make progress.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			require.NoError(t, buffer.FlushReady(func(Result) error { return nil }))
			if buffer.Pending() == 0 && reserved.Load() >= 40 {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
	<-done
	buffer.Close()
	require.NoError(t, buffer.Drain(func(Result) error { return nil }))
}
