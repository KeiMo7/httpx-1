package runner

import (
	"sync/atomic"
)

// slotCursor hands out sequence numbers of one reserved range to the probe
// goroutines of a single target. Next is safe for concurrent use: each probe
// claims a distinct slot.
type slotCursor struct {
	next Slot
}

// Next claims the next slot of the range. Once the range is exhausted it
// returns the next value past it, which Push rejects; a probe that never ran
// leaves its slot to be consumed by the timeout.
func (c *slotCursor) Next() Slot {
	if c == nil {
		return 0
	}
	return Slot(atomic.AddUint64((*uint64)(&c.next), 1) - 1)
}

// advanceResume records the input being dispatched and reports whether it
// should be probed. A skipped (already completed) input burns its counter
// without reserving a slot, so the resumed run skips exactly Index inputs.
func advanceResume(r *Runner, key string) bool {
	if r.options.resumeCfg == nil {
		return true
	}
	r.options.resumeCfg.current = key
	r.options.resumeCfg.currentIndex++
	return r.options.resumeCfg.currentIndex > r.options.resumeCfg.Index
}
