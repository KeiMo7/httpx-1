package runner

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// ClassificationRecord is the fixed, structured shape of one classified
// result. Field names are part of the contract and must not change between
// taxonomy versions; new fields may only be added.
type ClassificationRecord struct {
	TaxonomyVersion string `json:"taxonomy_version"`
	Input           string `json:"input"`
	URL             string `json:"url"`
	Category        string `json:"category"`
	// RawError keeps the original error text for the "other" bucket (and any
	// error category), so an unknown failure shape is never silently lost.
	RawError string `json:"raw_error,omitempty"`
	// PreviousCategory tracks within-run category migration for this target.
	PreviousCategory string `json:"previous_category,omitempty"`
}

// TargetClassification is the target-level rollup: every category this target
// has produced, in first-seen order, plus the transitions between rounds.
type TargetClassification struct {
	Input       string         `json:"input"`
	Last        string         `json:"last_category"`
	Categories  []string       `json:"categories"`
	Counts      map[string]int `json:"counts"`
	Transitions []string       `json:"transitions,omitempty"`
}

// SummaryRecord is the batch-level rollup. Counts use the fixed category
// order, so two batches can be diffed field by field.
type SummaryRecord struct {
	Kind            string                 `json:"kind"` // "batch_summary"
	TaxonomyVersion string                 `json:"taxonomy_version"`
	Total           int                    `json:"total"`
	Counts          map[string]int         `json:"counts"`
	Percent         map[string]float64     `json:"percent"`
	Anomalies       []string               `json:"anomalies,omitempty"`
	Targets         []TargetClassification `json:"targets"`
}

// resultLedger classifies and streams every result. It holds one small
// counter set per target instead of buffering results, so 100k outcomes stay
// streaming with bounded memory.
type resultLedger struct {
	mu sync.Mutex

	w            io.WriteCloser // optional JSONL sink; nil means in-memory only
	thresholdPct int

	total  int
	counts map[string]int

	targets map[string]*TargetClassification
	last    map[string]string

	failedClassifications int
}

const defaultAnomalyThresholdPct = 30

func newResultLedger(w io.WriteCloser, anomalyThresholdPct int) *resultLedger {
	if anomalyThresholdPct <= 0 {
		anomalyThresholdPct = defaultAnomalyThresholdPct
	}
	return &resultLedger{
		w:            w,
		thresholdPct: anomalyThresholdPct,
		counts:       make(map[string]int),
		targets:      make(map[string]*TargetClassification),
		last:         make(map[string]string),
	}
}

// record classifies one result and immediately streams it. A panic inside the
// classifier is contained: the result is recorded as "other" and a warning is
// emitted, probing is never interrupted. It returns the assigned category and
// preserved raw error so the caller can annotate the result itself.
func (l *resultLedger) record(res Result, followRedirects bool, maxRedirects int) (category, rawErr string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	category, rawErr = l.safeClassify(res, followRedirects, maxRedirects)

	target := res.Input
	if target == "" {
		target = res.URL
	}

	previous := l.last[target]
	l.last[target] = category
	l.total++
	l.counts[category]++

	tc, ok := l.targets[target]
	if !ok {
		tc = &TargetClassification{Input: target, Counts: make(map[string]int)}
		l.targets[target] = tc
	}
	tc.Last = category
	tc.Counts[category]++
	if !containsString(tc.Categories, category) {
		tc.Categories = append(tc.Categories, category)
	}
	if previous != "" && previous != category {
		tc.Transitions = append(tc.Transitions, previous+" -> "+category)
	}

	if l.w != nil {
		rec := ClassificationRecord{
			TaxonomyVersion:  ResultCategoryVersion,
			Input:            target,
			URL:              res.URL,
			Category:         category,
			RawError:         rawErr,
			PreviousCategory: previous,
		}
		data, err := json.Marshal(rec)
		if err != nil {
			gologger.Warning().Msgf("result classification: could not marshal record for %s: %s", target, err)
		} else if _, err := l.w.Write(append(data, '\n')); err != nil {
			gologger.Warning().Msgf("result classification: could not write record for %s: %s", target, err)
		}
	}
	return category, rawErr
}

// safeClassify isolates panics in the taxonomy from the scan itself.
func (l *resultLedger) safeClassify(res Result, followRedirects bool, maxRedirects int) (category, rawErr string) {
	defer func() {
		if r := recover(); r != nil {
			l.failedClassifications++
			gologger.Warning().Msgf("result classification failed for %s (degraded to %s): %v", res.Input, CategoryOther, r)
			category = CategoryOther
			if res.Err != nil {
				rawErr = res.Err.Error()
			}
		}
	}()

	in := classificationInput{
		err:      res.Err,
		resp:     res.Response,
		redirect: followRedirects,
		maxHops:  maxRedirects,
	}
	category = classifyResult(in)
	if res.Err != nil {
		rawErr = res.Err.Error()
	}
	return category, rawErr
}

// summary builds the batch rollup from the running counters without iterating
// raw results.
func (l *resultLedger) summary() SummaryRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buildSummaryLocked()
}

// close flushes the summary and closes the sink.
func (l *resultLedger) close() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.w == nil {
		return
	}
	summary := l.buildSummaryLocked()
	data, err := json.Marshal(summary)
	if err != nil {
		gologger.Warning().Msgf("result classification: could not marshal summary: %s", err)
	} else if _, err := l.w.Write(append(data, '\n')); err != nil {
		gologger.Warning().Msgf("result classification: could not write summary: %s", err)
	}
	if err := l.w.Close(); err != nil {
		gologger.Warning().Msgf("result classification: could not close output: %s", err)
	}
	l.w = nil
}

// buildSummaryLocked assembles the rollup; callers must hold l.mu.
func (l *resultLedger) buildSummaryLocked() SummaryRecord {
	counts := make(map[string]int, len(categoryOrder)+1)
	for _, c := range categoryOrder {
		counts[c] = l.counts[c]
	}
	if extra := l.counts[CategoryOther]; extra > 0 {
		counts[CategoryOther] = extra
	}
	percent := make(map[string]float64, len(counts))
	var anomalies []string
	if l.total > 0 {
		for c, n := range counts {
			pct := float64(n) * 100 / float64(l.total)
			percent[c] = roundPercent(pct)
			if pct >= float64(l.thresholdPct) && c != CategoryOK {
				anomalies = append(anomalies, c)
			}
		}
	}
	targets := make([]TargetClassification, 0, len(l.targets))
	for _, tc := range l.targets {
		targets = append(targets, *tc)
	}
	return SummaryRecord{
		Kind:            "batch_summary",
		TaxonomyVersion: ResultCategoryVersion,
		Total:           l.total,
		Counts:          counts,
		Percent:         percent,
		Anomalies:       anomalies,
		Targets:         targets,
	}
}

// bufferedWriter makes a small write buffer explicit so each record does not
// take a syscall; Close flushes it before closing the underlying file.
type bufferedWriteCloser struct {
	*bufio.Writer
	f *os.File
}

func newBufferedWriteCloser(f *os.File) *bufferedWriteCloser {
	return &bufferedWriteCloser{Writer: bufio.NewWriter(f), f: f}
}

func (b *bufferedWriteCloser) Close() error {
	if err := b.Flush(); err != nil {
		_ = b.f.Close()
		return err
	}
	return b.f.Close()
}

func containsString(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func roundPercent(p float64) float64 {
	return float64(int(p*100+0.5)) / 100
}

// formatCategoryCounts renders the fixed-order distribution for logs.
func formatCategoryCounts(counts map[string]int) string {
	parts := make([]string, 0, len(categoryOrder)+1)
	for _, c := range categoryOrder {
		parts = append(parts, c+"="+strconv.Itoa(counts[c]))
	}
	if n := counts[CategoryOther]; n > 0 {
		parts = append(parts, CategoryOther+"="+strconv.Itoa(n))
	}
	return strings.Join(parts, " ")
}

// ClassificationSummary exposes the batch-level rollup to library callers.
// It returns the zero value when classification is disabled.
func (r *Runner) ClassificationSummary() (SummaryRecord, bool) {
	if r.ledger == nil {
		return SummaryRecord{}, false
	}
	return r.ledger.summary(), true
}

// ClassificationOfTarget exposes the target-level rollup to library callers.
func (r *Runner) ClassificationOfTarget(input string) (TargetClassification, bool) {
	if r.ledger == nil {
		return TargetClassification{}, false
	}
	return r.ledger.classificationOf(input)
}

func (l *resultLedger) classificationOf(input string) (TargetClassification, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	tc, ok := l.targets[input]
	if !ok {
		return TargetClassification{}, false
	}
	return *tc, true
}
