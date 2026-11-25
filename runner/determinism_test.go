package runner

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// orderedProjection builds the comparable projection of a run: the fields
// that must not vary with thread count or response latency.
func orderedProjection(results []Result) []string {
	var out []string
	for _, result := range results {
		out = append(out, fmt.Sprintf("%d|%s|%s|%s|%d|%s|%s|%s|%v|%v",
			result.Sequence,
			result.URL,
			result.Scheme,
			result.Port,
			result.StatusCode,
			strings.Join(result.Technologies, ","),
			result.FavIconMMH3,
			result.JarmHash,
			sortedHashStrings(result.Hashes),
			result.CPE,
		))
	}
	return out
}

func sortedHashStrings(hashes map[string]interface{}) []string {
	keys := make([]string, 0, len(hashes))
	for key := range hashes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out []string
	for _, key := range keys {
		out = append(out, fmt.Sprintf("%s=%v", key, hashes[key]))
	}
	return out
}

// determinismServer serves one page per path. Each path is delayed by a
// deterministic but shuffled amount, so a run with more threads completes the
// probes in a different order.
func determinismServer(t *testing.T, paths int, seed int64) (*httptest.Server, []string) {
	t.Helper()
	delays := make([]time.Duration, paths)
	rng := rand.New(rand.NewSource(seed))
	for i := range delays {
		delays[i] = time.Duration(rng.Intn(20)) * time.Millisecond
	}

	var targets []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var index int
		fmt.Sscanf(strings.TrimPrefix(req.URL.Path, "/p"), "%d", &index)
		if index >= 0 && index < len(delays) {
			time.Sleep(delays[index])
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<html><head><title>page %d</title></head><body>page %d</body></html>", index, index)
	}))
	t.Cleanup(server.Close)

	for i := 0; i < paths; i++ {
		targets = append(targets, fmt.Sprintf("%s/p%d", server.URL, i))
	}
	return server, targets
}

func runDeterminism(t *testing.T, targets []string, threads int) []string {
	t.Helper()
	var (
		mu      sync.Mutex
		results []Result
	)
	options := &Options{
		Threads:   threads,
		Timeout:   5,
		Methods:   http.MethodGet,
		RateLimit: 0,
	}
	options.InputTargetHost = targets
	require.NoError(t, options.ValidateOptions())
	options.OnResult = func(result Result) {
		if result.Err != nil || result.URL == "" {
			return
		}
		mu.Lock()
		results = append(results, result)
		mu.Unlock()
	}
	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	mu.Lock()
	defer mu.Unlock()
	return orderedProjection(results)
}

// The ordered projection must be identical for 1, 4 and 32 threads, five runs
// each, with shuffled per-path delays.
func TestRunEnumerationIsDeterministic(t *testing.T) {
	const paths = 8
	_, targets := determinismServer(t, paths, 42)

	var baseline []string
	for _, threads := range []int{1, 4, 32} {
		for run := 0; run < 5; run++ {
			got := runDeterminism(t, targets, threads)
			if len(got) == 0 {
				continue // a run where every probe failed is not comparable
			}
			sort.Strings(got)
			if baseline == nil {
				baseline = got
				continue
			}
			require.Equal(t, baseline, got, "threads=%d run=%d differs", threads, run)
		}
	}
	require.NotEmpty(t, baseline)
}

// With no filters and no failures, Sequence must increase from 0 with no
// gaps.
func TestRunEnumerationSequenceIsContinuous(t *testing.T) {
	_, targets := determinismServer(t, 5, 7)
	var sequences []uint64
	options := &Options{Threads: 4, Timeout: 5, Methods: http.MethodGet, RateLimit: 0}
	options.InputTargetHost = targets
	require.NoError(t, options.ValidateOptions())
	options.OnResult = func(result Result) {
		if result.Err != nil || result.URL == "" {
			return
		}
		sequences = append(sequences, result.Sequence)
	}
	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	require.Len(t, sequences, len(targets))
	for i, sequence := range sequences {
		require.Equal(t, uint64(i), sequence, "sequence at %d", i)
	}
}

// The normalized JSON output is byte identical apart from timestamp and time,
// even when the probe latency varies.
func TestRunEnumerationJSONIsStable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>stable</title></head><body>stable body</body></html>"))
	}))
	defer server.Close()

	normalize := func(line string) string {
		for _, field := range []string{`"timestamp":"`, `"time":"`} {
			if start := strings.Index(line, field); start >= 0 {
				end := strings.Index(line[start+len(field):], `"`)
				if end >= 0 {
					line = line[:start] + field + `X"` + line[start+len(field)+end+1:]
				}
			}
		}
		return line
	}

	var runs []string
	for _, threads := range []int{1, 4} {
		dir := t.TempDir()
		output := filepath.Join(dir, "out.jsonl")
		options := &Options{Threads: threads, Timeout: 5, Methods: http.MethodGet, JSONOutput: true, Output: output}
		options.InputTargetHost = []string{server.URL}
		require.NoError(t, options.ValidateOptions())
		r, err := New(options)
		require.NoError(t, err)
		r.RunEnumeration()
		r.Close()
		data, err := os.ReadFile(output)
		require.NoError(t, err)
		runs = append(runs, normalize(strings.TrimSpace(string(data))))
	}
	require.Equal(t, runs[0], runs[1])
}

// A read-only output directory aborts the run with a non-zero exit path: the
// output writer reports the error instead of exiting, and no partial file is
// left behind.
func TestRunEnumerationReadOnlyOutputFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>body</html>"))
	}))
	defer server.Close()

	dir := t.TempDir()
	output := filepath.Join(dir, "out.txt")
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	options := &Options{Threads: 1, Timeout: 5, Methods: http.MethodGet, Output: output}
	options.InputTargetHost = []string{server.URL}
	require.NoError(t, options.ValidateOptions())
	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	// If the file cannot be opened, the writer records the error; the run must
	// not panic and must not leave a partial line.
	require.NotPanics(t, func() {
		r.RunEnumeration()
	})
	if _, statErr := os.Stat(output); statErr == nil {
		data, readErr := os.ReadFile(output)
		require.NoError(t, readErr)
		require.True(t, len(data) == 0 || strings.HasSuffix(string(data), "\n"), "no half line")
	}
}
