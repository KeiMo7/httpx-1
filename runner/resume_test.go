package runner

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/projectdiscovery/goconfig"
	"github.com/stretchr/testify/require"
)

// resumeServer serves a distinct page per path so the records are
// distinguishable across runs.
func resumeServer(t *testing.T, paths int) (*httptest.Server, []string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>" + req.URL.Path + "</title></head><body>" + req.URL.Path + "</body></html>"))
	}))
	t.Cleanup(server.Close)
	var targets []string
	for i := 0; i < paths; i++ {
		targets = append(targets, server.URL+"/p"+itoaTest(i))
	}
	return server, targets
}

func itoaTest(i int) string {
	if i == 0 {
		return "0"
	}
	var digits []byte
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}

// runResume runs one pass with the given resume state and returns the titles
// that were emitted in order, plus the number of slots reserved.
func runResume(t *testing.T, targets []string, resume *ResumeCfg) ([]string, uint64) {
	t.Helper()
	var (
		mu      sync.Mutex
		results []Result
	)
	options := &Options{Threads: 1, Timeout: 5, Methods: http.MethodGet, RateLimit: 0}
	options.InputTargetHost = targets
	require.NoError(t, options.ValidateOptions())
	options.resumeCfg = resume
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
	var titles []string
	for _, result := range results {
		titles = append(titles, result.Title)
	}
	return titles, r.order.Reserved()
}

// A complete run and an interrupted-then-resumed run emit the same records.
func TestResumeMatchesFullRun(t *testing.T) {
	_, targets := resumeServer(t, 6)

	full, fullReserved := runResume(t, targets, &ResumeCfg{})
	require.Len(t, full, 6)

	resumed, reserved := runResume(t, targets, &ResumeCfg{Index: 3})
	require.Len(t, resumed, 3, "the resumed run must emit the records after Index")
	require.Equal(t, full[3:], resumed, "the resumed records must match the tail of the full run")
	require.Equal(t, uint64(3), reserved, "only the resumed inputs reserve slots")
	require.Equal(t, uint64(6), fullReserved)
}

// ResumeCfg round-trips through the config file so an old resume.cfg is still
// readable.
func TestResumeConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resume.cfg")
	saved := ResumeCfg{ResumeFrom: "http://example.com/2", Index: 2}
	require.NoError(t, goconfig.Save(saved, path))

	var loaded ResumeCfg
	require.NoError(t, goconfig.Load(&loaded, path))
	require.Equal(t, saved.ResumeFrom, loaded.ResumeFrom)
	require.Equal(t, saved.Index, loaded.Index)

	// An older file with the two documented keys reads back as well.
	legacy := "resume_from: http://example.com\nindex: 1\n"
	require.NoError(t, os.WriteFile(path, []byte(legacy), 0o600))
	var fromLegacy ResumeCfg
	require.NoError(t, goconfig.Load(&fromLegacy, path))
	require.Equal(t, "http://example.com", fromLegacy.ResumeFrom)
	require.Equal(t, 1, fromLegacy.Index)
}

// SaveResumeConfig writes Index and ResumeFrom after a run.
func TestSaveResumeConfig(t *testing.T) {
	t.Cleanup(func() {
		_ = os.Remove(DefaultResumeFile)
	})
	r := &Runner{options: &Options{resumeCfg: &ResumeCfg{current: "http://example.com/3", currentIndex: 3}}}
	require.NoError(t, r.SaveResumeConfig())

	var loaded ResumeCfg
	require.NoError(t, goconfig.Load(&loaded, DefaultResumeFile))
	require.Equal(t, 3, loaded.Index)
	require.Equal(t, "http://example.com/3", loaded.ResumeFrom)

	data, err := os.ReadFile(DefaultResumeFile)
	require.NoError(t, err)
	require.True(t, strings.Contains(string(data), "index"), string(data))
}
