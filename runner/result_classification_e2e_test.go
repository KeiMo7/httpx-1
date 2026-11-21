package runner

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// runClassificationScan runs one enumeration with classification enabled and
// returns the batch rollup. Every input uses an explicit scheme with
// NoFallbackScheme so each target produces exactly one attempt.
func runClassificationScan(t *testing.T, targets []string, extra func(*Options)) SummaryRecord {
	t.Helper()
	options := &Options{
		Threads:              1,
		RateLimit:            50,
		Retries:              0,
		Timeout:              3,
		Methods:              http.MethodGet,
		Delay:                -1,
		NoFallbackScheme:     true,
		ResultClassification: true,
		InputTargetHost:      targets,
	}
	if extra != nil {
		extra(options)
	}
	require.NoError(t, options.ValidateOptions())

	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	summary, ok := r.ClassificationSummary()
	require.True(t, ok)
	return summary
}

func TestClassificationE2E_NormalAndEmptyBody(t *testing.T) {
	normal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "alive and well")
	}))
	t.Cleanup(normal.Close)

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(empty.Close)

	summary := runClassificationScan(t, []string{normal.URL, empty.URL}, nil)

	require.Equal(t, 2, summary.Total)
	require.Equal(t, 1, summary.Counts[CategoryOK])
	require.Equal(t, 1, summary.Counts[CategoryEmptyBody])

	tc, ok := summary.targetOf(empty.URL)
	require.True(t, ok)
	require.Equal(t, CategoryEmptyBody, tc.Last)
}

func TestClassificationE2E_ConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()
	require.NoError(t, listener.Close())

	summary := runClassificationScan(t, []string{"http://" + addr}, nil)
	require.Equal(t, 1, summary.Counts[CategoryConnectionRefused])
}

func TestClassificationE2E_Timeout(t *testing.T) {
	// A listener that accepts the connection and never answers: the client
	// deadline has to fire rather than a refusal.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()

	summary := runClassificationScan(t, []string{"http://" + listener.Addr().String()}, func(o *Options) {
		o.Timeout = 1
	})
	require.Equal(t, 1, summary.Counts[CategoryTimeout])
}

func TestClassificationE2E_TLSFailure(t *testing.T) {
	// Plaintext HTTP probed over HTTPS must fail at the TLS handshake.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "plaintext only")
	}))
	t.Cleanup(plain.Close)

	target := "https://" + plain.Listener.Addr().String()
	summary := runClassificationScan(t, []string{target}, nil)
	require.Equal(t, 1, summary.Counts[CategoryTLSFailure], "distribution: %v", summary.Counts)
}

func TestClassificationE2E_RedirectLoop(t *testing.T) {
	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop-again", http.StatusFound)
	}))
	t.Cleanup(loop.Close)

	summary := runClassificationScan(t, []string{loop.URL}, func(o *Options) {
		o.FollowRedirects = true
		o.MaxRedirects = 2
	})
	require.Equal(t, 1, summary.Counts[CategoryRedirectLoop], "distribution: %v", summary.Counts)
}

func TestClassificationE2E_DisabledByDefaultAndSummaryConserves(t *testing.T) {
	normal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(normal.Close)

	options := &Options{
		Threads:         1,
		RateLimit:       50,
		Retries:         0,
		Timeout:         3,
		Methods:         http.MethodGet,
		Delay:           -1,
		InputTargetHost: []string{normal.URL},
	}
	require.NoError(t, options.ValidateOptions())
	r, err := New(options)
	require.NoError(t, err)
	defer r.Close()
	r.RunEnumeration()

	_, ok := r.ClassificationSummary()
	require.False(t, ok, "classification must stay opt-in")

	// with it enabled, every result lands in exactly one bucket and the
	// buckets add up to the total
	summary := runClassificationScan(t, []string{normal.URL}, nil)
	sum := 0
	for _, n := range summary.Counts {
		sum += n
	}
	require.Equal(t, summary.Total, sum)
	require.Equal(t, "1.0", summary.TaxonomyVersion)
}

// targetOf finds the rollup of a target by its input or URL.
func (s SummaryRecord) targetOf(input string) (TargetClassification, bool) {
	for _, tc := range s.Targets {
		if tc.Input == input {
			return tc, true
		}
	}
	return TargetClassification{}, false
}
