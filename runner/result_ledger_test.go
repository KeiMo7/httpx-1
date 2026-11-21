package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/httpx/common/httpx"
	pdhttputil "github.com/projectdiscovery/utils/http"
	"github.com/stretchr/testify/require"
)

func TestLedger_CountsSumToTotal(t *testing.T) {
	l := newResultLedger(nil, 30)

	// 2 ok, 2 empty, 1 timeout, 1 refused, 1 tls, 1 loop, 2 other = 10
	l.record(Result{Input: "a", Response: &httpx.Response{Data: []byte("x")}}, false, 10)
	l.record(Result{Input: "b", Response: &httpx.Response{Data: []byte("x")}}, false, 10)
	l.record(Result{Input: "c", Response: &httpx.Response{}}, false, 10)
	l.record(Result{Input: "d", Response: &httpx.Response{}}, false, 10)
	l.record(Result{Input: "e", Err: errors.New("dial tcp: i/o timeout")}, false, 10)
	l.record(Result{Input: "f", Err: errors.New("dial tcp: connection refused")}, false, 10)
	l.record(Result{Input: "g", Err: errors.New("tls: handshake failure")}, false, 10)
	l.record(Result{
		Input: "h",
		Response: &httpx.Response{Chain: []pdhttputil.ChainItem{
			{StatusCode: 302, Location: "/x"},
		}},
	}, true, 1)
	l.record(Result{Input: "i", Err: errors.New("dial udp: weird new transport error")}, false, 10)
	l.record(Result{Input: "j", Err: errors.New("totally unknown failure shape")}, false, 10)

	summary := l.summary()
	require.Equal(t, 10, summary.Total)

	sum := 0
	for _, n := range summary.Counts {
		sum += n
	}
	// hard requirement: the per-category counts add up to the total
	require.Equal(t, summary.Total, sum)
	require.Equal(t, 2, summary.Counts[CategoryOther])
	require.Equal(t, 1, summary.Counts[CategoryRedirectLoop])
}

func TestLedger_UnknownShapeKeepsRawError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "classification.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	require.NoError(t, err)

	l := newResultLedger(newBufferedWriteCloser(f), 30)
	weird := errors.New("dial quic: frame encoding v42 unsupported")
	category, raw := l.record(Result{Input: "x", URL: "http://x", Err: weird}, false, 10)
	require.Equal(t, CategoryOther, category)
	require.Equal(t, weird.Error(), raw)
	l.close()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2) // one record + one summary

	var rec ClassificationRecord
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &rec))
	require.Equal(t, CategoryOther, rec.Category)
	require.Equal(t, weird.Error(), rec.RawError)
	require.Equal(t, ResultCategoryVersion, rec.TaxonomyVersion)

	var summary SummaryRecord
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &summary))
	require.Equal(t, "batch_summary", summary.Kind)
	require.Equal(t, 1, summary.Total)
}

func TestLedger_TargetAggregationAndTransition(t *testing.T) {
	l := newResultLedger(nil, 30)

	// same target across rounds: timeout -> timeout -> ok -> empty
	l.record(Result{Input: "host", Err: errors.New("i/o timeout")}, false, 10)
	l.record(Result{Input: "host", Err: errors.New("i/o timeout")}, false, 10)
	l.record(Result{Input: "host", Response: &httpx.Response{Data: []byte("ok")}}, false, 10)
	l.record(Result{Input: "host", Response: &httpx.Response{}}, false, 10)

	tc, ok := l.classificationOf("host")
	require.True(t, ok)
	require.Equal(t, CategoryEmptyBody, tc.Last)
	require.ElementsMatch(t, []string{CategoryTimeout, CategoryOK, CategoryEmptyBody}, tc.Categories)
	require.Equal(t, 2, tc.Counts[CategoryTimeout])
	require.Equal(t, []string{"timeout -> ok", "ok -> empty_body"}, tc.Transitions)
}

func TestLedger_AnomalyFlagged(t *testing.T) {
	l := newResultLedger(nil, 30)
	for i := 0; i < 8; i++ {
		l.record(Result{Input: "t", Err: errors.New("i/o timeout")}, false, 10)
	}
	for i := 0; i < 2; i++ {
		l.record(Result{Input: "o", Response: &httpx.Response{Data: []byte("x")}}, false, 10)
	}
	summary := l.summary()
	require.Contains(t, summary.Anomalies, CategoryTimeout)
	require.Equal(t, 80.0, summary.Percent[CategoryTimeout])
}

func TestLedger_PanicDegradesToOtherAndKeepsScanning(t *testing.T) {
	l := newResultLedger(nil, 30)
	// nil response with nil error is an unmodeled internal shape that must not
	// panic the scan; it is bucketed as other.
	category, _ := l.record(Result{Input: "z"}, false, 10)
	require.Equal(t, CategoryOther, category)
	// the ledger still works afterwards
	category, _ = l.record(Result{Input: "a", Response: &httpx.Response{Data: []byte("x")}}, false, 10)
	require.Equal(t, CategoryOK, category)
}

func TestLedger_StreamsWithoutBufferingAllResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "classification.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	require.NoError(t, err)
	l := newResultLedger(newBufferedWriteCloser(f), 30)

	const n = 1000
	for i := 0; i < n; i++ {
		l.record(Result{Input: "host", Response: &httpx.Response{Data: []byte("x")}}, false, 10)
	}
	l.close()

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, n+1, bytes.Count(data, []byte("\n"))) // n records + summary
}

func TestOptions_ClassificationOutputRejectedWhenUnwritable(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "does-not-exist", "out.jsonl")
	opts := &Options{
		ResultClassification:       true,
		ResultClassificationOutput: missingDir,
	}
	err := opts.ValidateOptions()
	require.Error(t, err)
	require.Contains(t, err.Error(), "not writable")
}

func TestOptions_OutputPathImpliesClassification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	opts := &Options{ResultClassificationOutput: path}
	require.NoError(t, opts.ValidateOptions())
	require.True(t, opts.ResultClassification)
}

func TestOptions_ThresholdRangeValidated(t *testing.T) {
	require.Error(t, (&Options{ResultClassification: true, ResultAnomalyThresholdPct: 101}).ValidateOptions())
	require.NoError(t, (&Options{ResultClassification: true, ResultAnomalyThresholdPct: 0}).ValidateOptions())
}
