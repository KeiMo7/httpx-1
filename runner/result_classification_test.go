package runner

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/projectdiscovery/httpx/common/httpx"
	pdhttputil "github.com/projectdiscovery/utils/http"
	"github.com/stretchr/testify/require"
)

func errWith(msg string) error { return errors.New(msg) }

func TestClassifyResult_SixCategories(t *testing.T) {
	tests := []struct {
		name     string
		in       classificationInput
		expected string
	}{
		{
			name: "normal response",
			in: classificationInput{
				resp: &httpx.Response{StatusCode: 200, Data: []byte("hello")},
			},
			expected: CategoryOK,
		},
		{
			name: "connection refused",
			in: classificationInput{
				err: &net.OpError{Op: "dial", Net: "tcp", Err: errWith("connection refused")},
			},
			expected: CategoryConnectionRefused,
		},
		{
			name: "timeout via net.Error",
			in: classificationInput{
				err: &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}},
			},
			expected: CategoryTimeout,
		},
		{
			name: "tls failure",
			in: classificationInput{
				err: tls.RecordHeaderError{Msg: "tls: first record does not look like a TLS handshake"},
			},
			expected: CategoryTLSFailure,
		},
		{
			name: "redirect loop",
			in: classificationInput{
				resp: &httpx.Response{
					StatusCode: 302,
					Headers:    map[string][]string{"Location": {"/loop"}},
					Chain: []pdhttputil.ChainItem{
						{StatusCode: 302, Location: "/a"},
						{StatusCode: 302, Location: "/b"},
						{StatusCode: 302, Location: "/loop"},
					},
				},
				redirect: true,
				maxHops:  3,
			},
			expected: CategoryRedirectLoop,
		},
		{
			name: "empty response body",
			in: classificationInput{
				resp: &httpx.Response{StatusCode: 204, Data: nil, RawData: nil},
			},
			expected: CategoryEmptyBody,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, classifyResult(tt.in))
		})
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassifyResult_UnknownGoesToOtherWithRawError(t *testing.T) {
	// an error shape the taxonomy does not model must land in "other";
	// the ledger separately keeps its raw text.
	in := classificationInput{err: errWith("dial udp: something completely unexpected")}
	require.Equal(t, CategoryOther, classifyResult(in))
}

func TestClassifyResult_PriorityTimeoutOverTLS(t *testing.T) {
	// A TLS handshake that runs past the deadline matches both rules; the
	// taxonomy must pick exactly one, timeout first.
	err := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: &osTimeout{msg: "tls: handshake timeout: i/o timeout"},
	}
	require.True(t, isTimeout(err))
	require.True(t, isTLSFailure(err))
	require.Equal(t, CategoryTimeout, classifyResult(classificationInput{err: err}))
}

type osTimeout struct {
	msg string
}

func (e *osTimeout) Error() string   { return e.msg }
func (e *osTimeout) Timeout() bool   { return true }
func (e *osTimeout) Temporary() bool { return true }

func TestClassifyResult_RedirectLoopRules(t *testing.T) {
	chain := func(n int) []pdhttputil.ChainItem {
		items := make([]pdhttputil.ChainItem, 0, n)
		for i := 0; i < n; i++ {
			items = append(items, pdhttputil.ChainItem{StatusCode: 302, Location: "/r"})
		}
		return items
	}

	// redirect following disabled: never a loop even with a long chain
	require.False(t, isRedirectLoop(&httpx.Response{Chain: chain(10)}, false, 10))
	// under the limit: not a loop
	require.False(t, isRedirectLoop(&httpx.Response{Chain: chain(3)}, true, 10))
	// at the limit but final response is a normal page: not a loop
	ok := chain(10)
	ok[9] = pdhttputil.ChainItem{StatusCode: 200}
	require.False(t, isRedirectLoop(&httpx.Response{Chain: ok}, true, 10))
	// at the limit and still redirecting: loop
	require.True(t, isRedirectLoop(&httpx.Response{Chain: chain(10)}, true, 10))
}

func TestClassifyResult_ContextDeadline(t *testing.T) {
	_, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	time.Sleep(2 * time.Millisecond)
	cancel()
	require.Equal(t, CategoryTimeout, classifyResult(classificationInput{err: context.DeadlineExceeded}))
}
