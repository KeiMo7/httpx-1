package runner

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"

	"github.com/projectdiscovery/httpx/common/httpx"
)

// ResultCategoryVersion marks the classification taxonomy. Old results carry
// the version they were produced with, so they stay interpretable when the
// taxonomy grows (new categories, changed rules). Bump it whenever the set of
// categories or the priority rules change.
const ResultCategoryVersion = "1.0"

// Result categories. Every classified result maps to exactly one of them.
const (
	// CategoryOK: a response was received and the body is not empty.
	CategoryOK = "ok"
	// CategoryConnectionRefused: the remote host actively refused the connection.
	CategoryConnectionRefused = "connection_refused"
	// CategoryTimeout: the request exceeded its deadline or was canceled.
	CategoryTimeout = "timeout"
	// CategoryTLSFailure: the TLS handshake or a TLS-level operation failed.
	CategoryTLSFailure = "tls_failure"
	// CategoryRedirectLoop: redirect following stopped at the redirect limit
	// while the final response still asks for another redirect.
	CategoryRedirectLoop = "redirect_loop"
	// CategoryEmptyBody: a response was received but its body is empty.
	CategoryEmptyBody = "empty_body"
	// CategoryOther: an error shape the taxonomy does not know. The raw error
	// text is always preserved alongside it.
	CategoryOther = "other"
)

// categoryOrder is the single, authoritative classification table. One
// phenomenon can match several rules (e.g. a TLS handshake that times out);
// the first match in this order wins, so it is recorded in one bucket only.
var categoryOrder = []string{
	CategoryTimeout,
	CategoryConnectionRefused,
	CategoryTLSFailure,
	CategoryRedirectLoop,
	CategoryEmptyBody,
	CategoryOK,
}

// classificationInput carries exactly the signals the taxonomy needs. It is
// the only entry point of the classification rules, so the same phenomenon
// cannot be categorized differently on different code paths.
type classificationInput struct {
	err      error
	resp     *httpx.Response
	redirect bool // redirects are being followed (FollowRedirects/Host)
	maxHops  int  // configured redirect limit
}

// classifyResult applies the taxonomy to one probe outcome. It never returns
// an empty category: unknown error shapes fall back to CategoryOther.
func classifyResult(in classificationInput) string {
	if in.err != nil {
		switch {
		// Timeout first: a TLS handshake running past the deadline is reported
		// as a timeout, not a TLS failure.
		case isTimeout(in.err):
			return CategoryTimeout
		case isConnectionRefused(in.err):
			return CategoryConnectionRefused
		case isTLSFailure(in.err):
			return CategoryTLSFailure
		default:
			return CategoryOther
		}
	}

	if in.resp == nil {
		// No error and no response is an internal shape the taxonomy does not
		// model; keep the raw signal instead of pretending it succeeded.
		return CategoryOther
	}

	switch {
	case isRedirectLoop(in.resp, in.redirect, in.maxHops):
		return CategoryRedirectLoop
	case isEmptyBody(in.resp):
		return CategoryEmptyBody
	default:
		return CategoryOK
	}
}

// isTimeout matches deadline/cancelation failures at any layer.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// Wrapped messages from net/http and rawhttp keep the dialer's wording.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "deadline exceeded") ||
		strings.Contains(msg, "context canceled") ||
		strings.Contains(msg, "client.timeout exceeded")
}

// isConnectionRefused matches an active RST/ECONNREFUSED at connect time.
func isConnectionRefused(err error) bool {
	var sysErr *net.OpError
	if errors.As(err, &sysErr) {
		if strings.Contains(strings.ToLower(sysErr.Err.Error()), "connection refused") {
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connectex:") // Windows wording
}

// isTLSFailure matches handshake, certificate and protocol-level TLS errors.
func isTLSFailure(err error) bool {
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return true
	}
	var alertErr tls.AlertError
	if errors.As(err, &alertErr) {
		return true
	}
	var csErr *tls.CertificateVerificationError
	if errors.As(err, &csErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "tls handshake") ||
		strings.Contains(msg, "remote error: tls:") ||
		strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "ssl")
}

// isRedirectLoop detects a chain that reached the redirect limit while the
// last response is itself a redirect (3xx with a Location header). A chain
// that ends in a normal response after many hops is not a loop.
func isRedirectLoop(resp *httpx.Response, followRedirects bool, maxRedirects int) bool {
	if resp == nil || !followRedirects {
		return false
	}
	hops := len(resp.Chain)
	if maxRedirects <= 0 || hops < maxRedirects {
		return false
	}
	last := resp.Chain[hops-1]
	if last.StatusCode < 300 || last.StatusCode >= 400 {
		return false
	}
	return last.Location != "" || resp.GetHeader("Location") != ""
}

// isEmptyBody reports that a response was received but carries no body.
func isEmptyBody(resp *httpx.Response) bool {
	return resp != nil && len(resp.Data) == 0 && len(resp.RawData) == 0
}
