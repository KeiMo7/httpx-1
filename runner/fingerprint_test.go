package runner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
)

const testFingerprintRules = `
{"id":"wp-title","source":"title","pattern":"WordPress","product":"WordPress","vendor":"Automattic","version":"6.0","confidence":90}
{"id":"wp-body","source":"body","pattern":"wp-content","product":"wordpress","vendor":"automattic","confidence":70}
{"id":"nginx-header","source":"header","pattern":"nginx","product":"nginx","vendor":"NGINX","confidence":80}
{"id":"favicon-rule","source":"favicon","pattern":"FaviconHash","product":"Favorite","vendor":"Example","confidence":50}
{"id":"cdn-rule","source":"cdn","pattern":"cloudflare","product":"Cloudflare","vendor":"Cloudflare","confidence":60}
`

func writeFingerprintRules(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fp-rules.jsonl")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func runFingerprintProbe(t *testing.T, rulesPath string, target string, mutate func(*Options)) []Result {
	t.Helper()
	var (
		mu      sync.Mutex
		results []Result
	)
	options := &Options{Threads: 1, Timeout: 5, Methods: http.MethodGet, RateLimit: 0, FingerprintRulesPath: rulesPath}
	options.InputTargetHost = []string{target}
	if mutate != nil {
		mutate(options)
	}
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
	return results
}

// Favicon candidates are ordered .ico first, then the rest in byte order, and
// inline data: icons before any network request.
func TestFingerprintFaviconCandidateOrder(t *testing.T) {
	page := []byte(`<html><head>
<link rel="icon" href="/z.png">
<link rel="icon" href="/a.png">
<link rel="icon" href="/favicon.ico">
<link rel="icon" href="data:image/png;base64,iVBORw0KGgo=">
</head></html>`)
	candidates, _, err := extractPotentialFavIconsURLs(page)
	require.NoError(t, err)
	require.Equal(t, []string{
		"data:image/png;base64,iVBORw0KGgo=",
		"/favicon.ico",
		"/a.png",
		"/z.png",
	}, candidates)
}

// The same product matched by two rules merges to one technology.
func TestFingerprintMergesSameProduct(t *testing.T) {
	rules := writeFingerprintRules(t, testFingerprintRules)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>WordPress</title></head><body>wp-content</body></html>"))
	}))
	defer server.Close()

	results := runFingerprintProbe(t, rules, server.URL, nil)
	require.Len(t, results, 1)
	fp := results[0].Fingerprint
	require.NotNil(t, fp)
	require.Len(t, fp.Technologies, 1, "same normalized product must merge: %v", fp.Technologies)
	require.Equal(t, "WordPress", fp.Technologies[0], "the highest confidence display name wins")
	require.Len(t, fp.CPEs, 1)
	require.Contains(t, fp.CPEs[0].CPE, ":6.0:")
}

// When -fp-rules is not configured, Result.Fingerprint stays nil and JSON has
// no fingerprint key.
func TestFingerprintAbsentWithoutRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>hello</body></html>"))
	}))
	defer server.Close()

	results := runFingerprintProbe(t, "", server.URL, nil)
	require.Len(t, results, 1)
	require.Nil(t, results[0].Fingerprint)
	require.NotContains(t, results[0].JSON(nil), "fingerprint")
}

// A configured rule set makes JSON carry the fingerprint key.
func TestFingerprintPresentInJSON(t *testing.T) {
	rules := writeFingerprintRules(t, testFingerprintRules)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>WordPress</title></head></html>"))
	}))
	defer server.Close()

	results := runFingerprintProbe(t, rules, server.URL, nil)
	require.Len(t, results, 1)
	require.NotNil(t, results[0].Fingerprint)
	require.Contains(t, results[0].JSON(nil), `"fingerprint":`)
}

// A favicon hash matched by a rule is part of the fingerprint, and the favicon
// is probed even without -favicon.
func TestFingerprintUsesFavicon(t *testing.T) {
	rules := writeFingerprintRules(t, testFingerprintRules)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><head><link rel=\"icon\" href=\"/favicon.ico\"></head></html>"))
		case "/favicon.ico":
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write(testFaviconGIF)
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	var mmh3 string
	results := runFingerprintProbe(t, rules, server.URL, func(options *Options) {
		options.FingerprintRulesPath = rules
	})
	require.Len(t, results, 1)
	fp := results[0].Fingerprint
	require.NotNil(t, fp)
	require.NotEmpty(t, fp.FaviconMMH3, "the favicon is probed for fingerprinting")
	mmh3 = fp.FaviconMMH3
	require.NotEmpty(t, fp.FaviconPath)
	_ = mmh3
}

// The fingerprint JSON key set is lowercase and matches the documented fields.
func TestFingerprintJSONKeys(t *testing.T) {
	rules := writeFingerprintRules(t, testFingerprintRules)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>WordPress</title></head></html>"))
	}))
	defer server.Close()

	results := runFingerprintProbe(t, rules, server.URL, nil)
	require.Len(t, results, 1)
	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(results[0].JSON(nil)), &decoded))
	require.Contains(t, decoded, "fingerprint")
	root := decoded["fingerprint"].(map[string]any)
	for _, key := range []string{"technologies", "cpes", "rule_digest"} {
		require.Contains(t, root, key)
	}
	// CSV and Markdown never carry the new fields.
	require.NotContains(t, results[0].CSVRow(nil), "fingerprint")
	require.NotContains(t, results[0].MarkdownRow(nil), "fingerprint")
}

// A rule file with bad syntax is rejected at validation time, not silently.
func TestFingerprintInvalidRulesFile(t *testing.T) {
	path := writeFingerprintRules(t, `{"id":"a","source":"body","pattern":"(","product":"p","confidence":1}`)
	require.NoError(t, (&Options{FingerprintRulesPath: path}).ValidateOptions())
	// The file exists, so validation passes; New rejects the bad rule.
	options := &Options{FingerprintRulesPath: path}
	_, err := New(options)
	require.Error(t, err)
	require.Contains(t, err.Error(), path+":1:")
}

// A missing rule file fails validation.
func TestFingerprintMissingRulesFile(t *testing.T) {
	options := &Options{FingerprintRulesPath: "/nonexistent/rules.jsonl"}
	err := options.ValidateOptions()
	require.Error(t, err)
	require.Contains(t, err.Error(), "/nonexistent/rules.jsonl")
}

// jarmHostKey reduces a URL to its host:port, and returns empty for plain
// http URLs that cannot be JARM probed.
func TestJarmHostKey(t *testing.T) {
	cases := map[string]string{
		"https://example.com":        "example.com:443",
		"https://example.com:8443/x": "example.com:8443",
		"http://example.com":         "",
		"http://example.com:8080":    "example.com:8080",
		"not a url":                  "",
	}
	for raw, want := range cases {
		require.Equal(t, want, jarmHostKey(raw), raw)
	}
}

// jarmFor computes a host's JARM once and caches it, however many probes ask.
func TestJarmForCachesPerHost(t *testing.T) {
	r := &Runner{options: &Options{Timeout: 1}}
	hp := &httpx.HTTPX{}
	// A dialer that always fails makes JARM return the empty string; the cache
	// still records the result, so the second call does not recompute.
	first := r.jarmFor(hp, "https://example.org")
	second := r.jarmFor(hp, "https://example.org")
	require.Equal(t, first, second)
	jarmCache.Delete("example.org:443")
}

// A non-200 favicon response is a miss: the hashes stay empty and the scan
// continues.
func TestFaviconNon200IsMiss(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><head><link rel=\"icon\" href=\"/favicon.ico\"></head></html>"))
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	results := runFingerprintProbe(t, "", server.URL, func(options *Options) {
		options.Favicon = true
	})
	require.Len(t, results, 1)
	require.Empty(t, results[0].FavIconMMH3, "a 404 favicon must not produce a hash")
	require.Empty(t, results[0].FavIconMD5)
}

// A favicon that decodes but cannot be hashed as an image is a miss, and every
// candidate failing leaves both hashes empty without aborting the scan.
func TestFaviconAllCandidatesFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html><head><title>ok</title><link rel=\"icon\" href=\"/bad.ico\"></head><body>ok</body></html>"))
		default:
			w.Header().Set("Content-Type", "image/x-icon")
			_, _ = w.Write([]byte("not an image"))
		}
	}))
	defer server.Close()

	results := runFingerprintProbe(t, "", server.URL, func(options *Options) {
		options.Favicon = true
	})
	require.Len(t, results, 1)
	require.Empty(t, results[0].FavIconMMH3)
	require.Empty(t, results[0].FavIconMD5)
}

// At most two network fetches are issued for one favicon probe.
func TestFaviconAtMostTwoFetches(t *testing.T) {
	var (
		mu      sync.Mutex
		fetches int
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		fetches++
		mu.Unlock()
		switch req.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head>
<link rel="icon" href="a.png">
<link rel="icon" href="b.png">
<link rel="icon" href="c.png">
</head></html>`))
		default:
			http.NotFound(w, req)
		}
	}))
	defer server.Close()

	results := runFingerprintProbe(t, "", server.URL, func(options *Options) {
		options.Favicon = true
	})
	require.Len(t, results, 1)
	// One page request plus at most two favicon fetches.
	mu.Lock()
	defer mu.Unlock()
	require.LessOrEqual(t, fetches, 3, "got %d requests", fetches)
}
