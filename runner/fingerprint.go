package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/fingerprint"
	"github.com/projectdiscovery/httpx/common/hashes/jarm"
	"github.com/projectdiscovery/httpx/common/httpx"
	urlutil "github.com/projectdiscovery/utils/url"
)

// jarmCache remembers one JARM hash per host for the run: the same host is
// often probed for several methods and paths, and JARM opens its own
// connections, so recomputing it per probe would multiply the traffic.
var jarmCache sync.Map // host -> string

// jarmFor returns the JARM hash of host, computing it at most once per host.
// A failure returns the empty string and is logged at debug level only.
func (r *Runner) jarmFor(hp *httpx.HTTPX, fullURL string) string {
	key := jarmHostKey(fullURL)
	if key == "" {
		return ""
	}
	if cached, ok := jarmCache.Load(key); ok {
		return cached.(string)
	}
	value := jarm.Jarm(hp.Dialer, fullURL, r.options.Timeout)
	if value == "" {
		gologger.Debug().Msgf("jarm probe failed for %s", key)
	}
	jarmCache.Store(key, value)
	return value
}

// jarmHostKey reduces a URL to the host:port that identifies its JARM
// service, or the empty string when the URL has no host.
func jarmHostKey(rawURL string) string {
	parsed, err := urlutil.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "http" {
			return ""
		}
		port = "443"
	}
	return parsed.Hostname() + ":" + port
}

// sortCPEInfos orders a CPE list so the JSON and CSV output is independent of
// the map iteration order of the detector.
func sortCPEInfos(cpes []CPEInfo) {
	sort.Slice(cpes, func(i, j int) bool {
		if cpes[i].CPE != cpes[j].CPE {
			return cpes[i].CPE < cpes[j].CPE
		}
		if cpes[i].Product != cpes[j].Product {
			return cpes[i].Product < cpes[j].Product
		}
		return cpes[i].Vendor < cpes[j].Vendor
	})
}

// tlsNames joins the subject names of a TLS response, for the tls source.
func tlsNames(resp *httpx.Response) string {
	if resp == nil || resp.TLSData == nil {
		return ""
	}
	names := append([]string(nil), resp.TLSData.SubjectAN...)
	if resp.TLSData.SubjectCN != "" {
		names = append(names, resp.TLSData.SubjectCN)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// computeFingerprint builds the fingerprint of a response from the six
// evidence sources. Empty sources stay empty: nothing is replaced by a
// placeholder string.
func (r *Runner) computeFingerprint(hp *httpx.HTTPX, title string, resp *httpx.Response, faviconMMH3, faviconMD5, faviconPath, faviconURL, jarmhash, cdnName string, technologies []string) *fingerprint.Fingerprint {
	in := fingerprint.Input{
		Title:       title,
		Body:        string(resp.Data),
		RawHeaders:  resp.RawHeaders,
		FaviconMMH3: faviconMMH3,
		FaviconMD5:  faviconMD5,
		JARM:        jarmhash,
		TLSNames:    tlsNames(resp),
		CDNName:     cdnName,
	}

	// Cache the fingerprint by the request key so the same target probed for
	// several methods does not re-match. The key covers every evidence source.
	key := fingerprintCacheKey(in)
	if cached, _, err := r.fingerprintCache.GetOrLoad(key, func() (any, error) {
		fp := r.fingerprinter.Fingerprint(in)
		return &fp, nil
	}); err == nil {
		if cachedFP, ok := cached.(*fingerprint.Fingerprint); ok {
			// The favicon path and URL are per-request, not per-input.
			clone := *cachedFP
			clone.FaviconPath = faviconPath
			clone.FaviconURL = faviconURL
			return &clone
		}
	}

	fp := r.fingerprinter.Fingerprint(in)
	fp.FaviconPath = faviconPath
	fp.FaviconURL = faviconURL
	return &fp
}

// fingerprintCacheKey hashes the evidence of an input, so equal evidence
// shares one cached fingerprint.
func fingerprintCacheKey(in fingerprint.Input) string {
	h := sha256.New()
	for _, field := range []string{in.Title, in.Body, in.RawHeaders, in.FaviconMMH3, in.FaviconMD5, in.JARM, in.TLSNames, in.CDNName} {
		h.Write([]byte(field))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
