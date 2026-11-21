// Package diff implements deterministic, streaming comparison of two httpx
// JSONL result sets (a baseline run and a current run).
//
// The comparison contract (which fields participate and which category a
// change belongs to) is declared as data in this file, not in comments:
// CompareFieldSpecs is the single source of truth. Fields absent from the
// contract are never compared (see IgnoredFields for the explicit,
// machine-checked ignore list).
package diff

// ChangeCategory classifies a single difference. Categories are mutually
// distinct so that, for example, a body change and a header-only change of
// the same target never land in the same bucket.
type ChangeCategory string

const (
	// CategoryAvailability: the target flipped between reachable and
	// unreachable, or exists in only one of the two runs.
	CategoryAvailability ChangeCategory = "availability"
	// CategorySource: address resolution changed (A/AAAA/CNAME/host IP/SNI).
	CategorySource ChangeCategory = "source"
	// CategoryCertificate: the TLS certificate (or TLS metadata) changed
	// while the page itself stayed the same.
	CategoryCertificate ChangeCategory = "certificate"
	// CategoryRedirect: the redirect chain changed (hop count, any hop's
	// status code/location/URL, final landing point or scheme).
	CategoryRedirect ChangeCategory = "redirect"
	// CategoryBody: the response body summary changed (body hash, body
	// preview or full body).
	CategoryBody ChangeCategory = "body"
	// CategoryHeader: response headers changed without a body change.
	CategoryHeader ChangeCategory = "header"
	// CategoryField: any other compared scalar/collection field changed
	// (status code, title, technology stack, web server, ...).
	CategoryField ChangeCategory = "field"
)

// AllCategories is the ordered list of categories. The order is fixed and
// used for deterministic summary output.
var AllCategories = []ChangeCategory{
	CategoryAvailability,
	CategorySource,
	CategoryCertificate,
	CategoryRedirect,
	CategoryBody,
	CategoryHeader,
	CategoryField,
}

// FieldSpec declares one JSON field that participates in comparison and the
// category its change belongs to. The JSON name matches the `json:` tag of
// runner.Result. Comparison of the decoded value is done via canonical JSON
// (see canonicalize), so ordering of slices/maps matters only through their
// serialized, deterministic form.
type FieldSpec struct {
	// JSONName is the exact key under which the field appears in the JSONL
	// output of httpx.
	JSONName string
	// Category is the change category assigned when the value differs.
	Category ChangeCategory
}

// CompareFieldSpecs is THE comparison contract: every field listed here is
// compared; every field not listed here is ignored. It is code (not a
// comment) on purpose, and the exhaustive-field test in fields_test.go
// guarantees that every JSON-serialized runner.Result field is either listed
// here or in IgnoredFields.
var CompareFieldSpecs = []FieldSpec{
	// --- availability is derived from the "failed" flag separately, but the
	// failure reason string still participates as a regular field ---
	{JSONName: "failed", Category: CategoryAvailability},
	{JSONName: "error", Category: CategoryField},

	// --- identity-adjacent scalars (never used as the key itself) ---
	{JSONName: "scheme", Category: CategoryRedirect},
	{JSONName: "location", Category: CategoryRedirect},
	{JSONName: "final_url", Category: CategoryRedirect},
	{JSONName: "chain_status_codes", Category: CategoryRedirect},
	{JSONName: "chain", Category: CategoryRedirect},

	// --- source / address resolution (requirement 一.6) ---
	{JSONName: "host_ip", Category: CategorySource},
	{JSONName: "a", Category: CategorySource},
	{JSONName: "aaaa", Category: CategorySource},
	{JSONName: "cname", Category: CategorySource},
	{JSONName: "sni", Category: CategorySource},

	// --- TLS / certificate (requirement 一.7) ---
	{JSONName: "tls", Category: CategoryCertificate},
	{JSONName: "jarm_hash", Category: CategoryCertificate},

	// --- response body summary (requirement 一.3) ---
	// "hash" is handled specially (see SpecialCompareFields): its object
	// mixes body_* and header_* digests and each subkey is categorized
	// independently so a header digest change is never reported as a body
	// change.
	{JSONName: "body_preview", Category: CategoryBody},
	{JSONName: "body", Category: CategoryBody},
	{JSONName: "content_length", Category: CategoryBody},
	{JSONName: "words", Category: CategoryBody},
	{JSONName: "lines", Category: CategoryBody},
	{JSONName: "headless_body", Category: CategoryBody},
	{JSONName: "body_fqdn", Category: CategoryBody},
	{JSONName: "body_domains", Category: CategoryBody},
	{JSONName: "favicon", Category: CategoryBody},
	{JSONName: "favicon_md5", Category: CategoryBody},

	// --- response headers without body change (requirement 一.3) ---
	{JSONName: "header", Category: CategoryHeader},
	{JSONName: "raw_header", Category: CategoryHeader},
	{JSONName: "content_type", Category: CategoryHeader},
	{JSONName: "webserver", Category: CategoryHeader},

	// --- generic page fields (requirement 一.1) ---
	{JSONName: "status_code", Category: CategoryField},
	{JSONName: "title", Category: CategoryField},
	{JSONName: "generator", Category: CategoryField},
	{JSONName: "tech", Category: CategoryField},
	{JSONName: "method", Category: CategoryField},
	{JSONName: "host", Category: CategoryField},
	{JSONName: "port", Category: CategoryField},
	{JSONName: "path", Category: CategoryField},
	{JSONName: "url", Category: CategoryField},
	{JSONName: "cdn", Category: CategoryField},
	{JSONName: "cdn_name", Category: CategoryField},
	{JSONName: "cdn_type", Category: CategoryField},
	{JSONName: "http2", Category: CategoryField},
	{JSONName: "pipeline", Category: CategoryField},
	{JSONName: "websocket", Category: CategoryField},
	{JSONName: "vhost", Category: CategoryField},
	{JSONName: "csp", Category: CategoryField},
	// The whole "asn" object is compared as one top-level field; its inner
	// keys (as_number/as_name/...) are not top-level Result fields.
	{JSONName: "asn", Category: CategoryField},
	{JSONName: "cpe", Category: CategoryField},
	{JSONName: "wordpress", Category: CategoryField},
	{JSONName: "extract_regex", Category: CategoryField},
	{JSONName: "extracts", Category: CategoryField},
	{JSONName: "knowledgebase", Category: CategoryField},
	{JSONName: "resolvers", Category: CategoryField},
}

// IgnoredFields lists every JSON-serialized runner.Result field that is
// deliberately excluded from comparison, with the reason encoded in the map
// value. Volatile/ephemeral data must never make two identical observations
// look different, and identity/materialized artifacts must not be compared.
var IgnoredFields = map[string]string{
	// probe wall-clock time: not a property of the target (hard constraint 一.1)
	"timestamp": "probe wall-clock time, inherently different each run",
	// request/response timing: nondeterministic latency, explicitly excluded
	"time": "response duration is nondeterministic",
	// full request/response raw material and traces are operational artifacts
	"request":              "raw request artifact, not a target property",
	"stored_response_path": "local filesystem path of the operator machine",
	"screenshot_path":      "local filesystem path of the operator machine",
	"screenshot_path_rel":  "local filesystem path of the operator machine",
	"screenshot_bytes":     "binary screenshot artifact, not a stable field",
	"link_request":         "operational request linkage metadata",
	"trace":                "per-connection timing trace, nondeterministic",
	"favicon_path":         "local filesystem path of the operator machine",
	"favicon_url":          "derived URL of operator-chosen probe path",
}

// SpecialCompareFields names top-level fields whose comparison cannot be a
// single whole-value category and is implemented by dedicated logic in the
// engine. Each entry documents why. "hash" contains both body_* and header_*
// digests in one object: comparing it as a whole would misclassify a header
// digest change as a body change (violating the body/header separation).
var SpecialCompareFields = map[string]string{
	"hash": "object mixes body_* (body category) and header_* (header category) digests; compared per subkey in compareHashField",
}

// HashSubkeyCategory maps the prefix of a "hash" object subkey to its change
// category. Every subkey produced by runner has one of these two prefixes.
var HashSubkeyCategory = map[string]ChangeCategory{
	"body_":   CategoryBody,
	"header_": CategoryHeader,
}

// fieldCategory maps JSON name -> category for fast lookup.
var fieldCategory = func() map[string]ChangeCategory {
	out := make(map[string]ChangeCategory, len(CompareFieldSpecs))
	for _, spec := range CompareFieldSpecs {
		out[spec.JSONName] = spec.Category
	}
	return out
}()
