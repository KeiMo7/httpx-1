package diff

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// resultJSONFields mirrors the serialized TOP-LEVEL JSON keys of
// runner.Result. Inner tags of named nested structs (as_number inside "asn",
// timing fields inside "trace", ...) are not top-level keys and therefore do
// not belong here. The reflective cross-check in runner/diff_contract_test.go
// enforces that this list matches the real struct's top-level fields.
var resultJSONFields = []string{
	"timestamp", "link_request", "asn", "csp", "tls", "hash", "extract_regex",
	"cdn_name", "cdn_type", "sni", "port", "url", "input", "location", "title",
	"generator", "scheme", "error", "webserver", "body", "body_preview",
	"content_type", "method", "host", "host_ip", "path", "favicon",
	"favicon_md5", "favicon_path", "favicon_url", "final_url", "header",
	"raw_header", "request", "time", "jarm_hash", "chain_status_codes", "a",
	"aaaa", "cname", "tech", "extracts", "chain", "words", "lines",
	"status_code", "content_length", "failed", "vhost", "websocket", "cdn",
	"http2", "pipeline", "headless_body", "screenshot_bytes",
	"stored_response_path", "screenshot_path", "screenshot_path_rel",
	"knowledgebase", "resolvers", "body_fqdn", "body_domains", "trace",
	"cpe", "wordpress",
}

// TestCompareFieldContractIsExhaustive guarantees that every serialized
// Result field is explicitly accounted for: compared, ignored with a reason,
// or an identity key.
func TestCompareFieldContractIsExhaustive(t *testing.T) {
	jsonNames := map[string]struct{}{}
	for _, n := range resultJSONFields {
		jsonNames[n] = struct{}{}
	}

	accounted := map[string]struct{}{}
	for _, id := range IdentityFields {
		accounted[id] = struct{}{}
	}
	seenCompared := map[string]struct{}{}
	for _, spec := range CompareFieldSpecs {
		_, known := jsonNames[spec.JSONName]
		require.Truef(t, known, "compared field %q is not a serialized Result field", spec.JSONName)
		_, dup := seenCompared[spec.JSONName]
		require.Falsef(t, dup, "field %q appears twice in CompareFieldSpecs", spec.JSONName)
		seenCompared[spec.JSONName] = struct{}{}
		require.NotEmpty(t, spec.Category, "field %q has no category", spec.JSONName)
		accounted[spec.JSONName] = struct{}{}
	}
	for name, reason := range IgnoredFields {
		_, known := jsonNames[name]
		require.Truef(t, known, "ignored field %q is not a serialized Result field", name)
		require.NotEmptyf(t, reason, "ignored field %q must document a reason", name)
		_, dup := accounted[name]
		require.Falsef(t, dup, "field %q is both compared and ignored", name)
		accounted[name] = struct{}{}
	}

	for name := range jsonNames {
		_, ok := accounted[name]
		_, special := SpecialCompareFields[name]
		require.Truef(t, ok || special, "serialized field %q is neither compared, ignored, special nor an identity field", name)
	}
}

// TestSpecialFieldsAreRealAndExplained pins the dedicated-computation fields.
func TestSpecialFieldsAreRealAndExplained(t *testing.T) {
	for name, reason := range SpecialCompareFields {
		_, known := resultJSONFieldsSet()[name]
		require.Truef(t, known, "special field %q is not a serialized Result field", name)
		require.NotEmptyf(t, reason, "special field %q must explain why it needs dedicated logic", name)
	}
}

func resultJSONFieldsSet() map[string]struct{} {
	m := map[string]struct{}{}
	for _, n := range resultJSONFields {
		m[n] = struct{}{}
	}
	return m
}

// TestIgnoredFieldsStayVolatile pins the fields that must never participate:
// time, duration and operational artifacts. This is the test form of hard
// constraint 二.1 (stable identity) and 一.1 (comparable history).
func TestIgnoredFieldsStayVolatile(t *testing.T) {
	volatile := []string{"timestamp", "time", "trace", "request", "stored_response_path", "screenshot_path"}
	for _, name := range volatile {
		_, ignored := IgnoredFields[name]
		require.Truef(t, ignored, "%q must remain ignored", name)
		_, compared := fieldCategory[name]
		require.Falsef(t, compared, "%q must never be compared", name)
	}
}

// TestIdentityFieldsContainNoVolatileMaterial ensures no identity key can
// carry probe time, timing or hash data.
func TestIdentityFieldsContainNoVolatileMaterial(t *testing.T) {
	forbidden := map[string]struct{}{
		"timestamp": {}, "time": {}, "hash": {}, "body": {}, "trace": {},
	}
	for _, id := range IdentityFields {
		_, bad := forbidden[id]
		require.Falsef(t, bad, "identity field %q is volatile material", id)
	}
}

// TestContractUsesKnownCategories guards against typos in category names.
func TestContractUsesKnownCategories(t *testing.T) {
	valid := map[ChangeCategory]struct{}{}
	for _, c := range AllCategories {
		valid[c] = struct{}{}
	}
	for _, spec := range CompareFieldSpecs {
		_, ok := valid[spec.Category]
		require.Truef(t, ok, "field %q uses unknown category %q", spec.JSONName, spec.Category)
	}
}
