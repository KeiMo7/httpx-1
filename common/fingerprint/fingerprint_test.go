package fingerprint_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/projectdiscovery/httpx/common/fingerprint"
)

const rulesJSONL = `
{"id":"wp-title","source":"title","pattern":"WordPress","product":"WordPress","vendor":"Automattic","version":"6.0","confidence":90}
{"id":"wp-body","source":"body","pattern":"wp-content","product":"  Wordpress  ","vendor":"automattic","confidence":80}
{"id":"nginx-header","source":"header","pattern":"nginx/([0-9.]+)","product":"nginx","vendor":"NGINX","version":"","confidence":70}
{"id":"nginx-title","source":"title","pattern":"nginx","product":"NGINX","vendor":"NGINX Server","confidence":95}
{"id":"gunicorn-header","source":"header","pattern":"gunicorn","product":"gunicorn","vendor":"Benny Bottema","version":"19.9.0","confidence":60}
{"id":"gunicorn-body","source":"body","pattern":"gunicorn","product":"gunicorn","vendor":"Benny Bottema","version":"20.1.0","confidence":65}
{"id":"jarm-rule","source":"jarm","pattern":"29d29d00029d29d","product":"Some TLS stack","vendor":"Example","confidence":50}
{"id":"tls-rule","source":"tls","pattern":"example.org","product":"Example TLS","vendor":"Example","confidence":40}
{"id":"cdn-rule","source":"cdn","pattern":"cloudflare","product":"Cloudflare","vendor":"Cloudflare, Inc.","confidence":85}
{"id":"favicon-rule","source":"favicon","pattern":"1522510080","product":"Jenkins","vendor":"Jenkins","confidence":100}
`

func loadTestRules(t *testing.T) *fingerprint.RuleSet {
	t.Helper()
	rules, err := fingerprint.LoadRules(strings.NewReader(rulesJSONL))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return rules
}

func fullInput() fingerprint.Input {
	return fingerprint.Input{
		Title:       "WordPress nginx",
		Body:        "<html>wp-content gunicorn</html>",
		RawHeaders:  "Server: nginx/1.21.0\r\nX-Powered-By: gunicorn\r\n",
		FaviconMMH3: "1522510080",
		FaviconMD5:  "abcdef",
		JARM:        "29d29d00029d29d00029d29d00029d29d00029d29d00029d29d00029d29d",
		TLSNames:    "example.org",
		CDNName:     "cloudflare",
	}
}

// Shuffling the evidence that produces the same set of matches must not change
// the digest: the merge is order independent.
func TestDigestIsStableAcrossShuffledEvidence(t *testing.T) {
	rules := loadTestRules(t)
	input := fullInput()

	// The rule set is fixed, so digest stability is exercised through the
	// merged fields: build several inputs whose evidence order varies by
	// swapping the title/body/header order is not possible (the fields are
	// distinct sources), so instead account for rule order in the file.
	want := rules.Fingerprint(input).Digest()
	for i := 0; i < 100; i++ {
		shuffledRules := shuffleRuleLines(rulesJSONL, i)
		rs, err := fingerprint.LoadRules(strings.NewReader(shuffledRules))
		if err != nil {
			t.Fatalf("load shuffled rules: %v", err)
		}
		if got := rs.Fingerprint(input).Digest(); got != want {
			t.Fatalf("order %d: digest changed: got %s want %s", i, got, want)
		}
	}
}

func shuffleRuleLines(jsonl string, seed int) string {
	lines := strings.Split(strings.TrimSpace(jsonl), "\n")
	rng := rand.New(rand.NewSource(int64(seed)))
	rng.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
	return strings.Join(lines, "\n")
}

func TestEmptyInput(t *testing.T) {
	rules := loadTestRules(t)
	fp := rules.Fingerprint(fingerprint.Input{})
	if len(fp.Technologies) != 0 {
		t.Errorf("expected no technologies, got %v", fp.Technologies)
	}
	if len(fp.BodyHashes) != 0 || len(fp.HeaderHashes) != 0 {
		t.Errorf("empty input must not hash empty bodies: %v %v", fp.BodyHashes, fp.HeaderHashes)
	}
	if fp.FaviconMMH3 != "" || fp.FaviconMD5 != "" || fp.JARM != "" || fp.CDNName != "" {
		t.Errorf("empty input must leave string fields empty: %+v", fp)
	}
	if fp.RuleDigest != rules.RuleDigest() {
		t.Errorf("rule digest must always be set")
	}
	if empty := (fingerprint.Fingerprint{}).Digest(); empty == "" {
		t.Errorf("an empty fingerprint still has a digest")
	}
}

func TestUnicodeProductName(t *testing.T) {
	rules, err := fingerprint.LoadRules(strings.NewReader(
		`{"id":"u","source":"title","pattern":"敷地","product":"日本語サーバー","vendor":"例","confidence":50}`))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	fp := rules.Fingerprint(fingerprint.Input{Title: "ようこそ 敷地 へ"})
	if len(fp.Technologies) != 1 || fp.Technologies[0] != "日本語サーバー" {
		t.Fatalf("unexpected technologies: %v", fp.Technologies)
	}
	if len(fp.CPEs) != 1 || !strings.Contains(fp.CPEs[0].CPE, "日本語サーバー") {
		t.Fatalf("unexpected cpes: %v", fp.CPEs)
	}
}

func TestCaseAndWhitespaceMerge(t *testing.T) {
	rules := loadTestRules(t)
	fp := rules.Fingerprint(fingerprint.Input{
		Title: "WordPress",
		Body:  "wp-content",
	})
	// wp-title (WordPress) and wp-body ("  Wordpress  ") share the normalized
	// (vendor, product) key, so they merge to one technology.
	if len(fp.Technologies) != 1 {
		t.Fatalf("expected one merged technology, got %v", fp.Technologies)
	}
	if fp.Technologies[0] != "WordPress" {
		t.Fatalf("the display name must come from the highest confidence rule, got %q", fp.Technologies[0])
	}
	want := "cpe:2.3:a:automattic:wordpress:6.0:*:*:*:*:*:*:*"
	if len(fp.CPEs) != 1 || fp.CPEs[0].CPE != want {
		t.Fatalf("unexpected cpe: %v (want %s)", fp.CPEs, want)
	}
}

func TestVersionConflict(t *testing.T) {
	rules := loadTestRules(t)
	fp := rules.Fingerprint(fingerprint.Input{
		Body:       "gunicorn",
		RawHeaders: "Server: gunicorn\r\n",
	})
	// gunicorn-body has confidence 65 with version 20.1.0; gunicorn-header has
	// 60 with 19.9.0. The highest confidence version wins.
	var found string
	for _, cpe := range fp.CPEs {
		if strings.Contains(cpe.CPE, "gunicorn") {
			found = cpe.CPE
		}
	}
	if !strings.Contains(found, ":20.1.0:") {
		t.Fatalf("expected the higher confidence version, got %q", found)
	}

	// Same confidence: the smallest version in byte order wins.
	rs, err := fingerprint.LoadRules(strings.NewReader(`
{"id":"a","source":"body","pattern":"x","product":"p","vendor":"v","version":"2.0","confidence":50}
{"id":"b","source":"title","pattern":"x","product":"p","vendor":"v","version":"1.0","confidence":50}`))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	got := rs.Fingerprint(fingerprint.Input{Body: "x", Title: "x"})
	if len(got.CPEs) != 1 || !strings.Contains(got.CPEs[0].CPE, ":1.0:") {
		t.Fatalf("expected the byte-order smallest version, got %v", got.CPEs)
	}
}

func TestCPESorted(t *testing.T) {
	rules, err := fingerprint.LoadRules(strings.NewReader(`
{"id":"z","source":"body","pattern":"zeta","product":"zeta","vendor":"v","confidence":50}
{"id":"a","source":"body","pattern":"alpha","product":"alpha","vendor":"v","confidence":50}
{"id":"m","source":"body","pattern":"mid","product":"mid","vendor":"v","confidence":50}`))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	fp := rules.Fingerprint(fingerprint.Input{Body: "zeta alpha mid"})
	if len(fp.CPEs) != 3 {
		t.Fatalf("expected 3 cpes, got %v", fp.CPEs)
	}
	if !sort.SliceIsSorted(fp.CPEs, func(i, j int) bool { return fp.CPEs[i].CPE < fp.CPEs[j].CPE }) {
		t.Fatalf("cpes are not sorted: %v", fp.CPEs)
	}
}

func TestTechnologiesSortedByKey(t *testing.T) {
	rules, err := fingerprint.LoadRules(strings.NewReader(`
{"id":"b","source":"body","pattern":"beta","product":"Beta","vendor":"v","confidence":10}
{"id":"a","source":"body","pattern":"alpha","product":"alpha","vendor":"v","confidence":20}`))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	fp := rules.Fingerprint(fingerprint.Input{Body: "beta alpha"})
	// sorted by normalized key: alpha before beta
	if len(fp.Technologies) != 2 || fp.Technologies[0] != "alpha" || fp.Technologies[1] != "Beta" {
		t.Fatalf("unexpected order: %v", fp.Technologies)
	}
}

func TestMatchKeepsEvidence(t *testing.T) {
	rules := loadTestRules(t)
	evidence := rules.Match(fingerprint.Input{Title: "WordPress", RawHeaders: "Server: nginx/1.21.0\r\n"})
	if len(evidence) < 2 {
		t.Fatalf("expected at least two evidence entries, got %v", evidence)
	}
	for _, ev := range evidence {
		if ev.RuleID == "" || ev.Product == "" {
			t.Fatalf("evidence lost a field: %+v", ev)
		}
		if ev.Fragment == "" {
			t.Fatalf("evidence lost its fragment: %+v", ev)
		}
	}
}

func TestStats(t *testing.T) {
	rules, err := fingerprint.LoadRules(strings.NewReader(`
{"id":"good","source":"body","pattern":"x","product":"p","vendor":"v","confidence":50}`))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	stats := rules.Stats()
	if stats.Rules != 1 || stats.Dropped != 0 || stats.Matched != 0 {
		t.Fatalf("unexpected initial stats: %+v", stats)
	}
	rules.Match(fingerprint.Input{Body: "x"})
	stats = rules.Stats()
	if stats.Matched != 1 {
		t.Fatalf("expected one match, got %+v", stats)
	}
}

// The golden file records the canonical JSON of a full fingerprint. A change
// that alters sorting, key names or merge rules must fail this test.
func TestGoldenFingerprint(t *testing.T) {
	rules := loadTestRules(t)
	fp := rules.Fingerprint(fullInput())
	got, err := json.MarshalIndent(fp, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("testdata/fingerprint.golden.json")
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestBodyAndHeaderHashKeys(t *testing.T) {
	rules := loadTestRules(t)
	fp := rules.Fingerprint(fingerprint.Input{Body: "body", RawHeaders: "headers"})
	wantKeys := []string{"md5", "mmh3", "sha1", "sha256", "sha512", "simhash"}
	for _, key := range wantKeys {
		if _, ok := fp.BodyHashes[key]; !ok {
			t.Fatalf("missing body hash key %q", key)
		}
		if _, ok := fp.HeaderHashes[key]; !ok {
			t.Fatalf("missing header hash key %q", key)
		}
	}
	if len(fp.BodyHashes) != len(wantKeys) || len(fp.HeaderHashes) != len(wantKeys) {
		t.Fatalf("unexpected hash key count: %v %v", fp.BodyHashes, fp.HeaderHashes)
	}
	data, err := json.Marshal(fp.BodyHashes)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Index(string(data), `"md5"`) > strings.Index(string(data), `"mmh3"`) {
		t.Fatalf("hash keys are not sorted: %s", data)
	}
}

func TestNoDuplicateEvidence(t *testing.T) {
	rules, err := fingerprint.LoadRules(strings.NewReader(`
{"id":"dup1","source":"body","pattern":"x","product":"P","vendor":"V","confidence":50}
{"id":"dup2","source":"title","pattern":"x","product":"p","vendor":"v","confidence":50}
{"id":"dup3","source":"body","pattern":"x","product":"p ","vendor":" V ","confidence":50}`))
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	evidence := rules.Match(fingerprint.Input{Body: "x", Title: "x"})
	if len(evidence) != 3 {
		t.Fatalf("expected three raw matches, got %d", len(evidence))
	}
	fp := rules.Fingerprint(fingerprint.Input{Body: "x", Title: "x"})
	if len(fp.Technologies) != 1 || len(fp.CPEs) != 1 {
		t.Fatalf("duplicate evidence must merge to one entry: %v %v", fp.Technologies, fp.CPEs)
	}
}

func TestSourceOrder(t *testing.T) {
	for i, want := range []string{"title", "header", "body", "favicon", "jarm", "tls", "cdn"} {
		if got := fingerprint.Source(i).String(); got != want {
			t.Errorf("source %d = %q, want %q", i, got, want)
		}
	}
	// AllSources is the fixed priority slice, in domain order.
	if got := fmt.Sprint(fingerprint.AllSources); got != "[title header body favicon jarm tls cdn]" {
		t.Errorf("unexpected source order: %s", got)
	}
}
