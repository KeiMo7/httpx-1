package fingerprint_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/projectdiscovery/httpx/common/fingerprint"
)

// Ten illegal rule files, each asserted to carry a "file:line" in its error.
func TestLoadRulesRejectsIllegalFiles(t *testing.T) {
	cases := []struct {
		name  string
		rules string
		want  string // substring expected in the error
	}{
		{
			name:  "duplicate id",
			rules: "{\"id\":\"a\",\"source\":\"body\",\"pattern\":\"x\",\"product\":\"p\",\"confidence\":1}\n{\"id\":\"a\",\"source\":\"title\",\"pattern\":\"y\",\"product\":\"q\",\"confidence\":1}",
			want:  "rules:2: duplicate rule id",
		},
		{
			name:  "bad regex",
			rules: "{\"id\":\"a\",\"source\":\"body\",\"pattern\":\"(\",\"product\":\"p\",\"confidence\":1}",
			want:  "rules:1: invalid pattern",
		},
		{
			name:  "unknown source",
			rules: "{\"id\":\"a\",\"source\":\"cookie\",\"pattern\":\"x\",\"product\":\"p\",\"confidence\":1}",
			want:  "rules:1: unknown source",
		},
		{
			name:  "confidence too high",
			rules: "{\"id\":\"a\",\"source\":\"body\",\"pattern\":\"x\",\"product\":\"p\",\"confidence\":101}",
			want:  "rules:1: confidence 101 out of range",
		},
		{
			name:  "confidence negative",
			rules: "{\"id\":\"a\",\"source\":\"body\",\"pattern\":\"x\",\"product\":\"p\",\"confidence\":-1}",
			want:  "rules:1: confidence -1 out of range",
		},
		{
			name:  "missing id",
			rules: "{\"source\":\"body\",\"pattern\":\"x\",\"product\":\"p\",\"confidence\":1}",
			want:  "rules:1: missing required field \"id\"",
		},
		{
			name:  "missing source",
			rules: "{\"id\":\"a\",\"pattern\":\"x\",\"product\":\"p\",\"confidence\":1}",
			want:  "rules:1: missing required field \"source\"",
		},
		{
			name:  "missing pattern",
			rules: "{\"id\":\"a\",\"source\":\"body\",\"product\":\"p\",\"confidence\":1}",
			want:  "rules:1: missing required field \"pattern\"",
		},
		{
			name:  "missing product",
			rules: "{\"id\":\"a\",\"source\":\"body\",\"pattern\":\"x\",\"confidence\":1}",
			want:  "rules:1: missing required field \"product\"",
		},
		{
			name:  "invalid json",
			rules: "{\"id\":\"a\",",
			want:  "rules:1: invalid json",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := fingerprint.LoadRules(strings.NewReader(tc.rules))
			if err == nil {
				t.Fatalf("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestLoadRulesEmptyFile(t *testing.T) {
	rules, err := fingerprint.LoadRules(strings.NewReader("\n\n\n"))
	if err != nil {
		t.Fatalf("an empty file is readable: %v", err)
	}
	if rules.Stats().Rules != 0 {
		t.Fatalf("an empty file has no rules: %+v", rules.Stats())
	}
}

func TestLoadRulesFromMissingFile(t *testing.T) {
	_, err := fingerprint.LoadRulesFromFile("/nonexistent/fingerprint-rules.jsonl")
	if err == nil {
		t.Fatalf("expected an error")
	}
	var fileErr *fingerprint.RuleFileError
	if !errors.As(err, &fileErr) {
		t.Fatalf("expected a RuleFileError, got %T", err)
	}
	if fileErr.Path != "/nonexistent/fingerprint-rules.jsonl" {
		t.Fatalf("the error must carry the path, got %q", fileErr.Path)
	}
}

// A file with many errors returns a bounded aggregate, each tagged with
// file:line.
func TestLoadRulesAggregatesErrors(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 30; i++ {
		b.WriteString("{\"id\":\"x\",\"source\":\"body\",\"pattern\":\"(\",\"product\":\"p\",\"confidence\":1}\n")
	}
	_, err := fingerprint.LoadRules(strings.NewReader(b.String()))
	if err == nil {
		t.Fatalf("expected an aggregate error")
	}
	var aggregate *fingerprint.RuleSetError
	if !errors.As(err, &aggregate) {
		t.Fatalf("expected a RuleSetError, got %T", err)
	}
	if len(aggregate.Errors) > 20 {
		t.Fatalf("the aggregate must be bounded, got %d", len(aggregate.Errors))
	}
	if !strings.Contains(err.Error(), "rules:1:") {
		t.Fatalf("an aggregate must keep file:line: %s", err.Error())
	}
}

func TestRuleDigestIsOrderIndependent(t *testing.T) {
	a, err := fingerprint.LoadRules(strings.NewReader(
		"{\"id\":\"a\",\"source\":\"body\",\"pattern\":\"x\",\"product\":\"p\",\"confidence\":1}\n" +
			"{\"id\":\"b\",\"source\":\"title\",\"pattern\":\"y\",\"product\":\"q\",\"confidence\":1}"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	b, err := fingerprint.LoadRules(strings.NewReader(
		"{\"id\":\"b\",\"source\":\"title\",\"pattern\":\"y\",\"product\":\"q\",\"confidence\":1}\n" +
			"{\"id\":\"a\",\"source\":\"body\",\"pattern\":\"x\",\"product\":\"p\",\"confidence\":1}"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if a.RuleDigest() != b.RuleDigest() {
		t.Fatalf("digest depends on file order: %s != %s", a.RuleDigest(), b.RuleDigest())
	}
	if len(a.RuleDigest()) != 64 {
		t.Fatalf("expected a sha256 hex digest, got %q", a.RuleDigest())
	}
}

func TestSourcesAreKnown(t *testing.T) {
	for _, source := range fingerprint.AllSources {
		if _, ok := fingerprint.SourceFromString(source.String()); !ok {
			t.Errorf("source %d does not round-trip", source)
		}
	}
	if _, ok := fingerprint.SourceFromString("cookie"); ok {
		t.Errorf("an unknown source must not parse")
	}
}

func TestConfidenceBounds(t *testing.T) {
	for _, confidence := range []int{0, 1, 50, 100} {
		rules, err := fingerprint.LoadRules(strings.NewReader(
			`{"id":"a","source":"body","pattern":"x","product":"p","confidence":` + itoa(confidence) + `}`))
		if err != nil {
			t.Fatalf("confidence %d should be valid: %v", confidence, err)
		}
		if rules.Stats().Rules != 1 {
			t.Fatalf("confidence %d rule not loaded", confidence)
		}
	}
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
