package runner

import (
	"reflect"
	"testing"

	"github.com/projectdiscovery/httpx/internal/diff"
	"github.com/stretchr/testify/require"
)

// TestDiffContractCoversEveryResultJSONField reflects over runner.Result and
// fails if a serialized JSON field is not explicitly covered by the diff
// package's comparison contract. This is the structural guarantee behind
// hard constraint 二.2 (the compared/ignored field list is declared in code
// and cannot silently drift from the Result struct).
func TestDiffContractCoversEveryResultJSONField(t *testing.T) {
	names := map[string]struct{}{}
	collectJSONNames(reflect.TypeOf(Result{}), names)

	compared := map[string]struct{}{}
	for _, spec := range diff.CompareFieldSpecs {
		compared[spec.JSONName] = struct{}{}
	}
	for _, id := range diff.IdentityFields {
		compared[id] = struct{}{}
	}

	for name := range names {
		_, isCompared := compared[name]
		_, isIgnored := diff.IgnoredFields[name]
		_, isSpecial := diff.SpecialCompareFields[name]
		require.Truef(t, isCompared || isIgnored || isSpecial,
			"Result JSON field %q has no diff contract entry (add it to CompareFieldSpecs, SpecialCompareFields or IgnoredFields)", name)
	}

	// Reverse direction: contract entries must reference real fields.
	for _, spec := range diff.CompareFieldSpecs {
		_, ok := names[spec.JSONName]
		require.Truef(t, ok, "diff contract references unknown field %q", spec.JSONName)
	}
	for name := range diff.IgnoredFields {
		_, ok := names[name]
		require.Truef(t, ok, "diff ignore list references unknown field %q", name)
	}
	for name := range diff.SpecialCompareFields {
		_, ok := names[name]
		require.Truef(t, ok, "diff special-field list references unknown field %q", name)
	}
}

func collectJSONNames(rt reflect.Type, out map[string]struct{}) {
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		// Only recurse into anonymous (embedded) structs, whose fields are
		// promoted to the top-level JSON object. Named nested structs (e.g.
		// ASN, TLSData) serialize under their own single top-level key, so
		// their inner json tags are not top-level contract fields.
		if f.Anonymous {
			collectJSONNames(f.Type, out)
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name := tag
		for j := 0; j < len(tag); j++ {
			if tag[j] == ',' {
				name = tag[:j]
				break
			}
		}
		if name == "" || name == "-" {
			continue
		}
		out[name] = struct{}{}
	}
}
