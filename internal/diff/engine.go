package diff

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// IdentityFields are, in priority order, the JSON keys used to identify the
// same target across runs. None of them contain probe time, duration or body
// hashes (hard constraint 一.1 / 二.1).
var IdentityFields = []string{"input", "url", "host"}

// FieldChange describes one changed compared field.
type FieldChange struct {
	Field    string          `json:"field"`
	Category ChangeCategory  `json:"category"`
	Before   json.RawMessage `json:"before"`
	After    json.RawMessage `json:"after"`
}

// Record is the per-target diff result. Only targets with at least one
// change are emitted; unchanged targets produce no record (requirement 一.5).
type Record struct {
	// Identity is the stable cross-run key of the target.
	Identity string `json:"identity"`
	// IdentityField records which JSON key supplied the identity.
	IdentityField string `json:"identity_field"`
	// Categories is the sorted, deduplicated set of change categories.
	Categories []ChangeCategory `json:"categories"`
	// Presence reports availability/presence transitions.
	Presence string `json:"presence"`
	// Changes enumerates every changed field that belongs to the contract.
	Changes []FieldChange `json:"changes"`
}

// Presence transition values.
const (
	// PresenceBoth: target present in both runs but flipped failed<->ok.
	PresenceBoth = "both"
	// PresenceBaselineOnly: target vanished in the current run.
	PresenceBaselineOnly = "baseline_only"
	// PresenceCurrentOnly: newly observed target in the current run.
	PresenceCurrentOnly = "current_only"
)

// Stats summarizes a comparison run. Counts are category counters; a target
// with changes in several categories increments each of them.
type Stats struct {
	BaselineEntries  int `json:"baseline_entries"`
	CurrentEntries   int `json:"current_entries"`
	MatchedIdentites int `json:"matched_identities"`
	Unchanged        int `json:"unchanged"`
	ChangedTargets   int `json:"changed_targets"`
	// ByCategory counts changed targets per category.
	ByCategory map[ChangeCategory]int `json:"by_category"`
	// BaselineOnly / CurrentOnly track presence differences.
	BaselineOnly int `json:"baseline_only"`
	CurrentOnly  int `json:"current_only"`
	// DuplicateIdentities counts keys seen more than once in the same file.
	DuplicateIdentities int `json:"duplicate_identities"`
}

// entry is one decoded JSONL line kept only as raw messages: the engine never
// unmarshals into runner.Result, so it stays decoupled from the probe package
// and tolerates fields added or removed between httpx versions.
type entry struct {
	identity      string
	identityField string
	raw           map[string]json.RawMessage
}

// DecodeLine decodes one JSONL line into a raw entry and resolves its stable
// identity. A line with no usable identity field is reported as an error so
// the caller can name the offending line instead of silently merging rows.
func DecodeLine(line []byte, lineNo int) (entry, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return entry{}, fmt.Errorf("line %d: invalid JSON object: %w", lineNo, err)
	}
	id, field, err := resolveIdentity(raw)
	if err != nil {
		return entry{}, fmt.Errorf("line %d: %w", lineNo, err)
	}
	return entry{identity: id, identityField: field, raw: raw}, nil
}

func resolveIdentity(raw map[string]json.RawMessage) (string, string, error) {
	for _, key := range IdentityFields {
		v, ok := raw[key]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil || s == "" {
			continue
		}
		return s, key, nil
	}
	return "", "", fmt.Errorf("no identity field (%v) with a non-empty string value", IdentityFields)
}

// canonicalize renders a raw JSON value into a deterministic byte form so
// that two semantically equal values (e.g. reordered object keys) compare
// equal. A missing/nil value and an explicit JSON null are both rendered as
// "null".
func canonicalize(v json.RawMessage) (string, error) {
	if len(v) == 0 {
		return "null", nil
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, bytes.TrimSpace(v)); err != nil {
		return "", err
	}
	// json.Compact preserves key order inside objects; decode into `any` and
	// re-marshal through encoding/json, which sorts map keys, to make object
	// key order irrelevant.
	var decoded any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	dec.UseNumber() // keep integer precision instead of float64
	if err := dec.Decode(&decoded); err != nil {
		return "", err
	}
	out, err := json.Marshal(decoded)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// comparePair compares two entries sharing an identity and returns the
// resulting record, or nil when the observations are identical across every
// contracted field.
func comparePair(baseline, current entry) (*Record, error) {
	changes := make([]FieldChange, 0)
	catSet := map[ChangeCategory]struct{}{}

	// Union of contracted field names present in either observation, iterated
	// in the fixed contract order so field-level output is deterministic.
	for _, spec := range CompareFieldSpecs {
		bv, bOK := baseline.raw[spec.JSONName]
		cv, cOK := current.raw[spec.JSONName]
		if !bOK && !cOK {
			continue
		}
		bCanon, err := canonicalize(bv)
		if err != nil {
			return nil, fmt.Errorf("identity %q field %q baseline: %w", baseline.identity, spec.JSONName, err)
		}
		cCanon, err := canonicalize(cv)
		if err != nil {
			return nil, fmt.Errorf("identity %q field %q current: %w", current.identity, spec.JSONName, err)
		}
		if bCanon == cCanon {
			continue
		}
		changes = append(changes, FieldChange{
			Field:    spec.JSONName,
			Category: spec.Category,
			Before:   normalizeRaw(bv),
			After:    normalizeRaw(cv),
		})
		catSet[spec.Category] = struct{}{}
	}

	// "hash" is compared per subkey so body and header digest changes stay in
	// separate categories (see SpecialCompareFields).
	hashChanges := compareHashField(baseline, current)
	changes = append(changes, hashChanges...)
	for _, hc := range hashChanges {
		catSet[hc.Category] = struct{}{}
	}

	presence := PresenceBoth
	availabilityFlip := availabilityChanged(baseline.raw, current.raw)

	if len(changes) == 0 && !availabilityFlip {
		return nil, nil
	}

	categories := make([]ChangeCategory, 0, len(catSet))
	for c := range catSet {
		categories = append(categories, c)
	}
	sortChanges(categories)

	// An availability flip always carries the availability category, even if
	// the "failed" field itself was missing from one side.
	if availabilityFlip {
		if _, ok := catSet[CategoryAvailability]; !ok {
			categories = append(categories, CategoryAvailability)
			sortChanges(categories)
		}
	}

	return &Record{
		Identity:      current.identity,
		IdentityField: current.identityField,
		Categories:    categories,
		Presence:      presence,
		Changes:       changes,
	}, nil
}

func sortChanges(cats []ChangeCategory) {
	order := make(map[ChangeCategory]int, len(AllCategories))
	for i, c := range AllCategories {
		order[c] = i
	}
	sort.Slice(cats, func(i, j int) bool { return order[cats[i]] < order[cats[j]] })
}

// availabilityChanged reports whether one side failed while the other
// succeeded. A missing "failed" key is treated as false (the probe
// succeeded) because httpx only sets it on failure.
func availabilityChanged(b, c map[string]json.RawMessage) bool {
	return failedFlag(b) != failedFlag(c)
}

func failedFlag(raw map[string]json.RawMessage) bool {
	v, ok := raw["failed"]
	if !ok {
		return false
	}
	var f bool
	if err := json.Unmarshal(v, &f); err != nil {
		return false
	}
	return f
}

func normalizeRaw(v json.RawMessage) json.RawMessage {
	if len(v) == 0 {
		return json.RawMessage("null")
	}
	return v
}

// compareHashField diffs the "hash" object subkey by subkey. Each subkey is
// named body_<algo> or header_<algo>; the prefix selects the category so that
// a changed header digest is reported as CategoryHeader, never CategoryBody.
// Output subkeys are sorted for determinism.
func compareHashField(baseline, current entry) []FieldChange {
	var bMap, cMap map[string]json.RawMessage
	if v, ok := baseline.raw["hash"]; ok {
		_ = json.Unmarshal(v, &bMap)
	}
	if v, ok := current.raw["hash"]; ok {
		_ = json.Unmarshal(v, &cMap)
	}
	if len(bMap) == 0 && len(cMap) == 0 {
		return nil
	}
	keys := map[string]struct{}{}
	for k := range bMap {
		keys[k] = struct{}{}
	}
	for k := range cMap {
		keys[k] = struct{}{}
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	var out []FieldChange
	for _, k := range sorted {
		bv := bMap[k]
		cv := cMap[k]
		bCanon, _ := canonicalize(bv)
		cCanon, _ := canonicalize(cv)
		if bCanon == cCanon {
			continue
		}
		category := hashSubkeyCategory(k)
		out = append(out, FieldChange{
			Field:    "hash." + k,
			Category: category,
			Before:   normalizeRaw(bv),
			After:    normalizeRaw(cv),
		})
	}
	return out
}

// hashSubkeyCategory resolves the category of a "hash" subkey from its
// body_/header_ prefix. An unrecognized prefix falls back to CategoryField
// rather than silently being dropped.
func hashSubkeyCategory(subkey string) ChangeCategory {
	for prefix, cat := range HashSubkeyCategory {
		if strings.HasPrefix(subkey, prefix) {
			return cat
		}
	}
	return CategoryField
}

// presenceRecord builds a record for a target observed on only one side.
// Such targets are always an availability change (requirement 异常.1 and
// 一.2): they are reported explicitly, never silently treated as "all new".
func presenceRecord(e entry, presence string) *Record {
	var change FieldChange
	if presence == PresenceBaselineOnly {
		change = FieldChange{
			Field:    "presence",
			Category: CategoryAvailability,
			Before:   json.RawMessage(`"present"`),
			After:    json.RawMessage(`"absent"`),
		}
	} else {
		change = FieldChange{
			Field:    "presence",
			Category: CategoryAvailability,
			Before:   json.RawMessage(`"absent"`),
			After:    json.RawMessage(`"present"`),
		}
	}
	return &Record{
		Identity:      e.identity,
		IdentityField: e.identityField,
		Categories:    []ChangeCategory{CategoryAvailability},
		Presence:      presence,
		Changes:       []FieldChange{change},
	}
}

// readEntries streams a JSONL file into a map keyed by stable identity. This
// is the one bounded-memory step: with ~10k targets the retained state is one
// small raw-message map per target rather than decoded Result structs.
func readEntries(r io.Reader) (map[string]entry, *Stats, error) {
	out := map[string]entry{}
	stats := &Stats{ByCategory: map[ChangeCategory]int{}}
	scanner := bufio.NewScanner(r)
	// Allow large lines (screenshots/body fields can be sizeable); 4 MiB per
	// line, grown on demand by the scanner itself.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		e, err := DecodeLine(line, lineNo)
		if err != nil {
			return nil, nil, err
		}
		if _, dup := out[e.identity]; dup {
			stats.DuplicateIdentities++
		}
		out[e.identity] = e
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("reading JSONL stream: %w", err)
	}
	return out, stats, nil
}
