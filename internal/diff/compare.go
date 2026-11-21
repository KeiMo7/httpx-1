package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// ScanMetadata captures the probe parameters that define the semantics of a
// result file. It is written as a sidecar by httpx when -scan-meta is set
// and consumed here to detect when the two files were produced with
// incompatible parameters (requirement 异常.2).
type ScanMetadata struct {
	FollowRedirects     bool   `json:"follow_redirects"`
	FollowHostRedirects bool   `json:"follow_host_redirects"`
	MaxRedirects        int    `json:"max_redirects"`
	JSONOutput          bool   `json:"json_output"`
	IncludeChain        bool   `json:"include_chain"`
	Tool                string `json:"tool"`
	SchemaVersion       int    `json:"schema_version"`
}

// CurrentSchemaVersion is bumped whenever the on-disk metadata layout changes.
const CurrentSchemaVersion = 1

// MetadataInconsistency describes a semantic mismatch between the parameters
// of the two runs being compared.
type MetadataInconsistency struct {
	Field       string `json:"field"`
	Baseline    any    `json:"baseline"`
	Current     any    `json:"current"`
	Explanation string `json:"explanation"`
}

// CheckMetadata compares two optional metadata documents. Missing documents
// (nil) are not an error: older result files simply predate the sidecar. A
// mismatch between two present documents is returned so the caller can warn.
func CheckMetadata(baseline, current *ScanMetadata) []MetadataInconsistency {
	if baseline == nil || current == nil {
		return nil
	}
	var out []MetadataInconsistency
	add := func(field string, b, c any, explanation string) {
		if fmt.Sprint(b) != fmt.Sprint(c) {
			out = append(out, MetadataInconsistency{
				Field: field, Baseline: b, Current: c, Explanation: explanation,
			})
		}
	}
	add("follow_redirects", baseline.FollowRedirects, current.FollowRedirects,
		"redirect chains were recorded with different -follow-redirects settings; chain/category differences may be an artifact of the probe parameters")
	add("follow_host_redirects", baseline.FollowHostRedirects, current.FollowHostRedirects,
		"redirect following scope (-follow-host-redirects) differs")
	add("max_redirects", baseline.MaxRedirects, current.MaxRedirects,
		"maximum redirect depth (-max-redirects) differs; hop counts are not comparable")
	add("include_chain", baseline.IncludeChain, current.IncludeChain,
		"one run omitted redirect chains from JSON output (-include-chain); chain comparison is incomplete")
	return out
}

// Compare streams a baseline JSONL reader and a current JSONL reader and
// writes one JSON record per changed target to w, followed by a final summary
// object. The baseline is held in an identity-indexed map (bounded memory);
// the current side is read line by line and never buffered wholesale, which
// keeps the working set proportional to the baseline size even for tens of
// thousands of targets (hard constraint 二.5).
//
// Output ordering is independent of input ordering: records are sorted by
// identity before writing, so running the same comparison twice yields
// byte-identical output (hard constraint 二.3).
func Compare(baseline, current io.Reader, w io.Writer, baselineMeta, currentMeta *ScanMetadata) (*Stats, []MetadataInconsistency, error) {
	baselineEntries, baseStats, err := readEntries(baseline)
	if err != nil {
		return nil, nil, fmt.Errorf("baseline: %w", err)
	}
	stats := &Stats{
		BaselineEntries:     len(baselineEntries),
		DuplicateIdentities: baseStats.DuplicateIdentities,
		ByCategory:          map[ChangeCategory]int{},
	}
	for _, c := range AllCategories {
		stats.ByCategory[c] = 0
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	records := make([]*Record, 0)
	seen := make(map[string]struct{}, len(baselineEntries))

	// Current side is streamed line by line: its entries are never retained
	// beyond the comparison of that single line, so peak memory tracks the
	// baseline map plus one output record per changed target, not the sum of
	// both files.
	scanner := newJSONLScanner(current)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Bytes()
		if len(bytesTrimSpace(line)) == 0 {
			continue
		}
		cur, err := DecodeLine(line, lineNo)
		if err != nil {
			return nil, nil, fmt.Errorf("current: %w", err)
		}
		stats.CurrentEntries++
		if _, dup := seen[cur.identity]; dup {
			stats.DuplicateIdentities++
		}
		seen[cur.identity] = struct{}{}
		base, ok := baselineEntries[cur.identity]
		if !ok {
			records = append(records, presenceRecord(cur, PresenceCurrentOnly))
			stats.CurrentOnly++
			continue
		}
		stats.MatchedIdentites++
		rec, err := comparePair(base, cur)
		if err != nil {
			return nil, nil, err
		}
		if rec == nil {
			stats.Unchanged++
			continue
		}
		annotateRedirectHopDetail(base, cur, rec)
		records = append(records, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("current: reading JSONL stream: %w", err)
	}

	// Baseline-only targets, also in deterministic order.
	baseIDs := make([]string, 0, len(baselineEntries))
	for id := range baselineEntries {
		baseIDs = append(baseIDs, id)
	}
	sort.Strings(baseIDs)
	for _, id := range baseIDs {
		if _, ok := seen[id]; ok {
			continue
		}
		records = append(records, presenceRecord(baselineEntries[id], PresenceBaselineOnly))
		stats.BaselineOnly++
	}

	// Finalize stats and emit.
	for _, rec := range records {
		stats.ChangedTargets++
		for _, c := range rec.Categories {
			stats.ByCategory[c]++
		}
	}
	// Records are already built from sorted iteration, but the two loops above
	// append baseline-only records afterwards: sort once for a global order.
	sort.Slice(records, func(i, j int) bool { return records[i].Identity < records[j].Identity })

	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return nil, nil, fmt.Errorf("writing diff record: %w", err)
		}
	}

	inconsistencies := CheckMetadata(baselineMeta, currentMeta)
	summary := summaryEnvelope{
		Type:             "diff_summary",
		Stats:            stats,
		MetadataWarnings: inconsistencies,
	}
	if err := enc.Encode(summary); err != nil {
		return nil, nil, fmt.Errorf("writing diff summary: %w", err)
	}
	return stats, inconsistencies, nil
}

type summaryEnvelope struct {
	Type             string                  `json:"type"`
	Stats            *Stats                  `json:"stats"`
	MetadataWarnings []MetadataInconsistency `json:"metadata_warnings,omitempty"`
}
