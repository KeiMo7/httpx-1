package diff

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
)

// newJSONLScanner returns a scanner sized for large JSONL lines (body/hash
// payloads can be sizeable), capping a single line at 4 MiB.
func newJSONLScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	return s
}

func bytesTrimSpace(b []byte) []byte {
	return bytes.TrimSpace(b)
}

// redirectHop is the hop-level projection of one entry in the httpx
// "chain" array. Only the structural fields of a hop participate; the raw
// request/response text is intentionally ignored because it embeds headers.
type redirectHop struct {
	StatusCode int    `json:"status_code"`
	Location   string `json:"location"`
	RequestURL string `json:"request-url"`
}

// annotateRedirectHopDetail adds a hop-by-hop explanation to a record that
// already carries a "redirect" category change. Requirement 一.8 asks for
// comparison by hop count, not only by the final landing point.
func annotateRedirectHopDetail(baseline, current entry, rec *Record) {
	if !hasCategory(rec, CategoryRedirect) {
		return
	}
	bHops := decodeHops(baseline.raw["chain"])
	cHops := decodeHops(current.raw["chain"])
	detail := FieldChange{
		Field:    "chain_hop_detail",
		Category: CategoryRedirect,
	}
	switch {
	case len(bHops) != len(cHops):
		detail.Before = mustJSON(map[string]any{"hop_count": len(bHops)})
		detail.After = mustJSON(map[string]any{"hop_count": len(cHops)})
	default:
		diffs := []map[string]any{}
		for i := 0; i < len(bHops) && i < len(cHops); i++ {
			if canonical(bHops[i]) == canonical(cHops[i]) {
				continue
			}
			diffs = append(diffs, map[string]any{
				"hop":    i,
				"before": bHops[i],
				"after":  cHops[i],
			})
		}
		if len(diffs) == 0 {
			// Chain array identical but another redirect field (e.g.
			// final_url/scheme/location) changed: nothing hop-specific to add.
			return
		}
		detail.Before = mustJSON(map[string]any{"hops": bHops})
		detail.After = mustJSON(map[string]any{"hops": cHops})
	}
	rec.Changes = append(rec.Changes, detail)
}

func hasCategory(rec *Record, c ChangeCategory) bool {
	for _, got := range rec.Categories {
		if got == c {
			return true
		}
	}
	return false
}

func decodeHops(raw json.RawMessage) []redirectHop {
	if len(raw) == 0 {
		return nil
	}
	var hops []redirectHop
	if err := json.Unmarshal(raw, &hops); err != nil {
		return nil
	}
	return hops
}

func canonical(v any) string {
	out, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(out)
}

func mustJSON(v any) json.RawMessage {
	out, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return out
}
