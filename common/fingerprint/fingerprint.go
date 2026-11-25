// Package fingerprint provides a small, deterministic rule based
// fingerprinting engine. It maps the evidence collected from an HTTP response
// (title, headers, body, favicon, JARM, TLS names and CDN) to a set of
// technologies and CPEs, and merges that into a canonical Fingerprint.
//
// The package only depends on the standard library, common/hashes and other
// common packages: it must not import runner or gologger, so it stays usable
// by any caller and testable in isolation.
package fingerprint

import (
	"strings"
)

// Source identifies the probe a rule reads. Its integer value doubles as the
// priority used to break ties when merging: a lower value wins.
type Source uint8

const (
	SourceTitle Source = iota
	SourceHeader
	SourceBody
	SourceFavicon
	SourceJARM
	SourceTLS
	SourceCDN
)

// AllSources lists every source in priority order.
var AllSources = []Source{
	SourceTitle,
	SourceHeader,
	SourceBody,
	SourceFavicon,
	SourceJARM,
	SourceTLS,
	SourceCDN,
}

// sourceNames maps a Source to its JSONL spelling.
var sourceNames = map[Source]string{
	SourceTitle:   "title",
	SourceHeader:  "header",
	SourceBody:    "body",
	SourceFavicon: "favicon",
	SourceJARM:    "jarm",
	SourceTLS:     "tls",
	SourceCDN:     "cdn",
}

// String returns the JSONL spelling of the source.
func (s Source) String() string {
	if name, ok := sourceNames[s]; ok {
		return name
	}
	return ""
}

// sourceRank is the fixed priority order used to break ties between rules
// that match the same technology. It is deliberately a slice: priority is
// positional, not a map lookup that could drift.
var sourceRank = []Source{
	SourceTitle,
	SourceHeader,
	SourceBody,
	SourceFavicon,
	SourceJARM,
	SourceTLS,
	SourceCDN,
}

// SourceFromString parses the JSONL spelling of a source.
func SourceFromString(s string) (Source, bool) {
	for source, name := range sourceNames {
		if name == s {
			return source, true
		}
	}
	return 0, false
}

func rankOf(s Source) int {
	for i, candidate := range sourceRank {
		if candidate == s {
			return i
		}
	}
	return len(sourceRank)
}

// Input is the evidence a rule set is matched against. Every field maps to a
// single Source; a missing probe leaves its field at the zero value.
type Input struct {
	Title       string
	Body        string
	RawHeaders  string
	FaviconMMH3 string
	FaviconMD5  string
	JARM        string
	TLSNames    string
	CDNName     string
}

// value returns the evidence of a source.
func (in Input) value(source Source) string {
	switch source {
	case SourceTitle:
		return in.Title
	case SourceHeader:
		return in.RawHeaders
	case SourceBody:
		return in.Body
	case SourceFavicon:
		return in.FaviconMMH3
	case SourceJARM:
		return in.JARM
	case SourceTLS:
		return in.TLSNames
	case SourceCDN:
		return in.CDNName
	}
	return ""
}

// normalizeProduct trims, collapses inner whitespace and lowercases a product
// name. It is the canonical key used to group evidence.
func normalizeProduct(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// Evidence is one rule match.
type Evidence struct {
	RuleID     string
	Source     Source
	Product    string
	Vendor     string
	Version    string
	Confidence int
	// Fragment is the part of the evidence that matched.
	Fragment string
}

// CPE is a Common Platform Enumeration entry, in 2.3 string form.
type CPE struct {
	Product string `json:"product"`
	Vendor  string `json:"vendor"`
	CPE     string `json:"cpe"`
}

// Fingerprint is the merged, canonical view of a set of evidence.
type Fingerprint struct {
	Technologies []string          `json:"technologies,omitempty"`
	CPEs         []CPE             `json:"cpes,omitempty"`
	FaviconPath  string            `json:"favicon_path,omitempty"`
	FaviconURL   string            `json:"favicon_url,omitempty"`
	FaviconMMH3  string            `json:"favicon_mmh3,omitempty"`
	FaviconMD5   string            `json:"favicon_md5,omitempty"`
	BodyHashes   map[string]string `json:"body_hashes,omitempty"`
	HeaderHashes map[string]string `json:"header_hashes,omitempty"`
	JARM         string            `json:"jarm,omitempty"`
	CDNName      string            `json:"cdn_name,omitempty"`
	RuleDigest   string            `json:"rule_digest,omitempty"`
}

// RuleStats reports the outcome of loading and applying a rule set.
type RuleStats struct {
	Rules   int
	Dropped int
	Matched int
}
