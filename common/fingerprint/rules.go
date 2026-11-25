package fingerprint

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
)

// maxLoadErrors is the maximum number of rule errors LoadRules collects before
// it stops reading and returns the aggregate. A broken rule file is reported
// as a whole rather than line by line, but never as an unbounded list.
const maxLoadErrors = 20

// Rule is one JSONL fingerprint rule.
type Rule struct {
	ID         string `json:"id"`
	Source     string `json:"source"`
	Pattern    string `json:"pattern"`
	Product    string `json:"product"`
	Vendor     string `json:"vendor,omitempty"`
	Version    string `json:"version,omitempty"`
	Confidence int    `json:"confidence"`

	compiled *regexp.Regexp
	source   Source
}

// Compiled exposes the compiled pattern of a loaded rule.
func (r Rule) Compiled() *regexp.Regexp { return r.compiled }

// SourceValue exposes the parsed source of a loaded rule.
func (r Rule) SourceValue() Source { return r.source }

// RuleSetError aggregates every problem found while loading a rule file. It
// implements Unwrap() []error so errors.Is and errors.As can inspect the
// individual failures.
type RuleSetError struct {
	// File is the path reported in each message, or a placeholder such as
	// "rules" when LoadRules was given a reader without a name.
	File   string
	Errors []error
}

func (e *RuleSetError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "failed to load fingerprint rules from %s:", e.File)
	for _, err := range e.Errors {
		b.WriteString("\n  ")
		b.WriteString(err.Error())
	}
	return b.String()
}

// Unwrap returns the individual errors.
func (e *RuleSetError) Unwrap() []error { return e.Errors }

// RuleSet is an immutable, compiled set of rules.
type RuleSet struct {
	rules    []Rule
	bySource map[Source][]Rule
	digest   string
	dropped  int64
	matched  int64
}

// LoadRules reads a JSONL rule file. Every line is one JSON object; empty
// lines are ignored. Errors carry "file:line" and at most maxLoadErrors are
// collected before the aggregated RuleSetError is returned.
func LoadRules(r io.Reader) (*RuleSet, error) {
	name := "rules"
	if named, ok := r.(interface{ Name() string }); ok {
		if n := named.Name(); n != "" {
			name = n
		}
	}
	return loadRules(r, name)
}

func loadRules(r io.Reader, name string) (*RuleSet, error) {
	scanner := bufio.NewScanner(r)
	// Fingerprint rules are small; a modest buffer still accepts long regexes.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	set := &RuleSet{bySource: make(map[Source][]Rule)}
	seen := make(map[string]int)
	var errs []error
	line := 0
	for scanner.Scan() {
		line++
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" {
			continue
		}
		rule, err := parseRule(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s:%d: %w", name, line, err))
			if len(errs) >= maxLoadErrors {
				return nil, &RuleSetError{File: name, Errors: errs}
			}
			continue
		}
		if first, ok := seen[rule.ID]; ok {
			errs = append(errs, fmt.Errorf("%s:%d: duplicate rule id %q (first seen on line %d)", name, line, rule.ID, first))
			if len(errs) >= maxLoadErrors {
				return nil, &RuleSetError{File: name, Errors: errs}
			}
			continue
		}
		seen[rule.ID] = line
		set.rules = append(set.rules, rule)
		set.bySource[rule.source] = append(set.bySource[rule.source], rule)
	}
	if err := scanner.Err(); err != nil {
		errs = append(errs, fmt.Errorf("%s:%d: %w", name, line+1, err))
	}
	if len(errs) > 0 {
		return nil, &RuleSetError{File: name, Errors: errs}
	}

	set.digest = computeRuleDigest(set.rules)
	return set, nil
}

func parseRule(raw string) (Rule, error) {
	var rule Rule
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	if err := dec.Decode(&rule); err != nil {
		return rule, fmt.Errorf("invalid json: %w", err)
	}
	rule.ID = strings.TrimSpace(rule.ID)
	if rule.ID == "" {
		return rule, errors.New("missing required field \"id\"")
	}
	rule.Source = strings.TrimSpace(rule.Source)
	if rule.Source == "" {
		return rule, errors.New("missing required field \"source\"")
	}
	source, ok := SourceFromString(rule.Source)
	if !ok {
		return rule, fmt.Errorf("unknown source %q (expected one of %s)", rule.Source, strings.Join(sourceNamesInOrder(), ", "))
	}
	rule.source = source
	if strings.TrimSpace(rule.Pattern) == "" {
		return rule, errors.New("missing required field \"pattern\"")
	}
	compiled, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return rule, fmt.Errorf("invalid pattern: %w", err)
	}
	rule.compiled = compiled
	if strings.TrimSpace(rule.Product) == "" {
		return rule, errors.New("missing required field \"product\"")
	}
	if rule.Confidence < 0 || rule.Confidence > 100 {
		return rule, fmt.Errorf("confidence %d out of range [0,100]", rule.Confidence)
	}
	rule.Product = cleanName(rule.Product)
	rule.Vendor = cleanName(rule.Vendor)
	rule.Version = strings.TrimSpace(rule.Version)
	return rule, nil
}

func sourceNamesInOrder() []string {
	names := make([]string, 0, len(AllSources))
	for _, s := range AllSources {
		names = append(names, s.String())
	}
	return names
}

// computeRuleDigest hashes the id, source and pattern of every rule, sorted by
// id, joined by tabs and newlines. It is stable across files whose rules are
// written in a different order.
func computeRuleDigest(rules []Rule) string {
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	var b strings.Builder
	for _, rule := range sorted {
		b.WriteString(rule.ID)
		b.WriteByte('\t')
		b.WriteString(rule.Source)
		b.WriteByte('\t')
		b.WriteString(rule.Pattern)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// RuleDigest returns the digest of the loaded rule set.
func (rs *RuleSet) RuleDigest() string { return rs.digest }

// UsesSource reports whether the rule set has at least one rule for source.
func (rs *RuleSet) UsesSource(source Source) bool {
	if rs == nil {
		return false
	}
	return len(rs.bySource[source]) > 0
}

// Stats reports rule accounting. Rules is the number of loaded rules, Dropped
// the number of evidence entries discarded because their normalized product
// was empty, and Matched the total number of evidence entries produced by
// Match calls so far.
func (rs *RuleSet) Stats() RuleStats {
	if rs == nil {
		return RuleStats{}
	}
	return RuleStats{
		Rules:   len(rs.rules),
		Dropped: int(atomicLoad(&rs.dropped)),
		Matched: int(atomicLoad(&rs.matched)),
	}
}

// Match returns every rule that matches the evidence, in rule order. The
// fragment is the first substring of the source evidence matched by the
// pattern.
func (rs *RuleSet) Match(in Input) []Evidence {
	if rs == nil {
		return nil
	}
	evidence, dropped := rs.match(in)
	atomicAdd(&rs.dropped, int64(dropped))
	atomicAdd(&rs.matched, int64(len(evidence)))
	return evidence
}

func (rs *RuleSet) match(in Input) ([]Evidence, int) {
	var evidence []Evidence
	dropped := 0
	for _, rule := range rs.rules {
		value := in.value(rule.source)
		if value == "" {
			continue
		}
		fragment := rule.compiled.FindString(value)
		if fragment == "" {
			continue
		}
		key := normalizeProduct(rule.Product)
		if key == "" {
			dropped++
			continue
		}
		evidence = append(evidence, Evidence{
			RuleID:     rule.ID,
			Source:     rule.source,
			Product:    rule.Product,
			Vendor:     rule.Vendor,
			Version:    rule.Version,
			Confidence: rule.Confidence,
			Fragment:   fragment,
		})
	}
	return evidence, dropped
}

// Fingerprint matches the input and merges the resulting evidence into the
// canonical fingerprint.
func (rs *RuleSet) Fingerprint(in Input) Fingerprint {
	fp := Fingerprint{
		FaviconMMH3: in.FaviconMMH3,
		FaviconMD5:  in.FaviconMD5,
		JARM:        in.JARM,
		CDNName:     in.CDNName,
		RuleDigest:  rs.digest,
	}
	if in.Body != "" {
		fp.BodyHashes = hashMap(in.Body)
	}
	if in.RawHeaders != "" {
		fp.HeaderHashes = hashMap(in.RawHeaders)
	}
	if rs == nil {
		return fp
	}

	evidence, dropped := rs.match(in)
	atomicAdd(&rs.dropped, int64(dropped))
	atomicAdd(&rs.matched, int64(len(evidence)))
	if len(evidence) == 0 {
		return fp
	}

	type group struct {
		productKey        string
		vendorKey         string
		display           string
		vendor            string
		source            Source
		ruleID            string
		confidence        int
		version           string
		versionConfidence int
	}
	groups := make(map[string]*group)
	for _, ev := range evidence {
		productKey := normalizeProduct(ev.Product)
		if productKey == "" {
			continue
		}
		vendorKey := normalizeProduct(ev.Vendor)
		key := vendorKey + "\x00" + productKey
		g, ok := groups[key]
		if !ok {
			groups[key] = &group{
				productKey:        productKey,
				vendorKey:         vendorKey,
				display:           ev.Product,
				vendor:            ev.Vendor,
				source:            ev.Source,
				ruleID:            ev.RuleID,
				confidence:        ev.Confidence,
				version:           ev.Version,
				versionConfidence: ev.Confidence,
			}
			continue
		}
		if betterDisplay(ev.Confidence, ev.Source, ev.RuleID, g.confidence, g.source, g.ruleID) {
			g.display = ev.Product
			g.vendor = ev.Vendor
			g.source = ev.Source
			g.ruleID = ev.RuleID
			g.confidence = ev.Confidence
		}
		if betterVersion(ev.Version, ev.Confidence, g.version, g.versionConfidence) {
			g.version = ev.Version
			g.versionConfidence = ev.Confidence
		}
	}

	// Sort groups by the normalized product key and then the display name so
	// the technology list is independent of evidence order.
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := groups[keys[i]], groups[keys[j]]
		if a.productKey != b.productKey {
			return a.productKey < b.productKey
		}
		if a.display != b.display {
			return a.display < b.display
		}
		return a.vendorKey < b.vendorKey
	})

	techs := make([]string, 0, len(keys))
	cpes := make([]CPE, 0, len(keys))
	for _, key := range keys {
		g := groups[key]
		techs = append(techs, g.display)
		if cpe, ok := buildCPE(g.vendor, g.display, g.version); ok {
			cpes = append(cpes, cpe)
		}
	}
	fp.Technologies = dedupeStrings(techs)
	fp.CPEs = sortCPEs(cpes)
	return fp
}

// betterDisplay reports whether a candidate should replace the current
// representative of a group: highest confidence wins, then the lowest
// (sourceRank, ruleID) pair.
func betterDisplay(candidateConfidence int, candidateSource Source, candidateRule string, confidence int, source Source, ruleID string) bool {
	if candidateConfidence != confidence {
		return candidateConfidence > confidence
	}
	rank, bestRank := rankOf(candidateSource), rankOf(source)
	if rank != bestRank {
		return rank < bestRank
	}
	return candidateRule < ruleID
}

// betterVersion reports whether a candidate version should replace the current
// one: highest confidence wins, then the smallest version in byte order.
func betterVersion(version string, confidence int, current string, currentConfidence int) bool {
	if version == "" {
		return false
	}
	if current == "" {
		return true
	}
	if confidence != currentConfidence {
		return confidence > currentConfidence
	}
	return version < current
}

func buildCPE(vendor, product, version string) (CPE, bool) {
	vendor = strings.TrimSpace(vendor)
	product = strings.TrimSpace(product)
	if vendor == "" || product == "" {
		return CPE{}, false
	}
	cpePart := func(s string) string {
		return strings.ToLower(strings.ReplaceAll(s, " ", "_"))
	}
	version = sanitizeCPEVersion(version)
	return CPE{
		Product: product,
		Vendor:  vendor,
		CPE: fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*",
			cpePart(vendor), cpePart(product), version),
	}, true
}

func sanitizeCPEVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return "*"
	}
	if strings.ContainsAny(version, ":*?") {
		return "*"
	}
	return strings.ReplaceAll(version, " ", "_")
}

func sortCPEs(cpes []CPE) []CPE {
	sort.Slice(cpes, func(i, j int) bool {
		if cpes[i].CPE != cpes[j].CPE {
			return cpes[i].CPE < cpes[j].CPE
		}
		if cpes[i].Product != cpes[j].Product {
			return cpes[i].Product < cpes[j].Product
		}
		return cpes[i].Vendor < cpes[j].Vendor
	})
	return cpes
}

func dedupeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:0]
	for _, s := range in {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

func cleanName(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func atomicLoad(v *int64) int64   { return atomic.LoadInt64(v) }
func atomicAdd(v *int64, n int64) { atomic.AddInt64(v, n) }
