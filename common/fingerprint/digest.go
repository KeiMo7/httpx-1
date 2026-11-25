package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/projectdiscovery/httpx/common/hashes"
)

// digestCanonical is the stable projection of a Fingerprint used by Digest.
// Only the fields listed here participate, and every collection is sorted, so
// the digest only depends on the evidence, never on match order.
type digestCanonical struct {
	Technologies []string          `json:"technologies"`
	CPEs         []string          `json:"cpes"`
	FaviconPath  string            `json:"favicon_path"`
	FaviconURL   string            `json:"favicon_url"`
	FaviconMMH3  string            `json:"favicon_mmh3"`
	FaviconMD5   string            `json:"favicon_md5"`
	BodyHashes   map[string]string `json:"body_hashes,omitempty"`
	HeaderHashes map[string]string `json:"header_hashes,omitempty"`
	JARM         string            `json:"jarm"`
	CDNName      string            `json:"cdn_name"`
	RuleDigest   string            `json:"rule_digest"`
}

// Digest returns a sha256 over the canonical JSON encoding of the
// fingerprint. Strings and slices are sorted so the digest only depends on
// the evidence, not on the order it was matched in.
func (f Fingerprint) Digest() string {
	cpes := make([]string, len(f.CPEs))
	for i, cpe := range f.CPEs {
		cpes[i] = cpe.CPE + "\t" + cpe.Product + "\t" + cpe.Vendor
	}
	sort.Strings(cpes)
	canonical := digestCanonical{
		Technologies: dedupeSorted(f.Technologies),
		CPEs:         cpes,
		FaviconPath:  f.FaviconPath,
		FaviconURL:   f.FaviconURL,
		FaviconMMH3:  f.FaviconMMH3,
		FaviconMD5:   f.FaviconMD5,
		BodyHashes:   copyStringMap(f.BodyHashes),
		HeaderHashes: copyStringMap(f.HeaderHashes),
		JARM:         f.JARM,
		CDNName:      f.CDNName,
		RuleDigest:   f.RuleDigest,
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		// The canonical struct only holds strings and maps of strings, which
		// encoding/json always marshals; keep a deterministic fallback anyway.
		data = []byte(fmt.Sprintf("%v", canonical))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// dedupeSorted returns a sorted, duplicate-free copy of in. It never mutates
// the input, so concurrent Digest calls are safe.
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	deduped := out[:0]
	for _, s := range out {
		if len(deduped) == 0 || deduped[len(deduped)-1] != s {
			deduped = append(deduped, s)
		}
	}
	return deduped
}

// copyStringMap returns a copy of m. encoding/json sorts map keys itself; the
// copy keeps the digest independent from concurrent map mutation.
func copyStringMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func hashMD5(data string) string    { return hashes.Md5([]byte(data)) }
func hashMMH3(data string) string   { return hashes.Mmh3([]byte(data)) }
func hashSHA1(data string) string   { return hashes.Sha1([]byte(data)) }
func hashSHA256(data string) string { return hashes.Sha256([]byte(data)) }
func hashSHA512(data string) string { return hashes.Sha512([]byte(data)) }
func hashSimhash(data string) string {
	return hashes.Simhash([]byte(data))
}

// hashMap computes the fixed set of body/header hashes. Keys are the algorithm
// names and are stable.
func hashMap(data string) map[string]string {
	return map[string]string{
		"md5":     hashMD5(data),
		"mmh3":    hashMMH3(data),
		"sha1":    hashSHA1(data),
		"sha256":  hashSHA256(data),
		"sha512":  hashSHA512(data),
		"simhash": hashSimhash(data),
	}
}
