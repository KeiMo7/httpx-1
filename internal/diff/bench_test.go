package diff

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// makeScaleFixture builds baseline/current JSONL sets of n targets where a
// fixed fraction changes, mirroring a realistic "few changed among many"
// run (requirement 一.5). Roughly 5% change, split across categories.
func makeScaleFixture(n int) (string, string) {
	var base, cur strings.Builder
	changed := n / 20 // 5%
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("https://host%05d.example", i)
		brow := fmt.Sprintf(`{"input":%q,"url":%q,"host":%q,"status_code":200,"title":"T","tech":["nginx"],"a":["1.1.1.1"],"body_preview":"b","hash":{"body_md5":"x","header_md5":"y"},"failed":false}`, id, id, id)
		base.WriteString(brow + "\n")
		if i < changed {
			switch i % 4 {
			case 0:
				cur.WriteString(strings.Replace(brow, `"status_code":200`, `"status_code":503`, 1) + "\n")
			case 1:
				cur.WriteString(strings.Replace(brow, `"body_md5":"x"`, `"body_md5":"z"`, 1) + "\n")
			case 2:
				cur.WriteString(strings.Replace(brow, `"a":["1.1.1.1"]`, `"a":["9.9.9.9"]`, 1) + "\n")
			default:
				cur.WriteString(strings.Replace(brow, `"failed":false`, `"failed":true`, 1) + "\n")
			}
		} else {
			cur.WriteString(brow + "\n")
		}
	}
	return base.String(), cur.String()
}

func BenchmarkCompare10k(b *testing.B) {
	baseline, current := makeScaleFixture(10000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		_, _, err := Compare(strings.NewReader(baseline), strings.NewReader(current), &out, nil, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompare100k demonstrates the streaming design stays linear rather
// than buffering both files.
func BenchmarkCompare100k(b *testing.B) {
	baseline, current := makeScaleFixture(100000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var out bytes.Buffer
		_, _, err := Compare(strings.NewReader(baseline), strings.NewReader(current), &out, nil, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
