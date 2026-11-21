package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// baseResult is a minimal but realistic httpx JSONL row. Tests clone and
// mutate it rather than hand-writing every line.
const baseResult = `{
  "timestamp": "2026-11-20T10:00:00Z",
  "input": "https://example.com",
  "url": "https://example.com",
  "host": "example.com",
  "scheme": "https",
  "status_code": 200,
  "title": "Example Domain",
  "webserver": "nginx/1.25",
  "content_type": "text/html",
  "tech": ["nginx", "React"],
  "body_preview": "hello world",
  "hash": {"body_md5": "aaa", "header_md5": "hhh"},
  "header": {"Server": ["nginx/1.25"]},
  "raw_header": "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n",
  "a": ["1.2.3.4"],
  "chain_status_codes": [200],
  "chain": [{"status_code": 200, "request-url": "https://example.com"}],
  "tls": {"serial": "111", "subject_cn": "example.com", "fingerprint_hash": {"sha256": "fp1"}},
  "time": "120ms",
  "failed": false
}`

func runCompare(t *testing.T, baseline, current string) (string, *Stats) {
	t.Helper()
	var out bytes.Buffer
	stats, warnings, err := Compare(strings.NewReader(baseline), strings.NewReader(current), &out, nil, nil)
	require.NoError(t, err)
	require.Empty(t, warnings)
	return out.String(), stats
}

// jsonl compacts pretty-printed JSON objects into one-object-per-line JSONL,
// matching the real on-disk format produced by `httpx -json`.
func jsonl(objs ...string) string {
	var b strings.Builder
	for _, o := range objs {
		var buf bytes.Buffer
		if err := json.Compact(&buf, []byte(o)); err != nil {
			panic(err)
		}
		b.Write(buf.Bytes())
		b.WriteByte('\n')
	}
	return b.String()
}

// 验收 1a: 完全一致 — 只有 summary，没有任何 diff 记录。
func TestCompareIdentical(t *testing.T) {
	out, stats := runCompare(t, jsonl(baseResult), jsonl(baseResult))
	lines := nonEmptyLines(out)
	require.Len(t, lines, 1, "identical inputs produce only the summary line")
	require.True(t, strings.HasPrefix(lines[0], `{"type":"diff_summary"`))
	require.Equal(t, 1, stats.Unchanged)
	require.Equal(t, 0, stats.ChangedTargets)
}

// 验收 1b: 字段变化（状态码/标题/技术栈）归入 field 类别。
func TestCompareFieldChange(t *testing.T) {
	// Build the mutated row in compact form so anchors are independent of
	// pretty-printing whitespace. Use sequential Replace calls (a single
	// NewReplacer scans non-overlapping, so one pair can starve the next).
	current := jsonl(baseResult)
	current = strings.Replace(current, `"title":"Example Domain"`, `"title":"Example Domain (maintenance)"`, 1)
	current = strings.Replace(current,
		`"status_code":200,"title":"Example Domain (maintenance)"`,
		`"status_code":503,"title":"Example Domain (maintenance)"`, 1)
	current = strings.Replace(current, `"tech":["nginx","React"]`, `"tech":["nginx","Vue"]`, 1)
	current = strings.TrimSuffix(current, "\n")

	out, stats := runCompare(t, jsonl(baseResult), current+"\n")
	lines := nonEmptyLines(out)
	require.Len(t, lines, 2)

	rec := decodeRecord(t, lines[0])
	require.Equal(t, "https://example.com", rec.Identity)
	require.ElementsMatch(t, []ChangeCategory{CategoryField}, rec.Categories)
	fields := changedFieldNames(rec)
	require.ElementsMatch(t, []string{"status_code", "title", "tech"}, fields)
	require.Equal(t, 1, stats.ByCategory[CategoryField])
	require.Equal(t, 0, stats.ByCategory[CategoryBody])
}

// 验收 1c: 可用性反转 — ok -> failed 是 availability 类别，而不是 field。
func TestCompareAvailabilityFlip(t *testing.T) {
	// Only flip the failed flag; every other compared field stays identical,
	// so the single resulting category must be availability.
	current := strings.NewReplacer(
		`"failed": false`, `"failed": true`,
	).Replace(baseResult)

	out, stats := runCompare(t, jsonl(baseResult), jsonl(current))
	lines := nonEmptyLines(out)
	require.Len(t, lines, 2)

	rec := decodeRecord(t, lines[0])
	require.ElementsMatch(t, []ChangeCategory{CategoryAvailability}, rec.Categories)
	require.Equal(t, PresenceBoth, rec.Presence)
	require.Equal(t, 1, stats.ByCategory[CategoryAvailability])
}

// 验收 1d / 一.8: 重定向链路变化，按跳数比较 — 新增一个跳转层级。
func TestCompareRedirectChainHopCount(t *testing.T) {
	current := strings.NewReplacer(
		`"chain_status_codes": [200]`, `"chain_status_codes": [301, 200]`,
		`"chain": [{"status_code": 200, "request-url": "https://example.com"}]`,
		`"chain": [{"status_code": 301, "location": "/new", "request-url": "https://example.com"},{"status_code": 200, "request-url": "https://example.com/new"}]`,
	).Replace(baseResult)

	out, stats := runCompare(t, jsonl(baseResult), jsonl(current))
	lines := nonEmptyLines(out)
	require.Len(t, lines, 2)

	rec := decodeRecord(t, lines[0])
	require.Contains(t, rec.Categories, CategoryRedirect)
	require.Equal(t, 1, stats.ByCategory[CategoryRedirect])

	// Hop detail must explicitly report the hop-count delta, not just a
	// generic "chain differs".
	var hopDetail *FieldChange
	for i := range rec.Changes {
		if rec.Changes[i].Field == "chain_hop_detail" {
			hopDetail = &rec.Changes[i]
		}
	}
	require.NotNil(t, hopDetail)
	require.Contains(t, string(hopDetail.Before), `"hop_count":1`)
	require.Contains(t, string(hopDetail.After), `"hop_count":2`)
}

// 验收 2: 响应体摘要变化与响应头变化必须分到不同类别。
func TestBodyAndHeaderChangesAreDifferentCategories(t *testing.T) {
	// Body only: body hash + preview change, headers stay byte-identical.
	bodyChanged := strings.NewReplacer(
		`"body_md5": "aaa"`, `"body_md5": "bbb"`,
		`"body_preview": "hello world"`, `"body_preview": "hello brave new world"`,
	).Replace(baseResult)
	out, stats := runCompare(t, jsonl(baseResult), jsonl(bodyChanged))
	rec := decodeRecord(t, nonEmptyLines(out)[0])
	require.Contains(t, rec.Categories, CategoryBody)
	require.NotContains(t, rec.Categories, CategoryHeader)
	require.GreaterOrEqual(t, stats.ByCategory[CategoryBody], 1)
	require.Equal(t, 0, stats.ByCategory[CategoryHeader])

	// Header only: raw header + header map change, body stays identical.
	headerChanged := strings.NewReplacer(
		`"header_md5": "hhh"`, `"header_md5": "hhh2"`,
		`"Server": ["nginx/1.25"]`, `"Server": ["nginx/1.26"]`,
		`Server: nginx/1.25`, `Server: nginx/1.26`,
	).Replace(baseResult)
	out, stats = runCompare(t, jsonl(baseResult), jsonl(headerChanged))
	rec = decodeRecord(t, nonEmptyLines(out)[0])
	require.Contains(t, rec.Categories, CategoryHeader)
	require.NotContains(t, rec.Categories, CategoryBody)
	require.GreaterOrEqual(t, stats.ByCategory[CategoryHeader], 1)
	require.Equal(t, 0, stats.ByCategory[CategoryBody])
}

// 一.6: 地址（DNS 来源）变化归 source，不算内容变化。
func TestSourceChangeIsSeparateCategory(t *testing.T) {
	current := strings.NewReplacer(
		`"a": ["1.2.3.4"]`, `"a": ["9.9.9.9"]`,
	).Replace(baseResult)
	out, _ := runCompare(t, jsonl(baseResult), jsonl(current))
	rec := decodeRecord(t, nonEmptyLines(out)[0])
	require.ElementsMatch(t, []ChangeCategory{CategorySource}, rec.Categories)
}

// 一.7: 证书更换但页面没变 — certificate 类别，不触发 body/field。
func TestCertificateChangeIsSeparateCategory(t *testing.T) {
	current := strings.NewReplacer(
		`"serial": "111"`, `"serial": "222"`,
		`"fp1"`, `"fp2"`,
	).Replace(baseResult)
	out, stats := runCompare(t, jsonl(baseResult), jsonl(current))
	rec := decodeRecord(t, nonEmptyLines(out)[0])
	require.ElementsMatch(t, []ChangeCategory{CategoryCertificate}, rec.Categories)
	require.Equal(t, 1, stats.ByCategory[CategoryCertificate])
	require.Equal(t, 0, stats.ByCategory[CategoryBody])
}

// 异常 1: 只在一侧出现的目标必须显式报告为 availability，不静默当新增。
func TestPresenceDifferences(t *testing.T) {
	extra := strings.Replace(baseResult, "example.com", "extra.example.com", -1)
	out, stats := runCompare(t, jsonl(baseResult), jsonl(baseResult, extra))
	recs := nonEmptyLines(out)
	require.Len(t, recs, 2) // one current-only record + summary
	rec := decodeRecord(t, recs[0])
	require.Equal(t, PresenceCurrentOnly, rec.Presence)
	require.Equal(t, "availability", string(rec.Categories[0]))
	require.Equal(t, 1, stats.CurrentOnly)

	// And the reverse direction.
	out, stats = runCompare(t, jsonl(baseResult, extra), jsonl(baseResult))
	recs = nonEmptyLines(out)
	require.Len(t, recs, 2)
	rec = decodeRecord(t, recs[0])
	require.Equal(t, PresenceBaselineOnly, rec.Presence)
	require.Equal(t, 1, stats.BaselineOnly)
}

// 验收 3 / 硬约束 二.3: 同样的两份输入比对两次，输出逐字节一致。
func TestDeterministicByteIdenticalOutput(t *testing.T) {
	// Deliberately shuffle input order and object key order on the current side.
	currentUnordered := jsonl(
		`{
  "failed": false,
  "url": "https://b.example", "input": "https://b.example", "host": "b.example",
  "status_code": 200, "title": "B"
}`,
		`{
  "input": "https://a.example", "url": "https://a.example", "host": "a.example",
  "title": "A changed", "status_code": 200, "failed": false
}`)
	baseline := `{"input":"https://a.example","url":"https://a.example","host":"a.example","status_code":200,"title":"A","failed":false}` + "\n" +
		`{"input":"https://b.example","url":"https://b.example","host":"b.example","status_code":200,"title":"B","failed":false}` + "\n"

	first, _ := runCompare(t, baseline, currentUnordered)
	second, _ := runCompare(t, baseline, currentUnordered)
	require.Equal(t, first, second, "repeated comparison must be byte-identical")

	// Records must be ordered by identity regardless of input order. The
	// trailing line is the diff summary envelope, not a change record.
	lines := nonSummaryLines(first)
	require.Len(t, lines, 1, "only the changed target (a) should be a change record")
	rec := decodeRecord(t, lines[0])
	require.Equal(t, "https://a.example", rec.Identity)
}

// 一.5: 一大批目标里只有少数变化 — 输出只包含变化的目标。
func TestOnlyChangedTargetsAreEmitted(t *testing.T) {
	var baseline, current strings.Builder
	for i := 0; i < 50; i++ {
		row := strings.Replace(baseResult, "example.com", host(i), 1)
		baseline.WriteString(jsonl(row))
		current.WriteString(jsonl(row))
	}
	// Mutate exactly two distinct current rows by editing the compact lines
	// directly, each with a unique anchor (its unique host name).
	lines := strings.Split(strings.TrimSpace(current.String()), "\n")
	require.Len(t, lines, 50)
	lines[0] = strings.Replace(lines[0], `"title":"Example Domain"`, `"title":"Changed once"`, 1)
	lines[1] = strings.Replace(lines[1], `"webserver":"nginx/1.25"`, `"webserver":"nginx/1.99"`, 1)
	curStr := strings.Join(lines, "\n") + "\n"

	out, stats := runCompare(t, baseline.String(), curStr)
	require.Equal(t, 2, len(nonSummaryLines(out)))
	require.Equal(t, 2, stats.ChangedTargets)
	require.Equal(t, 48, stats.Unchanged)
}

func nonSummaryLines(s string) []string {
	out := []string{}
	for _, line := range nonEmptyLines(s) {
		if !strings.HasPrefix(line, `{"type":"diff_summary"`) {
			out = append(out, line)
		}
	}
	return out
}

// 异常 2: 探测参数不一致要给出警告。
func TestMetadataInconsistencyWarning(t *testing.T) {
	bm := &ScanMetadata{FollowRedirects: true, MaxRedirects: 10, SchemaVersion: 1}
	cm := &ScanMetadata{FollowRedirects: false, MaxRedirects: 10, SchemaVersion: 1}
	warnings := CheckMetadata(bm, cm)
	require.NotEmpty(t, warnings)
	require.Equal(t, "follow_redirects", warnings[0].Field)

	// Missing metadata on either side must NOT produce warnings.
	require.Empty(t, CheckMetadata(nil, cm))
	require.Empty(t, CheckMetadata(bm, nil))
}

// 硬约束 二.1: 身份键不含时间/耗时/哈希 —— 仅时间戳和耗时不同时结果为 unchanged。
func TestVolatileFieldsDoNotTriggerChanges(t *testing.T) {
	current := strings.NewReplacer(
		`"2026-11-20T10:00:00Z"`, `"2026-11-21T10:00:00Z"`,
		`"time": "120ms"`, `"time": "940ms"`,
	).Replace(baseResult)
	out, stats := runCompare(t, jsonl(baseResult), jsonl(current))
	require.Len(t, nonEmptyLines(out), 1, "only summary expected")
	require.Equal(t, 1, stats.Unchanged)
}

func host(i int) string {
	return "host" + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + ".example"
}

func nonEmptyLines(s string) []string {
	out := []string{}
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func decodeRecord(t *testing.T, line string) *Record {
	t.Helper()
	var rec Record
	require.NoError(t, json.Unmarshal([]byte(line), &rec))
	return &rec
}

func changedFieldNames(rec *Record) []string {
	out := make([]string, 0, len(rec.Changes))
	for _, c := range rec.Changes {
		out = append(out, c.Field)
	}
	return out
}
