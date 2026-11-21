package diff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
}

// 异常 3: 比对失败不能留下半截输出文件。
func TestCompareFilesAtomicOnBadInput(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.jsonl")
	cur := filepath.Join(dir, "current.jsonl")
	out := filepath.Join(dir, "report.jsonl")
	writeFile(t, base, jsonl(baseResult))
	// Malformed current line.
	writeFile(t, cur, "{ this is not valid json\n")

	_, _, err := CompareFiles(base, cur, out)
	require.Error(t, err)
	_, statErr := os.Stat(out)
	require.True(t, os.IsNotExist(statErr), "no partial output file must remain: %v", statErr)

	// And no leftover temp files in the output directory.
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.Falsef(t, strings.HasPrefix(e.Name(), ".httpx-diff-"), "temp file leaked: %s", e.Name())
	}
}

// 异常 1: 缺失的上一轮文件必须明确报错，而不是当成空基线。
func TestCompareFilesMissingBaseline(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "current.jsonl")
	writeFile(t, cur, jsonl(baseResult))

	_, _, err := CompareFiles(filepath.Join(dir, "nope.jsonl"), cur, filepath.Join(dir, "out.jsonl"))
	require.Error(t, err)
	var missing *ErrMissingInput
	require.ErrorAs(t, err, &missing)
	require.Equal(t, "baseline", missing.Side)
}

func TestCompareFilesMissingCurrent(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.jsonl")
	writeFile(t, base, jsonl(baseResult))

	_, _, err := CompareFiles(base, filepath.Join(dir, "nope.jsonl"), filepath.Join(dir, "out.jsonl"))
	require.Error(t, err)
	var missing *ErrMissingInput
	require.ErrorAs(t, err, &missing)
	require.Equal(t, "current", missing.Side)
}

// 成功路径产出文件且内容与内存比对一致（逐字节确定性）。
func TestCompareFilesWritesReport(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.jsonl")
	cur := filepath.Join(dir, "current.jsonl")
	out := filepath.Join(dir, "report.jsonl")
	changed := strings.Replace(baseResult, `"title": "Example Domain"`, `"title": "New"`, 1)
	writeFile(t, base, jsonl(baseResult))
	writeFile(t, cur, jsonl(changed))

	stats, _, err := CompareFiles(base, cur, out)
	require.NoError(t, err)
	require.Equal(t, 1, stats.ChangedTargets)

	data, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Contains(t, string(data), `"identity":"https://example.com"`)
	require.Contains(t, string(data), `"type":"diff_summary"`)

	// Running again overwrites with identical bytes.
	_, _, err = CompareFiles(base, cur, out)
	require.NoError(t, err)
	data2, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, data, data2)
}

// sidecar 路径推导与往返读写。
func TestSidecarRoundTrip(t *testing.T) {
	require.Equal(t, "run.meta.json", SidecarPath("run.json"))
	require.Equal(t, "/a/b/run.meta.json", SidecarPath("/a/b/run.jsonl"))
	require.Equal(t, "run.meta.json", SidecarPath("run"))
	require.Equal(t, "", SidecarPath("-"))

	dir := t.TempDir()
	result := filepath.Join(dir, "scan.json")
	meta := ScanMetadata{FollowRedirects: true, MaxRedirects: 5}
	require.NoError(t, WriteMetadata(result, meta))

	loaded, err := LoadMetadata(SidecarPath(result))
	require.NoError(t, err)
	require.Equal(t, true, loaded.FollowRedirects)
	require.Equal(t, 5, loaded.MaxRedirects)
	require.Equal(t, "httpx", loaded.Tool)
	require.Equal(t, CurrentSchemaVersion, loaded.SchemaVersion)
}

// 元数据通过 FileOptions 显式覆盖时优先于自动 sidecar。
func TestCompareFilesMetadataOverride(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.jsonl")
	cur := filepath.Join(dir, "current.jsonl")
	writeFile(t, base, jsonl(baseResult))
	writeFile(t, cur, jsonl(baseResult))

	bm := &ScanMetadata{FollowRedirects: true}
	cm := &ScanMetadata{FollowRedirects: false}
	_, warnings, err := CompareFiles(base, cur, filepath.Join(dir, "o.jsonl"), FileOptions{
		BaselineMeta: bm, CurrentMeta: cm,
	})
	require.NoError(t, err)
	require.NotEmpty(t, warnings)
	require.Equal(t, "follow_redirects", warnings[0].Field)
}
