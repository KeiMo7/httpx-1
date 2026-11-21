package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/httpx/internal/diff"
	"github.com/stretchr/testify/require"
)

// WriteScanMetadata must be a no-op when -scan-meta is off, so the default
// probe path performs no extra file I/O.
func TestWriteScanMetadataDisabledIsNoOp(t *testing.T) {
	r, err := New(&Options{})
	require.NoError(t, err)
	defer r.Close()
	r.options.ScanMeta = false
	r.options.Output = filepath.Join(t.TempDir(), "scan.json")

	r.WriteScanMetadata()
	_, err = os.Stat(diff.SidecarPath(r.options.Output))
	require.True(t, os.IsNotExist(err), "no sidecar should be written when -scan-meta is off")
}

// When enabled, the sidecar is written next to the JSONL output and carries
// the probe parameters a later diff run checks.
func TestWriteScanMetadataEnabledWritesSidecar(t *testing.T) {
	r, err := New(&Options{})
	require.NoError(t, err)
	defer r.Close()
	r.options.ScanMeta = true
	r.options.Output = filepath.Join(t.TempDir(), "scan.json")
	r.options.FollowRedirects = true
	r.options.MaxRedirects = 7
	r.options.ChainInStdout = true
	r.options.JSONOutput = true

	r.WriteScanMetadata()
	meta, err := diff.LoadMetadata(diff.SidecarPath(r.options.Output))
	require.NoError(t, err)
	require.True(t, meta.FollowRedirects)
	require.Equal(t, 7, meta.MaxRedirects)
	require.True(t, meta.IncludeChain)
	require.True(t, meta.JSONOutput)
}
