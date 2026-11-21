package diff

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// FileOptions carries optional overrides for CompareFiles.
type FileOptions struct {
	// BaselineMeta / CurrentMeta override the auto-derived sidecars. A nil
	// element means "load the derived sidecar if present".
	BaselineMeta *ScanMetadata
	CurrentMeta  *ScanMetadata
}

// CompareFiles is the file-level entry point. It writes the diff report
// atomically: output is first written to a temp file in the same directory
// and renamed into place only after a fully successful comparison. A failure
// leaves no partial output behind (requirement 异常.3).
//
// Either path may equal "-" to read from stdin. Missing baseline/current
// files are reported with a dedicated error naming the missing side.
func CompareFiles(baselinePath, currentPath, outputPath string, opts ...FileOptions) (*Stats, []MetadataInconsistency, error) {
	var fo FileOptions
	if len(opts) > 0 {
		fo = opts[0]
	}

	baseline, closeBase, err := openInput(baselinePath, "baseline")
	if err != nil {
		return nil, nil, err
	}
	defer closeBase()

	current, closeCur, err := openInput(currentPath, "current")
	if err != nil {
		return nil, nil, err
	}
	defer closeCur()

	// Sidecar metadata is optional: a missing sidecar is not an error.
	baselineMeta := fo.BaselineMeta
	if baselineMeta == nil {
		baselineMeta, _ = LoadMetadata(SidecarPath(baselinePath))
	}
	currentMeta := fo.CurrentMeta
	if currentMeta == nil {
		currentMeta, _ = LoadMetadata(SidecarPath(currentPath))
	}

	if outputPath == "" || outputPath == "-" {
		// Streaming to stdout cannot be atomic; the contract of no partial
		// files only applies to filesystem outputs.
		stats, warnings, err := Compare(baseline, current, os.Stdout, baselineMeta, currentMeta)
		return stats, warnings, err
	}

	dir := filepath.Dir(outputPath)
	if dir == "" {
		dir = "."
	}
	tmp, err := createOutputTemp(dir, ".httpx-diff-")
	if err != nil {
		return nil, nil, fmt.Errorf("create temporary output: %w", err)
	}
	tmpPath := tmp.Name()
	// On any error path remove the temp file; a successful rename clears it.
	cleanup := func() { _ = os.Remove(tmpPath) }

	stats, warnings, err := Compare(baseline, current, tmp, baselineMeta, currentMeta)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if err := os.Rename(tmpPath, outputPath); err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("commit diff output %q: %w", outputPath, err)
	}
	return stats, warnings, nil
}

// ErrMissingInput names the side (baseline/current) whose file is absent so
// callers never mistake a missing run for "all targets are new".
type ErrMissingInput struct {
	Side string
	Path string
}

func (e *ErrMissingInput) Error() string {
	return fmt.Sprintf("%s result file is missing: %q (provide the previous run's JSONL output; it cannot be treated as an empty baseline)", e.Side, e.Path)
}

func openInput(path, side string) (io.Reader, func(), error) {
	if path == "-" {
		return os.Stdin, func() {}, nil
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, &ErrMissingInput{Side: side, Path: path}
		}
		return nil, nil, fmt.Errorf("open %s %q: %w", side, path, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s %q: %w", side, path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

// SidecarPath derives the optional metadata path for a JSONL result file:
// "run.json" -> "run.meta.json". For stdin there is no sidecar.
func SidecarPath(resultPath string) string {
	if resultPath == "" || resultPath == "-" {
		return ""
	}
	ext := filepath.Ext(resultPath)
	if ext == "" {
		return resultPath + ".meta.json"
	}
	return resultPath[:len(resultPath)-len(ext)] + ".meta.json"
}

// LoadMetadata reads a scan metadata sidecar. A missing file returns
// os.ErrNotExist wrapped, which callers treat as "no metadata available".
func LoadMetadata(path string) (*ScanMetadata, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var meta ScanMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parse metadata %q: %w", path, err)
	}
	return &meta, nil
}

// WriteMetadata writes a scan metadata sidecar next to a JSONL result file.
// It is a no-op when the result path is empty or stdout. The write is
// atomic for the same reason the diff output is.
func WriteMetadata(resultPath string, meta ScanMetadata) error {
	path := SidecarPath(resultPath)
	if path == "" {
		return nil
	}
	meta.Tool = "httpx"
	meta.SchemaVersion = CurrentSchemaVersion
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := createOutputTemp(dir, ".httpx-meta-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// createOutputTemp creates a new, uniquely named temporary file in dir.
// Unlike os.CreateTemp (which fixes permissions at 0600), it opens with
// mode 0666 and O_EXCL so the process umask is applied at creation time —
// exactly the semantics of os.Create, which httpx's normal output path uses.
// It retries on the (vanishingly unlikely) name collision implied by O_EXCL.
func createOutputTemp(dir, prefix string) (*os.File, error) {
	var randBytes [8]byte
	for attempt := 0; attempt < 100; attempt++ {
		if _, err := cryptorand.Read(randBytes[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, fmt.Sprintf("%s%x.tmp", prefix, randBytes[:]))
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("could not allocate a unique temporary file in %q", dir)
}
