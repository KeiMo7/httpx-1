package runner

import (
	"errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/internal/diff"
)

// RunDiff executes the offline two-file comparison mode. It never performs
// network probes and never touches the normal enumeration pipeline. It
// returns an exit code: 0 when the report was produced (changes may still be
// present — finding differences is a successful run), 1 on hard failure
// (missing input, unparseable JSONL, write error).
func RunDiff(options *Options) int {
	baseline := options.DiffBaseline
	current := options.DiffCurrent

	// Explicit metadata overrides take precedence over the derived sidecars.
	// A missing sidecar is not an error: result files older than this feature
	// simply carry no metadata.
	var baselineMeta, currentMeta *diff.ScanMetadata
	if options.DiffBaselineMeta != "" {
		m, err := diff.LoadMetadata(options.DiffBaselineMeta)
		if err != nil {
			gologger.Error().Msgf("Could not read baseline metadata %q: %s\n", options.DiffBaselineMeta, err)
			return 1
		}
		baselineMeta = m
	} else if options.DiffBaseline != "-" {
		baselineMeta, _ = diff.LoadMetadata(diff.SidecarPath(options.DiffBaseline))
	}
	if options.DiffCurrentMeta != "" {
		m, err := diff.LoadMetadata(options.DiffCurrentMeta)
		if err != nil {
			gologger.Error().Msgf("Could not read current metadata %q: %s\n", options.DiffCurrentMeta, err)
			return 1
		}
		currentMeta = m
	} else if options.DiffCurrent != "-" {
		currentMeta, _ = diff.LoadMetadata(diff.SidecarPath(options.DiffCurrent))
	}

	stats, warnings, err := diff.CompareFiles(baseline, current, options.DiffOutput, diff.FileOptions{
		BaselineMeta: baselineMeta,
		CurrentMeta:  currentMeta,
	})
	if err != nil {
		// Name the missing side explicitly instead of treating it as "all new".
		var missing *diff.ErrMissingInput
		if errors.As(err, &missing) {
			gologger.Error().Msgf("%s\n", err)
			return 1
		}
		gologger.Error().Msgf("Diff failed: %s\n", err)
		return 1
	}

	// Incompatible probe parameters: warn loudly but keep the report, which
	// was computed from the data actually present. Emitted at Info level on
	// purpose: gologger's Warning level is hidden by default, and this is a
	// functional guard (requirement 异常.2) that must be visible without -v.
	for _, w := range warnings {
		gologger.Info().Msgf("Inconsistent scan parameters (%s): baseline=%v current=%v — %s\n",
			w.Field, w.Baseline, w.Current, w.Explanation)
	}

	printDiffSummary(stats)
	return 0
}

func printDiffSummary(stats *diff.Stats) {
	gologger.Info().Msgf("Diff complete: %d baseline / %d current entries, %d matched identities, %d unchanged, %d changed targets\n",
		stats.BaselineEntries, stats.CurrentEntries, stats.MatchedIdentites, stats.Unchanged, stats.ChangedTargets)
	for _, cat := range diff.AllCategories {
		gologger.Info().Msgf("  %-12s %d\n", string(cat), stats.ByCategory[cat])
	}
	if stats.BaselineOnly > 0 || stats.CurrentOnly > 0 {
		gologger.Info().Msgf("Presence differences: %d baseline-only, %d current-only\n", stats.BaselineOnly, stats.CurrentOnly)
	}
	if stats.DuplicateIdentities > 0 {
		gologger.Info().Msgf("%d duplicate target identities detected (last occurrence wins within each file)\n", stats.DuplicateIdentities)
	}
}

// WriteScanMetadata writes the sidecar describing this run's probe
// parameters. Failures are warnings only: metadata is auxiliary.
func (r *Runner) WriteScanMetadata() {
	if !r.options.ScanMeta || r.options.Output == "" {
		return
	}
	meta := diff.ScanMetadata{
		FollowRedirects:     r.options.FollowRedirects,
		FollowHostRedirects: r.options.FollowHostRedirects,
		MaxRedirects:        r.options.MaxRedirects,
		JSONOutput:          r.options.JSONOutput,
		IncludeChain:        r.options.ChainInStdout,
	}
	jsonPath := r.options.Output
	if r.options.OutputAll {
		jsonPath = r.options.Output + ".json"
	}
	if err := diff.WriteMetadata(jsonPath, meta); err != nil {
		gologger.Info().Msgf("Could not write scan metadata sidecar: %s\n", err)
	}
}
