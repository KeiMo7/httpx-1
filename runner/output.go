package runner

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/corona10/goimagehash"
	"github.com/projectdiscovery/gologger"
	fileutilz "github.com/projectdiscovery/httpx/common/fileutil"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/projectdiscovery/utils/structs"
	urlutil "github.com/projectdiscovery/utils/url"
)

// slotResult is a probe record tagged with the slot it was dispatched for.
// Sequencing happens at dispatch, so the record can arrive in any order and
// still be emitted in reservation order.
type slotResult struct {
	slot   Slot
	result Result
}

// outputSinks holds the files and flags shared by every output format. All
// writes happen on the single output goroutine.
type outputSinks struct {
	plainFile, jsonFile, csvFile, mdFile, indexFile, indexScreenshotFile *os.File
	jsonOrCsvOrMD                                                        bool
	jsonAndCsvAndMD                                                      bool
	markdownHeaderWritten                                                bool
}

func (s *outputSinks) close() {
	for _, f := range []*os.File{s.plainFile, s.jsonFile, s.csvFile, s.mdFile, s.indexFile, s.indexScreenshotFile} {
		if f != nil {
			_ = f.Close()
		}
	}
}

// openSinks opens every configured output file. A failure to open returns an
// error instead of exiting, so a read-only directory is reported and the run
// stops with a non-zero exit code.
func (r *Runner) openSinks() (*outputSinks, error) {
	s := &outputSinks{}
	open := func(resume bool, filename string) (*os.File, error) {
		return openSinkFile(resume, filename)
	}

	if r.options.Output != "" && r.options.OutputAll {
		var err error
		if s.plainFile, err = open(r.options.Resume, r.options.Output); err != nil {
			return nil, err
		}
		if s.jsonFile, err = open(r.options.Resume, r.options.Output+".json"); err != nil {
			return nil, err
		}
		if s.csvFile, err = open(r.options.Resume, r.options.Output+".csv"); err != nil {
			return nil, err
		}
		if s.mdFile, err = open(r.options.Resume, r.options.Output+".md"); err != nil {
			return nil, err
		}
	}

	s.jsonOrCsvOrMD = (r.options.JSONOutput || r.options.CSVOutput || r.options.MarkDownOutput)
	s.jsonAndCsvAndMD = (r.options.JSONOutput && r.options.CSVOutput && r.options.MarkDownOutput)
	if r.options.Output != "" && s.plainFile == nil && !s.jsonOrCsvOrMD {
		f, err := open(r.options.Resume, r.options.Output)
		if err != nil {
			return nil, err
		}
		s.plainFile = f
	}

	if r.options.Output != "" && r.options.JSONOutput && s.jsonFile == nil {
		ext := ""
		if s.jsonAndCsvAndMD {
			ext = ".json"
		}
		f, err := open(r.options.Resume, r.options.Output+ext)
		if err != nil {
			return nil, err
		}
		s.jsonFile = f
	}

	if r.options.Output != "" && r.options.CSVOutput && s.csvFile == nil {
		ext := ""
		if s.jsonAndCsvAndMD {
			ext = ".csv"
		}
		f, err := open(r.options.Resume, r.options.Output+ext)
		if err != nil {
			return nil, err
		}
		s.csvFile = f
	}

	if r.options.Output != "" && r.options.MarkDownOutput && s.mdFile == nil {
		ext := ""
		if s.jsonAndCsvAndMD {
			ext = ".md"
		}
		f, err := open(r.options.Resume, r.options.Output+ext)
		if err != nil {
			return nil, err
		}
		s.mdFile = f
	}

	if r.options.CSVOutput {
		outEncoding := strings.ToLower(r.options.CSVOutputEncoding)
		switch outEncoding {
		case "": // no encoding do nothing
		case "utf-8", "utf8":
			bomUtf8 := []byte{0xEF, 0xBB, 0xBF}
			if s.csvFile != nil {
				if _, err := s.csvFile.Write(bomUtf8); err != nil {
					return nil, fmt.Errorf("could not write the csv encoding header: %w", err)
				}
			}
		default: // unknown encoding
			return nil, fmt.Errorf("unknown csv output encoding: %s", r.options.CSVOutputEncoding)
		}
		headers := Result{}.CSVHeader()
		if !r.options.OutputAll && !s.jsonAndCsvAndMD {
			gologger.Silent().Msgf("%s\n", headers)
		}

		if s.csvFile != nil {
			if _, err := s.csvFile.WriteString(headers + "\n"); err != nil {
				return nil, fmt.Errorf("could not write the csv header: %w", err)
			}
		}
	}
	if r.options.StoreResponseDir != "" {
		responseDirPath := filepath.Join(r.options.StoreResponseDir, "response")
		if err := os.MkdirAll(responseDirPath, 0755); err != nil {
			return nil, fmt.Errorf("could not create response directory '%s': %w", responseDirPath, err)
		}
		indexPath := filepath.Join(responseDirPath, "index.txt")
		// Append if resume is enabled or skip-dedupe is enabled (never truncate with -sd)
		var err error
		if r.options.Resume || r.options.SkipDedupe {
			s.indexFile, err = os.OpenFile(indexPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		} else {
			s.indexFile, err = os.Create(indexPath)
		}
		if err != nil {
			return nil, fmt.Errorf("could not open/create index file '%s': %w", indexPath, err)
		}
	}

	if r.options.Screenshot {
		indexScreenshotPath := filepath.Join(r.options.StoreResponseDir, "screenshot", "index_screenshot.txt")
		// Append if resume is enabled or skip-dedupe is enabled (never truncate with -sd)
		var err error
		if r.options.Resume || r.options.SkipDedupe {
			s.indexScreenshotFile, err = os.OpenFile(indexScreenshotPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		} else {
			s.indexScreenshotFile, err = os.Create(indexScreenshotPath)
		}
		if err != nil {
			return nil, fmt.Errorf("could not open/create index screenshot file '%s': %w", indexScreenshotPath, err)
		}
	}
	return s, nil
}

// outputWriter serializes the records the ordering layer emits to every sink.
// Every field is only touched by the writer goroutine.
type outputWriter struct {
	runner *Runner
	sinks  *outputSinks
	// raw is the probe result channel; order assigns sequence numbers in
	// reservation order; nextOut receives the ordered records for the HTML
	// summary step.
	raw     <-chan slotResult
	order   *OrderBuffer
	nextOut chan<- Result
	done    chan struct{}
	errMu   sync.Mutex
	err     error

	plainFile, jsonFile, csvFile, mdFile, indexFile, indexScreenshotFile *os.File
	jsonOrCsvOrMD, jsonAndCsvAndMD                                       bool
	markdownHeaderWritten                                                bool

	lastErr error
}

func (w *outputWriter) open() error {
	sinks, err := w.runner.openSinks()
	if err != nil {
		return err
	}
	w.sinks = sinks
	w.plainFile = sinks.plainFile
	w.jsonFile = sinks.jsonFile
	w.csvFile = sinks.csvFile
	w.mdFile = sinks.mdFile
	w.indexFile = sinks.indexFile
	w.indexScreenshotFile = sinks.indexScreenshotFile
	w.jsonOrCsvOrMD = sinks.jsonOrCsvOrMD
	w.jsonAndCsvAndMD = sinks.jsonAndCsvAndMD
	w.markdownHeaderWritten = sinks.markdownHeaderWritten
	return nil
}

// ---- sink write helpers (implemented in output_sinks.go) ----

// filterOut applies the matchers and filters to a record. A true return means
// the record is dropped: its slot is consumed without an output line.
func (r *Runner) filterOut(resp *Result) bool {
	if resp.str == "" {
		return true
	}
	if r.options.SniName != "" {
		resp.SNI = r.options.SniName
	}

	if resp.Err != nil {
		// Change the error message if any port value passed explicitly
		if url, err := r.parseURL(resp.URL); err == nil && url.Port() != "" {
			resp.Err = errors.New(strings.ReplaceAll(resp.Err.Error(), "address", "port"))
		}
		gologger.Debug().Msgf("Failed '%s': %s\n", resp.URL, resp.Err)
	}
	if resp.str == "" {
		return true
	}

	// apply matchers and filters
	if r.options.OutputFilterCondition != "" || r.options.OutputMatchCondition != "" {
		if r.options.OutputMatchCondition != "" {
			matched := evalDslExpr(*resp, r.options.OutputMatchCondition)
			if !matched {
				return true
			}
		}
		if r.options.OutputFilterCondition != "" {
			matched := evalDslExpr(*resp, r.options.OutputFilterCondition)
			if matched {
				return true
			}
		}
	}

	if len(r.options.OutputFilterPageType) > 0 {
		if pageType, ok := resp.KnowledgeBase["PageType"].(string); ok {
			if stringsutil.EqualFoldAny(pageType, r.options.OutputFilterPageType...) {
				logFilteredErrorPage(r.options.OutputFilterErrorPagePath, resp.URL)
				return true
			}
		}
	}

	if r.options.FilterOutDuplicates && r.duplicate(resp) {
		return true
	}

	if len(r.options.filterStatusCode) > 0 && sliceutil.Contains(r.options.filterStatusCode, resp.StatusCode) {
		return true
	}
	if len(r.options.filterContentLength) > 0 && sliceutil.Contains(r.options.filterContentLength, resp.ContentLength) {
		return true
	}
	if len(r.options.filterLinesCount) > 0 && sliceutil.Contains(r.options.filterLinesCount, resp.Lines) {
		return true
	}
	if len(r.options.filterWordsCount) > 0 && sliceutil.Contains(r.options.filterWordsCount, resp.Words) {
		return true
	}
	if r.options.filterRegexes != nil {
		shouldContinue := false
		for _, filterRegex := range r.options.filterRegexes {
			if filterRegex.MatchString(resp.Raw) {
				shouldContinue = true
				break
			}
		}
		if shouldContinue {
			return true
		}
	}
	if len(r.options.OutputFilterString) > 0 && stringsutil.ContainsAnyI(resp.Raw, r.options.OutputFilterString...) {
		return true
	}
	if len(r.options.OutputFilterFavicon) > 0 && stringsutil.ContainsAnyI(resp.FavIconMMH3, r.options.OutputFilterFavicon...) {
		return true
	}
	if len(r.options.matchStatusCode) > 0 && !sliceutil.Contains(r.options.matchStatusCode, resp.StatusCode) {
		return true
	}
	if len(r.options.matchContentLength) > 0 && !sliceutil.Contains(r.options.matchContentLength, resp.ContentLength) {
		return true
	}
	if r.options.matchRegexes != nil {
		shouldContinue := false
		for _, matchRegex := range r.options.matchRegexes {
			if !matchRegex.MatchString(resp.Raw) {
				shouldContinue = true
				break
			}
		}
		if shouldContinue {
			return true
		}
	}
	if len(r.options.OutputMatchString) > 0 && !stringsutil.ContainsAnyI(resp.Raw, r.options.OutputMatchString...) {
		return true
	}
	if len(r.options.OutputMatchFavicon) > 0 && !stringsutil.EqualFoldAny(resp.FavIconMMH3, r.options.OutputMatchFavicon...) {
		return true
	}
	if len(r.options.matchLinesCount) > 0 && !sliceutil.Contains(r.options.matchLinesCount, resp.Lines) {
		return true
	}
	if len(r.options.matchWordsCount) > 0 && !sliceutil.Contains(r.options.matchWordsCount, resp.Words) {
		return true
	}
	if len(r.options.OutputMatchCdn) > 0 && !stringsutil.EqualFoldAny(resp.CDNName, r.options.OutputMatchCdn...) {
		return true
	}
	if len(r.options.OutputFilterCdn) > 0 && stringsutil.EqualFoldAny(resp.CDNName, r.options.OutputFilterCdn...) {
		return true
	}

	if r.options.OutputMatchResponseTime != "" {
		filterOps := FilterOperator{flag: "-mrt, -match-response-time"}
		operator, value, err := filterOps.Parse(r.options.OutputMatchResponseTime)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		respTimeTaken, _ := time.ParseDuration(resp.ResponseTime)
		switch operator {
		// take negation of >= and >
		case greaterThanEq, greaterThan:
			if respTimeTaken < value {
				return true
			}
		// take negation of <= and <
		case lessThanEq, lessThan:
			if respTimeTaken > value {
				return true
			}
		// take negation of =
		case equal:
			if respTimeTaken != value {
				return true
			}
		// take negation of !=
		case notEq:
			if respTimeTaken == value {
				return true
			}
		}
	}

	if r.options.OutputFilterResponseTime != "" {
		filterOps := FilterOperator{flag: "-frt, -filter-response-time"}
		operator, value, err := filterOps.Parse(r.options.OutputFilterResponseTime)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		respTimeTaken, _ := time.ParseDuration(resp.ResponseTime)
		switch operator {
		case greaterThanEq:
			if respTimeTaken >= value {
				return true
			}
		case lessThanEq:
			if respTimeTaken <= value {
				return true
			}
		case equal:
			if respTimeTaken == value {
				return true
			}
		case lessThan:
			if respTimeTaken < value {
				return true
			}
		case greaterThan:
			if respTimeTaken > value {
				return true
			}
		case notEq:
			if respTimeTaken != value {
				return true
			}
		}
	}

	return false
}

// emit writes one ordered record to every configured sink. It returns the
// first write error; records already emitted stay complete, and no half line
// is produced.
func (w *outputWriter) emit(resp Result) error {
	r := w.runner
	if !r.options.DisableStdout && (!w.jsonOrCsvOrMD || w.jsonAndCsvAndMD || r.options.OutputAll) {
		gologger.Silent().Msgf("%s\n", resp.str)
	}

	// store responses or chain in directory
	if resp.Err == nil {
		URL, _ := urlutil.Parse(resp.URL)
		domainResponseFile := fmt.Sprintf("%s.txt", resp.FileNameHash)
		screenshotResponseFile := fmt.Sprintf("%s.png", resp.FileNameHash)
		hostFilename := strings.ReplaceAll(URL.Host, ":", "_")
		domainResponseBaseDir := filepath.Join(r.options.StoreResponseDir, "response")
		domainScreenshotBaseDir := filepath.Join(r.options.StoreResponseDir, "screenshot")
		responseBaseDir := filepath.Join(domainResponseBaseDir, hostFilename)
		screenshotBaseDir := filepath.Join(domainScreenshotBaseDir, hostFilename)

		var responsePath, screenshotPath, screenshotPathRel string
		// store response
		if r.scanopts.StoreResponse || r.scanopts.StoreChain {
			if r.scanopts.OmitBody && resp.Response != nil {
				resp.Raw = resp.Response.RawHeaders
			}

			responsePath = fileutilz.AbsPathOrDefault(filepath.Join(responseBaseDir, domainResponseFile))
			// URL.EscapedString returns that can be used as filename
			respRaw := resp.Raw
			reqRaw := resp.RequestRaw
			if len(respRaw) > r.scanopts.MaxResponseBodySizeToSave {
				respRaw = respRaw[:r.scanopts.MaxResponseBodySizeToSave]
			}
			data := reqRaw
			if r.options.StoreChain && resp.Response != nil && resp.Response.HasChain() {
				data = append(data, append([]byte("\n"), []byte(resp.Response.GetChain())...)...)
			}
			data = append(data, respRaw...)
			data = append(data, []byte("\n\n\n")...)
			data = append(data, []byte(resp.URL)...)
			_ = fileutil.CreateFolder(responseBaseDir)
			writeErr := os.WriteFile(responsePath, data, 0644)
			if writeErr != nil {
				gologger.Error().Msgf("Could not write response at path '%s', to disk: %s", responsePath, writeErr)
			}
			resp.StoredResponsePath = responsePath
		}

		if r.scanopts.Screenshot {
			screenshotPath = fileutilz.AbsPathOrDefault(filepath.Join(screenshotBaseDir, screenshotResponseFile))
			screenshotPathRel = filepath.Join(hostFilename, screenshotResponseFile)
			_ = fileutil.CreateFolder(screenshotBaseDir)
			err := os.WriteFile(screenshotPath, resp.ScreenshotBytes, 0644)
			if err != nil {
				gologger.Error().Msgf("Could not write screenshot at path '%s', to disk: %s", screenshotPath, err)
			}

			resp.ScreenshotPath = screenshotPath
			resp.ScreenshotPathRel = screenshotPathRel
			if r.scanopts.NoScreenshotBytes {
				resp.ScreenshotBytes = []byte{}
			}
		}

		if w.indexFile != nil {
			indexData := fmt.Sprintf("%s %s (%d %s)\n", resp.StoredResponsePath, resp.URL, resp.StatusCode, http.StatusText(resp.StatusCode))
			_, _ = w.indexFile.WriteString(indexData)
		}
		if w.indexScreenshotFile != nil && resp.ScreenshotPathRel != "" {
			indexData := fmt.Sprintf("%s %s (%d %s)\n", resp.ScreenshotPathRel, resp.URL, resp.StatusCode, http.StatusText(resp.StatusCode))
			_, _ = w.indexScreenshotFile.WriteString(indexData)
		}

		if r.scanopts.StoreVisionReconClusters {
			foundCluster := false
			pHash, _ := resp.KnowledgeBase["pHash"].(uint64)
			for i, cluster := range r.pHashClusters {
				distance, _ := goimagehash.NewImageHash(pHash, goimagehash.PHash).Distance(goimagehash.NewImageHash(cluster.BasePHash, goimagehash.PHash))
				if distance <= hammingDistanceThreshold {
					r.pHashClusters[i].Hashes = append(r.pHashClusters[i].Hashes, pHashUrl{PHash: pHash, Url: resp.URL})
					foundCluster = true
					break
				}
			}

			if !foundCluster {
				newCluster := pHashCluster{
					BasePHash: pHash,
					Hashes:    []pHashUrl{{PHash: pHash, Url: resp.URL}},
				}
				r.pHashClusters = append(r.pHashClusters, newCluster)
			}
		}
	}

	//nolint:errcheck // this method needs a small refactor to reduce complexity
	if w.plainFile != nil {
		w.plainFile.WriteString(handleStripAnsiCharacters(resp.str, r.options.NoColor) + "\n")
	}

	if len(r.options.ExcludeOutputFields) > 0 {
		if filteredData, err := structs.FilterStruct(resp, nil, r.options.ExcludeOutputFields); err == nil {
			resp = filteredData
		}
	}

	// call the callback function if any
	// be careful and check for result.Err
	if r.options.OnResult != nil {
		r.options.OnResult(resp)
	}

	if r.options.JSONOutput {
		row := resp.JSON(&r.scanopts)

		if !r.options.OutputAll && !w.jsonAndCsvAndMD {
			gologger.Silent().Msgf("%s\n", row)
		}

		//nolint:errcheck // this method needs a small refactor to reduce complexity
		if w.jsonFile != nil {
			w.jsonFile.WriteString(row + "\n")
		}
	}

	if r.options.CSVOutput {
		row := resp.CSVRow(&r.scanopts)

		if !r.options.OutputAll && !w.jsonAndCsvAndMD {
			gologger.Silent().Msgf("%s\n", row)
		}

		//nolint:errcheck // this method needs a small refactor to reduce complexity
		if w.csvFile != nil {
			w.csvFile.WriteString(row + "\n")
		}
	}

	if r.options.MarkDownOutput || r.options.OutputAll {
		if !w.markdownHeaderWritten {
			header := resp.MarkdownHeader()
			if !r.options.OutputAll {
				gologger.Silent().Msgf("%s", header)
			}
			if w.mdFile != nil {
				_, _ = w.mdFile.WriteString(header)
			}
			w.markdownHeaderWritten = true
		}

		row := resp.MarkdownRow(&r.scanopts)

		if !r.options.OutputAll {
			gologger.Silent().Msgf("%s", row)
		}
		if w.mdFile != nil {
			_, _ = w.mdFile.WriteString(row)
		}
	}

	return nil
}

// close flushes and closes every output file.
func (w *outputWriter) close() {
	if w.sinks != nil {
		w.sinks.close()
	}
}

// setError records the first error that should abort dispatch.
func (w *outputWriter) setError(err error) {
	w.errMu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.errMu.Unlock()
}

// errSnapshot returns the dispatch error, if any.
func (w *outputWriter) errSnapshot() error {
	w.errMu.Lock()
	defer w.errMu.Unlock()
	return w.err
}

// write consumes the raw slot results, applies filters and emits the ordered
// prefix until the probe channel closes and the buffer is drained.
//
// It is the only goroutine that writes to a sink. Probes only send to w.raw,
// so filtering (which mutates shared dedupe state and writes the filtered page
// log) and output stay on one goroutine.
func (w *outputWriter) write() {
	defer close(w.done)
	order := w.order
	for {
		// 1. Emit everything that is already ordered and ready.
		if err := order.FlushReady(w.emitOrdered); err != nil {
			w.setError(err)
			order.Cancel()
			for range w.raw {
				// Drain in-flight probes so they do not block on send.
			}
			break
		}

		// 2. Wait for a probe record or the next timeout deadline.
		wait := order.NextTimeout()
		var timer *time.Timer
		var deadline <-chan time.Time
		if wait > 0 {
			timer = time.NewTimer(wait)
			deadline = timer.C
		}
		select {
		case sr, ok := <-w.raw:
			if timer != nil {
				timer.Stop()
			}
			if !ok {
				// All probes are done: flush the remainder and drain.
				order.Close()
				if err := order.Drain(w.emitOrdered); err != nil {
					w.setError(err)
				}
				return
			}
			if w.errSnapshot() != nil {
				order.Cancel()
				continue
			}
			if err := w.handle(sr); err != nil {
				w.setError(err)
				order.Cancel()
			}
		case <-deadline:
			// NextTimeout loop synthesizes the timed out record.
		}
	}
}

// handle filters and pushes one probe record.
func (w *outputWriter) handle(sr slotResult) error {
	if w.runner.filterOut(&sr.result) {
		return w.order.Skip(sr.slot)
	}
	return w.order.Push(sr.slot, sr.result)
}

// emitOrdered is the callback given to the order buffer. It writes a record to
// every sink and forwards it to the HTML summary step.
func (w *outputWriter) emitOrdered(resp Result) error {
	if err := w.emit(resp); err != nil {
		return err
	}
	if w.nextOut != nil {
		w.nextOut <- resp
	}
	return nil
}

// reserveSlot is a placeholder kept for compatibility with the previous
// reservation helper.

// openSinkFile opens an output file for writing. Non-resume truncates and
// resume appends, matching the historical behavior; unlike openOrCreateFile it
// returns the error instead of exiting so a read-only directory stops the run
// with a non-zero exit code.
func openSinkFile(resume bool, filename string) (*os.File, error) {
	if resume {
		f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("could not open/create output file '%s': %w", filename, err)
		}
		return f, nil
	}
	f, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open/create output file '%s': %w", filename, err)
	}
	return f, nil
}
