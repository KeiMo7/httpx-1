package fingerprint

import (
	"fmt"
	"os"
)

// RuleFileError reports a rule file that could not be opened. It keeps the
// path so callers can print it, and implements errors.Is against the common
// errors it wraps.
type RuleFileError struct {
	Path string
	Err  error
}

func (e *RuleFileError) Error() string {
	return fmt.Sprintf("could not read fingerprint rules file %q: %s", e.Path, e.Err)
}

// Unwrap exposes the underlying error.
func (e *RuleFileError) Unwrap() error { return e.Err }

// LoadRulesFromFile loads rules from path, using the path as the file prefix of
// every error.
func LoadRulesFromFile(path string) (*RuleSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, &RuleFileError{Path: path, Err: err}
	}
	defer f.Close() //nolint:errcheck
	return loadRules(f, path)
}
