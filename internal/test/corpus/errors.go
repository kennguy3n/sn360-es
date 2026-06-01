package corpus

import "fmt"

// LoaderError carries the line number and underlying cause for a
// JSONL parse failure. The harness surfaces it verbatim to the
// operator so a malformed fixture is debuggable from the CI log
// without rerunning anything.
type LoaderError struct {
	Path string
	Line int
	Err  error
}

func (e *LoaderError) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("corpus: line %d: %v", e.Line, e.Err)
	}
	return fmt.Sprintf("corpus: %s line %d: %v", e.Path, e.Line, e.Err)
}

func (e *LoaderError) Unwrap() error { return e.Err }

type missingFieldError struct{ field string }

func (e *missingFieldError) Error() string {
	return fmt.Sprintf("missing required field %q", e.field)
}

func errMissing(field string) error { return &missingFieldError{field: field} }

type invalidLabelError struct{ value string }

func (e *invalidLabelError) Error() string {
	return fmt.Sprintf("invalid label %q (expected one of phish/spam/benign/bec)", e.value)
}

func errInvalidLabel(v string) error { return &invalidLabelError{value: v} }

type invalidTierError struct{ value string }

func (e *invalidTierError) Error() string {
	return fmt.Sprintf("invalid expected_tier %q", e.value)
}

func errInvalidTier(v string) error { return &invalidTierError{value: v} }
