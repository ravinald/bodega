// Package builder contains the orchestration logic for building bootstrap
// artifacts. Each sub-builder (apt, git, pypi, binary) calls out to system
// tools; the Go code manages directories, captures output, and reports results.
package builder

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/logging"
)

// Config holds the parameters shared by all builders.
type Config struct {
	BuildRoot   string
	ManifestDir string
	Bucket      string
	Region      string
	Verbose     bool
	// Per-type build root overrides. Empty means use BuildRoot.
	AptRoot    string
	GitRoot    string
	PypiRoot   string
	BinaryRoot string
	GomodRoot  string
	HelmRoot   string
	NpmRoot    string
	// Stdout is where builder output is written; defaults to os.Stdout.
	Stdout io.Writer
	// Logger is an optional structured build logger. When set, each per-entry
	// stage writes to a dedicated package log in addition to Stdout.
	Logger *logging.BuildLogger
}

// rootFor returns the effective build root for the given source type.
func (c *Config) rootFor(typ string) string {
	switch typ {
	case "apt":
		if c.AptRoot != "" {
			return c.AptRoot
		}
	case "git":
		if c.GitRoot != "" {
			return c.GitRoot
		}
	case "pypi":
		if c.PypiRoot != "" {
			return c.PypiRoot
		}
	case "binary":
		if c.BinaryRoot != "" {
			return c.BinaryRoot
		}
	case "gomod":
		if c.GomodRoot != "" {
			return c.GomodRoot
		}
	case "helm":
		if c.HelmRoot != "" {
			return c.HelmRoot
		}
	case "npm":
		if c.NpmRoot != "" {
			return c.NpmRoot
		}
	}
	return c.BuildRoot
}

// stdout returns the configured output writer, falling back to os.Stdout.
func (c *Config) stdout() io.Writer {
	if c.Stdout != nil {
		return c.Stdout
	}
	return os.Stdout
}

// entryWriter returns an io.Writer scoped to a single manifest entry. When a
// Logger is configured the output is written to both a dedicated package log
// file and the session log simultaneously. Without a Logger it falls back to
// the regular stdout writer so callers require no special-case logic.
func (c *Config) entryWriter(typ, name string) io.Writer {
	if c.Logger != nil {
		return c.Logger.StartPackage(typ, name)
	}
	return c.stdout()
}

// logf writes a formatted line to the configured output writer.
// The error return from fmt.Fprintf is intentionally ignored: the writer is
// either os.Stdout or an in-memory buffer; neither surfaces actionable errors.
func (c *Config) logf(format string, args ...interface{}) {
	_, _ = fmt.Fprintf(c.stdout(), format+"\n", args...)
}

// Result captures the outcome of building a single entry.
type Result struct {
	Type      string
	Name      string
	Elapsed   time.Duration
	Artifacts []string // absolute paths of produced files
	Err       error
}

// Summary is the aggregate result of a build run.
type Summary struct {
	Results  []Result
	Total    int
	Failures int
}

// Print writes a human-readable summary to w.
// Write errors are intentionally ignored: the writer is always a terminal or
// in-memory buffer where write failures are not recoverable.
func (s *Summary) Print(w io.Writer) {
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "--- Build Summary ---")
	for _, r := range s.Results {
		status := "ok"
		if r.Err != nil {
			status = "FAILED"
		}
		_, _ = fmt.Fprintf(w, "  %-8s %-30s %s  (%s)\n",
			r.Type, r.Name, status, r.Elapsed.Round(time.Millisecond))
		if r.Err != nil {
			_, _ = fmt.Fprintf(w, "           error: %v\n", r.Err)
		}
		for _, a := range r.Artifacts {
			_, _ = fmt.Fprintf(w, "           artifact: %s\n", a)
		}
	}
	_, _ = fmt.Fprintf(w, "\nTotal: %d  Failures: %d\n", s.Total, s.Failures)
}

// HasFailures returns true when at least one entry failed.
func (s *Summary) HasFailures() bool { return s.Failures > 0 }

// LogErrors writes all failed results to the error log with full context.
func (s *Summary) LogErrors(logger *logging.BuildLogger, operation string) {
	if logger == nil {
		return
	}
	for _, r := range s.Results {
		if r.Err != nil {
			logger.Error(operation, r.Type, r.Name, r.Err, "")
		}
	}
}

// dirs returns the canonical sub-directories under BuildRoot.
type dirs struct {
	sources  string
	repos    string
	bundles  string
	wheels   string
	binaries string
	aptRepo  string
	gomod    string
	charts   string
	npm      string
}

func buildDirs(root string) dirs {
	return dirs{
		sources:  filepath.Join(root, "sources"),
		repos:    filepath.Join(root, "repos"),
		bundles:  filepath.Join(root, "bundles"),
		wheels:   filepath.Join(root, "wheels"),
		binaries: filepath.Join(root, "binaries"),
		aptRepo:  filepath.Join(root, "apt-repo"),
		gomod:    filepath.Join(root, "gomod"),
		charts:   filepath.Join(root, "charts"),
		npm:      filepath.Join(root, "npm"),
	}
}

// mkdirAll creates a directory and all parents, returning an error on failure.
func mkdirAll(path string) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", path, err)
	}
	return nil
}

// runCmd executes a command, streaming its combined output to out.
// The command's working directory is set to dir when non-empty.
func runCmd(out io.Writer, dir string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

// runCmdCapture runs a command and returns its combined output as a string.
func runCmdCapture(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// StageStatus reports which pipeline stages have been completed for a given
// manifest entry by inspecting the filesystem. All fields default to false.
type StageStatus struct {
	// Fetched is true when the fetch stage output is present on disk.
	Fetched bool
	// Built is true when the build stage output is present on disk.
	Built bool
	// Packaged is true when the package stage output is present on disk.
	Packaged bool
}

// ArtifactPath pairs a local filesystem path with its target S3 object key.
// Used by the upload and sync commands to resolve per-entry upload targets.
type ArtifactPath struct {
	// Local is the absolute path on disk.
	Local string
	// S3Key is the key within the bucket (no leading slash).
	S3Key string
}

// MergeSummaries merges an arbitrary slice of Summary pointers into one.
// Nil entries are silently skipped. This is the exported variant of the
// package-internal mergeSummaries for use by command-layer pipeline helpers.
func MergeSummaries(ss ...*Summary) *Summary {
	out := &Summary{}
	for _, s := range ss {
		if s == nil {
			continue
		}
		out.Results = append(out.Results, s.Results...)
		out.Total += s.Total
		out.Failures += s.Failures
	}
	return out
}
