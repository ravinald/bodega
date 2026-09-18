package builder

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// chartMetadata is the part of a chart's own Chart.yaml bodega publishes back
// to a client: what the archive declares itself to be, as opposed to what the
// manifest entry says it is.
type chartMetadata struct {
	Name       string `yaml:"name"`
	Version    string `yaml:"version"`
	AppVersion string `yaml:"appVersion"`
}

// chartYAMLMaxBytes bounds the one archive entry this reads. A .tgz is
// attacker-supplied as far as this process is concerned — it arrived over the
// network from a URL an entry named — and a tar member declares no length the
// reader can trust, so the read is capped rather than sized from the header.
const chartYAMLMaxBytes = 1 << 20

// errChartYAMLMissing is an archive with no Chart.yaml at its root: not a helm
// chart at all, whatever the URL served.
var errChartYAMLMissing = errors.New("the archive holds no Chart.yaml at its root")

// errChartYAMLUnparseable is a Chart.yaml that exists and says nothing usable.
// Kept apart from the missing case because the two send an operator to
// different places: one to the URL, the other to the chart's author.
var errChartYAMLUnparseable = errors.New("the Chart.yaml in the archive declares no version this can read")

// readChartMetadata reads Chart.yaml out of a packaged chart.
//
// Root-level only: a chart vendors its dependencies under charts/, each with a
// Chart.yaml of its own, and a subchart's version is not the archive's.
func readChartMetadata(tgzPath string) (chartMetadata, error) {
	base := filepath.Base(tgzPath)

	f, err := os.Open(tgzPath) //nolint:gosec // the path is the fetch's own destination
	if err != nil {
		return chartMetadata{}, err
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return chartMetadata{}, fmt.Errorf("%s is not a gzip stream: %w", base, err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return chartMetadata{}, fmt.Errorf("%s: %w", base, errChartYAMLMissing)
		}
		if err != nil {
			return chartMetadata{}, fmt.Errorf("%s: reading the archive: %w", base, err)
		}
		if hdr.Typeflag != tar.TypeReg || !isRootChartYAML(hdr.Name) {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tr, chartYAMLMaxBytes+1))
		if err != nil {
			return chartMetadata{}, fmt.Errorf("%s: reading Chart.yaml: %w", base, err)
		}
		if len(data) > chartYAMLMaxBytes {
			return chartMetadata{}, fmt.Errorf("%s: Chart.yaml is over %d bytes: %w",
				base, chartYAMLMaxBytes, errChartYAMLUnparseable)
		}

		var meta chartMetadata
		if err := yaml.Unmarshal(data, &meta); err != nil {
			return chartMetadata{}, fmt.Errorf("%s: %w (%v)", base, errChartYAMLUnparseable, err)
		}
		if strings.TrimSpace(meta.Version) == "" {
			return chartMetadata{}, fmt.Errorf("%s: %w", base, errChartYAMLUnparseable)
		}
		meta.Version = strings.TrimSpace(meta.Version)
		return meta, nil
	}
}

// isRootChartYAML reports whether a tar entry is the chart's own Chart.yaml.
// helm packages as <chart>/Chart.yaml; some producers prefix ./ and some drop
// the directory, and a subchart sits two levels further down.
func isRootChartYAML(name string) bool {
	rel := strings.TrimPrefix(filepath.ToSlash(name), "./")
	rel = strings.Trim(rel, "/")
	return filepath.Base(rel) == "Chart.yaml" && strings.Count(rel, "/") <= 1
}

// verifyHelmChartVersion refuses an archive whose Chart.yaml names a release
// other than the one the entry pins.
//
// The archive filename, the index.yaml entry and the /helm/charts object key
// are all rendered from ve.Version, so an entry whose version and url name
// different releases publishes a consistent-looking chart with another
// release's body inside it. Nothing downstream can see that: a client asking
// for the pinned version gets exactly what it asked for by every name bodega
// prints, and only the templates differ.
//
// An entry naming no version pins nothing, so there is nothing to contradict.
func verifyHelmChartVersion(tgzPath, chart, pin string) error {
	pin = strings.TrimSpace(pin)
	if pin == "" {
		return nil
	}
	meta, err := readChartMetadata(tgzPath)
	if err != nil {
		return fmt.Errorf("helm/%s pinned at %s: %w", chart, pin, err)
	}
	if !sameChartVersion(meta.Version, pin) {
		return fmt.Errorf("helm/%s: the manifest pins %s and the Chart.yaml inside %s declares %s",
			chart, pin, filepath.Base(tgzPath), meta.Version)
	}
	return nil
}

// sameChartVersion compares a pin with a chart's declared version. helm treats
// a leading v as decoration on an otherwise-semver string, so an entry pinning
// v6.7.0 against a chart declaring 6.7.0 is agreement rather than the
// substitution this exists to catch.
func sameChartVersion(declared, pin string) bool {
	return strings.TrimPrefix(declared, "v") == strings.TrimPrefix(pin, "v")
}
