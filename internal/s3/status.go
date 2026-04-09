package s3

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/scaleapi/bodega/internal/manifest"
)

// EntryStatus describes one manifest entry compared against S3.
type EntryStatus struct {
	Type   string
	Name   string
	S3Key  string
	InS3   bool
	Frozen bool
	ETag   string
	SizeS3 int64
}

// CheckStatus compares the local manifests against S3 and returns a per-entry
// status report. Missing entries are marked InS3=false.
func CheckStatus(ctx context.Context, client *Client, store *manifest.Store, types []string) ([]EntryStatus, error) {
	var statuses []EntryStatus

	for _, t := range types {
		var err error
		switch t {
		case manifest.TypeBinary:
			s, e := checkBinaryStatus(ctx, client, store)
			statuses = append(statuses, s...)
			err = e
		case manifest.TypeGit:
			s, e := checkGitStatus(ctx, client, store)
			statuses = append(statuses, s...)
			err = e
		case manifest.TypeApt:
			s, e := checkAptStatus(ctx, client, store)
			statuses = append(statuses, s...)
			err = e
		case manifest.TypePypi:
			s, e := checkPypiStatus(ctx, client, store)
			statuses = append(statuses, s...)
			err = e
		case manifest.TypeGomod:
			s, e := checkGomodStatus(ctx, client, store)
			statuses = append(statuses, s...)
			err = e
		case manifest.TypeHelm:
			s, e := checkHelmStatus(ctx, client, store)
			statuses = append(statuses, s...)
			err = e
		case manifest.TypeNpm:
			s, e := checkNpmStatus(ctx, client, store)
			statuses = append(statuses, s...)
			err = e
		}
		if err != nil {
			return statuses, err
		}
	}

	return statuses, nil
}

func checkBinaryStatus(ctx context.Context, client *Client, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, e := range store.Binary {
		filename := e.Filename
		if filename == "" {
			filename = lastSegment(e.URL)
		}
		// Path: binaries/<name>/<version>/<filename> or binaries/<name>/<filename>
		var key string
		if e.Version != "" {
			key = fmt.Sprintf("binaries/%s/%s/%s", e.Name, e.Version, filename)
		} else {
			key = fmt.Sprintf("binaries/%s/%s", e.Name, filename)
		}
		s3stat, err := client.HeadObject(ctx, key)
		if err != nil {
			return out, err
		}
		out = append(out, EntryStatus{
			Type:   manifest.TypeBinary,
			Name:   e.VersionedName(),
			S3Key:  key,
			InS3:   s3stat.Exists,
			Frozen: e.Frozen,
			ETag:   s3stat.ETag,
			SizeS3: s3stat.Size,
		})
	}
	return out, nil
}

func checkGitStatus(ctx context.Context, client *Client, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, e := range store.Git {
		ext := ".bundle"
		if e.IsRelease() {
			ext = ".tar.gz"
		}
		sn := strings.ReplaceAll(e.Name, "/", "--")
		key := fmt.Sprintf("repos/%s/%s-%s%s", sn, sn, e.Ref, ext)
		s3stat, err := client.HeadObject(ctx, key)
		if err != nil {
			return out, err
		}
		out = append(out, EntryStatus{
			Type:   manifest.TypeGit,
			Name:   e.VersionedName(),
			S3Key:  key,
			InS3:   s3stat.Exists,
			Frozen: e.Frozen,
			ETag:   s3stat.ETag,
			SizeS3: s3stat.Size,
		})
	}
	return out, nil
}

func checkAptStatus(ctx context.Context, client *Client, store *manifest.Store) ([]EntryStatus, error) {
	// The apt repository is uploaded as a directory; check for the Release file.
	key := "packages/apt/dists/noble/Release"
	s3stat, err := client.HeadObject(ctx, key)
	if err != nil {
		return nil, err
	}
	var out []EntryStatus
	for _, e := range store.Apt {
		out = append(out, EntryStatus{
			Type:   manifest.TypeApt,
			Name:   e.VersionedName(),
			S3Key:  key,
			InS3:   s3stat.Exists,
			Frozen: e.Frozen,
			ETag:   s3stat.ETag,
			SizeS3: s3stat.Size,
		})
	}
	return out, nil
}

func checkPypiStatus(ctx context.Context, client *Client, store *manifest.Store) ([]EntryStatus, error) {
	// Versioned path: pypi/wheels/<version>/MANIFEST.sha256
	// Unversioned fallback: pypi/wheels/MANIFEST.sha256
	var key string
	if store.Pypi.Version != "" {
		key = fmt.Sprintf("pypi/wheels/%s/MANIFEST.sha256", store.Pypi.Version)
	} else {
		key = "pypi/wheels/MANIFEST.sha256"
	}
	s3stat, err := client.HeadObject(ctx, key)
	if err != nil {
		return nil, err
	}
	name := "wheels"
	if store.Pypi.Version != "" {
		name = "wheels@" + store.Pypi.Version
	}
	return []EntryStatus{
		{
			Type:   manifest.TypePypi,
			Name:   name,
			S3Key:  key,
			InS3:   s3stat.Exists,
			Frozen: store.Pypi.Frozen,
			ETag:   s3stat.ETag,
			SizeS3: s3stat.Size,
		},
	}, nil
}

func checkGomodStatus(ctx context.Context, client *Client, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, e := range store.Gomod {
		key := fmt.Sprintf("gomod/%s/@v/%s.zip", e.Name, e.Version)
		s3stat, err := client.HeadObject(ctx, key)
		if err != nil {
			return out, err
		}
		out = append(out, EntryStatus{
			Type:   manifest.TypeGomod,
			Name:   e.VersionedName(),
			S3Key:  key,
			InS3:   s3stat.Exists,
			Frozen: e.Frozen,
			ETag:   s3stat.ETag,
			SizeS3: s3stat.Size,
		})
	}
	return out, nil
}

func checkHelmStatus(ctx context.Context, client *Client, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, e := range store.Helm {
		key := fmt.Sprintf("charts/%s-%s.tgz", e.Name, e.Version)
		s3stat, err := client.HeadObject(ctx, key)
		if err != nil {
			return out, err
		}
		out = append(out, EntryStatus{
			Type:   manifest.TypeHelm,
			Name:   e.VersionedName(),
			S3Key:  key,
			InS3:   s3stat.Exists,
			Frozen: e.Frozen,
			ETag:   s3stat.ETag,
			SizeS3: s3stat.Size,
		})
	}
	return out, nil
}

func checkNpmStatus(ctx context.Context, client *Client, store *manifest.Store) ([]EntryStatus, error) {
	var out []EntryStatus
	for _, e := range store.Npm {
		key := fmt.Sprintf("npm/%s/%s-%s.tgz", e.Name, e.Name, e.Version)
		s3stat, err := client.HeadObject(ctx, key)
		if err != nil {
			return out, err
		}
		out = append(out, EntryStatus{
			Type:   manifest.TypeNpm,
			Name:   e.VersionedName(),
			S3Key:  key,
			InS3:   s3stat.Exists,
			Frozen: e.Frozen,
			ETag:   s3stat.ETag,
			SizeS3: s3stat.Size,
		})
	}
	return out, nil
}

// PrintStatus writes a formatted status table to out.
func PrintStatus(out io.Writer, statuses []EntryStatus) {
	_, _ = fmt.Fprintf(out, "\n%-8s %-30s %-6s %-6s %s\n",
		"TYPE", "NAME", "IN_S3", "FROZEN", "S3_KEY")
	_, _ = fmt.Fprintf(out, "%s\n", repeat("-", 80))
	for _, s := range statuses {
		inS3 := "no"
		if s.InS3 {
			inS3 = "yes"
		}
		frozen := ""
		if s.Frozen {
			frozen = "yes"
		}
		_, _ = fmt.Fprintf(out, "%-8s %-30s %-6s %-6s %s\n",
			s.Type, s.Name, inS3, frozen, s.S3Key)
	}
}

func lastSegment(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}

func repeat(c string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += c
	}
	return out
}
