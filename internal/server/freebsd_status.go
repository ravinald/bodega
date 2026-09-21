package server

import (
	"context"
	"net/http"
	"sort"

	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pkgrepos"
)

// freebsdStatus is what the running server knows about how pkg clients reach
// it, and nothing else in the tree can derive: which repositories answer, the
// URL in force, whether a catalogue signing key is loaded, and — per
// repository — whether it is mirrored or generated, which decides the whole
// trust half of the client stanza.
//
// The emitters read this rather than composing a stanza of their own, for the
// reason aptStatus exists: a TUI reading the config file and a web page
// reading its own origin each guessed at one of those facts and each guessed
// wrong.
type freebsdStatus struct {
	// Signed reports a loaded key, which applies to generated repositories
	// alone: bodega signs what bodega generates and never a mirror.
	Signed      bool   `json:"signed"`
	Fingerprint string `json:"fingerprint,omitempty"`

	// KeyError is a key file that is present and will not load. It is not the
	// same state as no key: the operator installed one and believes the
	// repository is signed, and every generated catalogue refuses until it
	// loads.
	//
	// It quotes a load failure that names the key file by path, so
	// handleAPIStatus blanks it for a caller outside admin_permit_cidr,
	// beside spool.Dir. The gate is there rather than here because
	// freeBSDStatusFor composes this struct for callers holding no request
	// at all, and one that read a nil request would have to assume an
	// answer.
	KeyError string `json:"key_error,omitempty"`

	PublicURL string `json:"public_url"`

	// Repos is one rendered configuration per repository and ABI, sorted by
	// repository then ABI so a diff between two status reads is readable.
	Repos []pkgrepos.Repo `json:"repos"`

	// Refused names an entry the renderer would not emit for, with the
	// reason. Reported rather than dropped: an absent stanza and a refused
	// one look identical to a client reading the list, and the second one is
	// a manifest an operator has to fix.
	Refused []freebsdRefused `json:"refused,omitempty"`
}

// freebsdRefused is one entry no stanza could be rendered for.
type freebsdRefused struct {
	Repo  string `json:"repo"`
	ABI   string `json:"abi"`
	Error string `json:"error"`
}

// RepoFor returns the rendered configuration for one repository and ABI.
//
// Exported off the status struct rather than looked up by the caller, because
// the match is on two fields and a consumer matching on the repository alone
// serves a FreeBSD:13 host the stanza rendered for FreeBSD:14 — same URL,
// wrong override.
func (f freebsdStatus) RepoFor(repo, abi string) *pkgrepos.Repo {
	for i := range f.Repos {
		if f.Repos[i].Repo == repo && f.Repos[i].ABI == abi {
			return &f.Repos[i]
		}
	}
	return nil
}

// freeBSDStatusFor renders one client configuration per freebsd entry, with
// the public URL resolved for the request that asked.
//
// One per version entry rather than one per package. A freebsd package is a
// repository and its versions are the ABI directories under it, each with its
// own mode, URL and generated flag: reading any of those off the first entry
// would hand a FreeBSD:13 client the FreeBSD:14 entry's answer, and the two
// are configured apart precisely so they can differ.
//
// A hidden package or ABI is left out. hide is the quarantine control and the
// route already 404s it, so publishing a stanza for one would hand an
// operator configuration for a repository that answers nothing.
func (s *Server) freeBSDStatusFor(r *http.Request) freebsdStatus {
	out := freebsdStatus{PublicURL: s.publicBase(r), Repos: []pkgrepos.Repo{}}
	base := pkgrepos.State{PublicURL: out.PublicURL, LocalScheme: s.localScheme()}

	if sign := s.pkgSign.Load(); sign != nil {
		switch {
		case sign.signer != nil:
			out.Signed = true
			out.Fingerprint = sign.fingerprint
			base.Fingerprint = sign.fingerprint
		case sign.err != nil:
			out.KeyError = sign.err.Error()
		}
	}

	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}
	for _, name := range s.store.ListPackages(manifest.TypeFreeBSD) {
		pm, _ := s.store.GetPackage(ctx, manifest.TypeFreeBSD, name)
		if pm == nil || isPackageHidden(pm) {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.Hidden || ve.Version == "" || ve.Version == "*" {
				continue
			}
			one := base
			one.ABI, one.Repo = ve.Version, pm.Name
			one.Generated, one.Upstream = ve.Generated, ve.URL
			one.Proxy = ve.EffectiveMode() == manifest.ModeProxy
			rendered, err := pkgrepos.Render(one)
			if err != nil {
				out.Refused = append(out.Refused,
					freebsdRefused{Repo: pm.Name, ABI: ve.Version, Error: err.Error()})
				continue
			}
			out.Repos = append(out.Repos, rendered)
		}
	}
	sort.Slice(out.Repos, func(i, j int) bool {
		if out.Repos[i].Repo != out.Repos[j].Repo {
			return out.Repos[i].Repo < out.Repos[j].Repo
		}
		return out.Repos[i].ABI < out.Repos[j].ABI
	})
	sort.Slice(out.Refused, func(i, j int) bool {
		if out.Refused[i].Repo != out.Refused[j].Repo {
			return out.Refused[i].Repo < out.Refused[j].Repo
		}
		return out.Refused[i].ABI < out.Refused[j].ABI
	})
	return out
}
