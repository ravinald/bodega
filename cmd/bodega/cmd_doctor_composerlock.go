package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/ravinald/bodega/internal/host"
)

// composerLock is the part of a composer.lock that decides where `composer
// install` fetches from. Composer reads each archive from the dist.url the
// lock records and never asks the global repository, so a lock written
// against Packagist downloads around bodega however config.json is set.
type composerLock struct {
	Packages    []composerLockPackage `json:"packages"`
	PackagesDev []composerLockPackage `json:"packages-dev"`
}

type composerLockPackage struct {
	Name string `json:"name"`
	Dist *struct {
		URL string `json:"url"`
	} `json:"dist"`
}

// checkComposerLock reports where the lock at path sends `composer install`.
// baseURL is the bodega this host reads from; a dist.url counts as bodega's
// only at that origin and under its /composer/ route.
func checkComposerLock(path, baseURL string) (host.Finding, error) {
	f := host.Finding{Check: "composer-lock"}
	base, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if baseURL == "" || err != nil || base.Host == "" {
		return f, fmt.Errorf("--composer-lock %s: no bodega base URL to compare the lock's dist.url entries with; pass --url or set public_url in the config file", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return f, fmt.Errorf("--composer-lock: %w", err)
	}
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return f, fmt.Errorf("--composer-lock %s is not JSON composer can read: %w; pass the project's composer.lock", path, err)
	}
	route := base.Path + "/composer/"

	total := 0
	foreign := map[string]int{}
	for _, p := range slices.Concat(lock.Packages, lock.PackagesDev) {
		if p.Dist == nil || p.Dist.URL == "" {
			continue
		}
		total++
		u, err := url.Parse(p.Dist.URL)
		switch {
		case err != nil || u.Host == "":
			foreign["an unparseable dist.url"]++
		case !sameOrigin(u, base):
			foreign[strings.ToLower(u.Host)]++
		case !strings.HasPrefix(u.Path, route):
			foreign[strings.ToLower(u.Host)+" outside "+route]++
		}
	}

	if len(foreign) == 0 {
		f.Status = host.StatusOK
		f.Detail = fmt.Sprintf("%s: all %d dist.url entries are at %s%s", path, total, base.Host, route)
		return f, nil
	}
	hosts := make([]string, 0, len(foreign))
	off := 0
	for h, n := range foreign {
		hosts = append(hosts, h)
		off += n
	}
	slices.SortFunc(hosts, func(a, b string) int {
		return cmp.Or(cmp.Compare(foreign[b], foreign[a]), cmp.Compare(a, b))
	})
	named := make([]string, len(hosts))
	for i, h := range hosts {
		named[i] = fmt.Sprintf("%s (%d)", h, foreign[h])
	}
	f.Status = host.StatusWarn
	f.Detail = fmt.Sprintf("%s: %d of %d packages fetch from %s; composer install reads the lock's dist.url and bypasses bodega",
		path, off, total, strings.Join(named, ", "))
	f.Remediation = "with bodega configured (bodega doctor --configure composer --apply), run composer update --lock in the project, " +
		"which rewrites each dist.url to bodega and changes no locked version, then review and commit the rewritten composer.lock"
	return f, nil
}

// sameOrigin compares scheme, host and port, with an omitted port read as the
// scheme's default, so https://h and https://h:443 are one origin.
func sameOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if strings.EqualFold(u.Scheme, "http") {
			return "80"
		}
		return "443"
	}
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		port(a) == port(b)
}
