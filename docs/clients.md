# Connecting clients

This page tells you, for each client a host runs, what to change so the client fetches through bodega, how to confirm it did, and what goes wrong.
Every example uses `https://bodega.example` for your `public_url`.

`bodega doctor --configure` writes everything on this page for you, from the plan [`GET /client/plan`](usage.md#client-plan-and-per-system-files) returns for the host.
Its flags, the checks it runs and how it merges into files you already have are in the [`bodega doctor` reference](usage.md#bodega-doctor---write-credentials---token-token---url-url---configure-systems---apply---suite-codename---abi-abi---release-n---quiet-ubuntu-pro---quiet-os-callers---restore-ubuntu-pro---restore-os-callers---restore-apt-sources---ntp-server-host---write-apt-sources---write-pkg-repo---allow-plaintext).
A host with no `bodega` binary runs the [setup script](usage.md#setup-script) instead, which applies the same plan.
Run either without `--apply` first: it prints a diff of each file and writes nothing.

The server has to know the host before it serves a plan.
Bind its address or token on the server first, `bodega identity bind cidr 192.0.2.10/32 web-01`, or every `/client/` request answers `403`.

Each by-hand block is the file `bodega doctor` writes for `https://bodega.example`, byte for byte.
A test renders each one again and fails when this page and the renderer disagree.

Every check uses [`bodega audit events`](usage.md#bodega-audit-events-flags) on the server.
A package a client downloaded is a `serve_fetch` row naming its type; a fetch that never reached bodega leaves no row at all, which is the point of looking.
`--client` takes the host's address, and `--identity` takes the name a binding gave it.

## apt

Run it as root, naming the codename when the server serves more than one:

```bash
sudo bodega doctor --configure apt --suite noble --apply --url https://bodega.example
```

Add `--archive {key}` once per vendor repository the host also reads, as [Vendor repositories](#vendor-repositories) describes.

### Files

`/etc/apt/sources.list.d/bodega.sources` holds one stanza for a mirrored codename and its pockets.
It carries neither `Signed-By:` nor `Trusted: yes`, because the archive's own `InRelease` arrives signed and apt checks it against the distribution keyring already on the host:

<!-- clientconf: apt Sources -->

```text
Types: deb
URIs: https://bodega.example/apt/
Suites: noble noble-updates noble-security
Components: main restricted universe multiverse
```

A suite bodega generates and signs itself adds `Signed-By: /etc/apt/keyrings/bodega-archive-keyring.gpg`, and doctor fetches that keyring from `/apt/bodega-archive-keyring.gpg`; see [Signing the apt repository](usage.md#signing-the-apt-repository).

doctor also disables the distribution's own sources, an `Enabled: no` line in each deb822 stanza naming a public archive and `#` before each such one-line entry, so apt cannot fetch around bodega.
`sudo bodega doctor --restore-apt-sources` puts them back.

### Vendor repositories

A vendor repository is mirrored on the server as an `apt_upstreams` codename with `signing_key_url` and `signing_key_fingerprint`, which [Vendor archives](usage.md#vendor-archives) covers.
Grafana's, mirrored as `stable`, reaches a host with `--archive stable`:

```bash
sudo bodega doctor --configure apt --suite noble --archive stable --apply --url https://bodega.example
```

That adds the vendor's key at `/etc/apt/keyrings/bodega-stable.asc`, fetched from `/apt/keys/stable.asc` and checked against the configured fingerprint, and a stanza beside the host's own at `/etc/apt/sources.list.d/bodega-stable.sources` whose `Signed-By:` names that key.

Many vendors publish their suite under the distribution's own codename: Tailscale's and Docker's Ubuntu repositories each have a `noble`, and so does every Launchpad PPA.
A bare key names one suite per server, so the server mirrors the vendor's as `{archive}/{codename}`, which it serves under its own root, `/apt/{archive}/`.
See [One codename in two archives](usage.md#one-codename-in-two-archives).

```json
"apt_upstreams": {
  "noble":           [{"url": "https://archive.ubuntu.com/ubuntu"}],
  "noble-updates":   [{"url": "https://archive.ubuntu.com/ubuntu"}],
  "noble-security":  [{"url": "https://security.ubuntu.com/ubuntu"}],
  "tailscale/noble": [{"url": "https://pkgs.tailscale.com/stable/ubuntu", "components": ["main"],
                       "signing_key_url": "https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg",
                       "signing_key_fingerprint": "<the 40 hex digits Tailscale publishes>"}]
}
```

Once two archives mirror `noble`, a bare `noble` names neither of them, so the host names Ubuntu's as `/noble`:

```bash
sudo bodega doctor --configure apt --suite /noble --archive tailscale/noble --apply --url https://bodega.example
```

The vendor stanza goes to `/etc/apt/sources.list.d/bodega-tailscale_noble.sources`, and the vendor key, served at `/apt/keys/tailscale/noble.asc`, to `/etc/apt/keyrings/bodega-tailscale_noble.asc`:

<!-- clientconf: apt Vendor archive sources -->

```text
Types: deb
URIs: https://bodega.example/apt/tailscale/
Suites: noble
Components: main
Signed-By: /etc/apt/keyrings/bodega-tailscale_noble.asc
```

### Check

Run `apt-get update` on the host, then on the server:

```bash
bodega audit events --type serve_fetch --pkg-type apt --client 192.0.2.10
```

Each row names the path under `/apt/` the host fetched: `dists/noble/InRelease`, then the indexes and each `pool/` file it installed.

### Traps

- **A bare codename after a vendor mirrors the same one.** `--suite noble` and `codename=noble` are refused once `tailscale/noble` exists.
  You see `apt codename "noble" is mirrored in 2 archives, so it names none of them: write one of /noble, tailscale/noble`.
  Write `--suite /noble`.
- **A vendor stanza for the host's own suite.** Two stanzas naming one root and suite with different `Signed-By:` values stop every update.
  You see `Conflicting values set for option Signed-By` from `apt-get update`, and doctor refuses the `--archive` before it writes.
- **A component the stanza leaves out.** The `Components:` line comes from the `apt_upstreams` entry, or Ubuntu's four when it names none, which is wrong for most vendors.
  You see `apt-get update` succeed and `apt-get install` fail with `404 Not Found` on a `pool/` path.
  Set `components` on the entry.
- **`[trusted=yes]` or `Signed-By:` added to a mirrored codename.** The first discards a valid signature; the second points apt at bodega's key, which signed nothing in that tree.
  You see `NO_PUBKEY` or `The following signatures couldn't be verified` on the second form, and nothing at all on the first.
- **The Ubuntu Pro apt hook.** It reaches `esm.ubuntu.com` on every update whatever the sources say.
  You see each `apt-get update` stall on resolver timeouts on an egress-locked host.
  See [Applications that fetch on their own](#applications-that-fetch-on-their-own).

## dnf and yum

doctor reads `ID` and `VERSION_ID` from `/etc/os-release` and the server maps them to the repositories it serves for that release:

```bash
sudo bodega doctor --configure rpm --apply --url https://bodega.example
```

yum on these releases is dnf under its old name, so the same file serves both.

### Files

`/etc/yum.repos.d/bodega.repo` holds one section per repository the host's release reads and `rpm_upstreams` configures.
For Rocky Linux 9, with `rocky-baseos`, `rocky-appstream` and `epel` configured:

<!-- clientconf: rpm dnf repositories (rocky 9) -->

```ini
[bodega-rocky-baseos]
name=bodega rocky-baseos
baseurl=https://bodega.example/rpm/rocky-baseos/$releasever/$basearch/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-bodega file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9

[bodega-rocky-appstream]
name=bodega rocky-appstream
baseurl=https://bodega.example/rpm/rocky-appstream/$releasever/$basearch/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-bodega file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9

[bodega-epel]
name=bodega epel
baseurl=https://bodega.example/rpm/epel/$releasever/$basearch/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-bodega file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-9
```

`/etc/pki/rpm-gpg/RPM-GPG-KEY-bodega` is bodega's key as `/rpm/bodega.gpg` serves it.
bodega signs `repomd.xml` with it; packages keep the vendor's signature, which is why each `gpgkey` line names the vendor's key beside bodega's.
doctor then runs `dnf config-manager --set-disabled` on each vendor repository the file replaces.
See [RPM repositories](usage.md#client-configuration) for the release table.

### Check

Run `dnf makecache` on the host, then:

```bash
bodega audit events --type serve_fetch --pkg-type rpm --client 192.0.2.10
```

### Traps

- **A release the table does not name.** The plan changes nothing and the skip names the `ID` and `VERSION_ID` the server read.
  You see doctor refuse with `rpm (skip):` and that reason, nothing written, and the vendor repositories still enabled.
- **A repository the table maps that `rpm_upstreams` lacks.** It is left out of `bodega.repo` and the host's own copy stays enabled.
  You see the plan's note naming it, and the `dnf-repos` row warning that it fetches around bodega.
- **EPEL without `epel-release`.** The EPEL key file comes from that package.
  You see `GPG check FAILED` on the first EPEL package until it is installed.
- **A vendor repository enabled again.** By hand, or by replacing its `.repo` with the `.rpmnew` an update left.
  You see the `dnf-repos` row in `bodega doctor` warn again.

## FreeBSD pkg

The server renders this file, since the tags it overrides and the key it trusts depend on facts only the running instance holds:

```bash
sudo bodega doctor --configure freebsd --abi FreeBSD:15:amd64 --apply --url https://bodega.example
```

`bodega doctor --write-pkg-repo` writes the same file on its own.

### Files

`/usr/local/etc/pkg/repos/bodega.conf`, for a FreeBSD 15 host reading a mirror of `latest`:

<!-- clientconf: freebsd Repository conf -->

```text
# bodega pkg repository. Install as /usr/local/etc/pkg/repos/bodega.conf.
#
# url carries a plain scheme with mirror_type: none, never the pkg+https
# next door in /etc/pkg/FreeBSD.conf: pkg+ means SRV mirror discovery, where
# the client resolves _https._tcp for the host and expects a record set, and
# bodega is one host that publishes none.
#
# ${ABI} is literal. pkg substitutes the running host's own ABI, so this file
# is correct on every architecture bodega mirrors. It was written for a
# FreeBSD 15 host, which is what the overrides below are named for.
#
# pkg merges repository definitions by tag across /etc/pkg/ and
# /usr/local/etc/pkg/repos/, so the overrides have to name the tags this
# release actually defines. One that names the wrong tag leaves the upstream
# repository enabled beside this one, and nothing in `pkg update` output says
# so: the host keeps fetching from the internet. Confirm with `pkg -vv`.
#
# fingerprints names the trust store every FreeBSD host already ships.
# bodega copies these bytes from upstream without transforming them, so
# FreeBSD's own signature arrives inside the catalogue archive and no key
# of bodega's is in this path. The exception is a base_release_<n>
# repository built for FreeBSD 15 or later, which release engineering
# signs against the pkgbase store; upstream calls this one something else.
#
# This repository publishes the paths its catalogue names and this server
# fetches nothing under it from upstream: every request stops here, and a
# package it does not hold is a 404 rather than a fetch from the internet.
# Two terms decide that and neither is in this file: this repository is not
# served in proxy mode, and this server's proxy_cache_enabled is off.
# Change either and a miss outside meta.conf, packagesite.pkg and data.pkg
# is fetched from upstream, cached and served under this repository's name,
# while this file goes on saying it is not. Re-run `bodega doctor
# --write-pkg-repo` when one of them moves.
#
# `pkg bootstrap` does not work against this repository. It fetches
# Latest/pkg.pkg and Latest/pkg.pkg.sig and nothing else, a catalogue
# never names that pair, and nothing here falls through to upstream to get
# from. Install pkg from upstream before switching a host over.

FreeBSD-ports: { enabled: no }
FreeBSD-ports-kmods: { enabled: no }
FreeBSD-base: { enabled: no }

bodega-latest: {
  url: "https://bodega.example/freebsd/${ABI}/latest",
  mirror_type: "none",
  signature_type: "fingerprints",
  fingerprints: "/usr/share/keys/pkg",
  enabled: yes
}
```

A repository bodega generates rather than mirrors is signed by bodega's key, and its stanza names `/usr/local/etc/pkg/fingerprints/bodega`.
Deliver that fingerprint out of band: one fetched from the server it authenticates proves nothing.

### Check

Run `pkg -vv` and confirm the upstream tags read `enabled: no`, then `pkg update`, then on the server:

```bash
bodega audit events --type serve_fetch --pkg-type freebsd --client 192.0.2.10
```

### Traps

- **An override naming a tag the release does not define.** FreeBSD 15 split `FreeBSD` into `FreeBSD-ports`, `FreeBSD-ports-kmods` and `FreeBSD-base`.
  You see `pkg update` succeed while `pkg -vv` lists the upstream repository enabled beside bodega's.
  Pass `--release` when the host's release differs from the mirror's.
- **`pkg bootstrap`.** It fetches `Latest/pkg.pkg` and its signature, which no catalogue names.
  You see a `404` from bodega.
  Install pkg from upstream before switching the host over.
- **The wrong fingerprint store.** A mirror pointed at bodega's key, or a generated repository at FreeBSD's, fails every update.
  You see `No trusted public keys found` and 0 entries processed.

## FreeBSD ports distfiles

A port fetching its source tarball reads two sites from `make.conf`:

```bash
sudo bodega doctor --configure distfiles --apply --url https://bodega.example
```

### Files

`/etc/make.conf` gains both sites, because `MASTER_SITE_BACKUP` defaults to `distcache.FreeBSD.org` and is the last site the fetch tries:

<!-- clientconf: distfiles make.conf -->

```text
MASTER_SITE_OVERRIDE?= https://bodega.example/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/
MASTER_SITE_BACKUP?= https://bodega.example/distfiles/@${BODEGA_DISTFILES_ENV}/${DIST_SUBDIR}/
.include "/usr/local/etc/bodega-distfiles.mk"
```

`/usr/local/etc/bodega-distfiles.mk` is the client check the last line includes, fetched from `/distfiles/@environment.mk`.
It measures the build environment and sets `BODEGA_DISTFILES_ENV`, which the server checks before it admits a distfile.

### Check

Run `make fetch` in a port, then:

```bash
bodega audit events --type serve_fetch --pkg-type distfiles --client 192.0.2.10
```

Each row names the distfile as its `distinfo` line spells it, `pcpustat/1.6.tar.bz2`.
A refusal is a `denied` row under the same type.

### Traps

- **A server with no `distfiles_ports_tree`.** Every request answers `404`, and the port falls through to its own sites.
  You see the fetch succeed from the upstream site on an open host, and no row.
- **A restricted port.** A port that sets `RESTRICTED` or `NO_CDROM` withholds distribution.
  You see `451` from bodega and the fetch fall through to the port's own sites.
- **A `make.conf` assignment after the include.** The check sees only what is assigned above it.
  You see a `denied` row with reason `distfile_client`.

## pip

pip reads one global file; doctor writes it at the path pip searches on each system:

```bash
sudo bodega doctor --configure pypi --apply --url https://bodega.example
```

### Files

`/etc/pip.conf` on Linux and FreeBSD, `/Library/Application Support/pip/pip.conf` on macOS:

<!-- clientconf: pypi pip.conf -->

```ini
[global]
index-url = https://bodega.example/pypi/simple/
```

A plaintext `http://` base adds `trusted-host = {host}`, without which pip ignores the index.

### Check

Run `pip download --no-deps requests` on the host, then:

```bash
bodega audit events --type serve_fetch --pkg-type pypi --client 192.0.2.10
```

### Traps

- **`/usr/local/etc/pip.conf` on FreeBSD.** Nothing reads it, though the ports convention puts files there.
  You see pip fetch from PyPI with the file in place.
- **A file or variable read after the global one.** `~/.config/pip/pip.conf`, a virtualenv's `pip.conf` and `PIP_INDEX_URL` all win, and an `extra-index-url` sends a miss straight to the other index.
  You see the `pip-config` row in `bodega doctor` warn, naming the file.
- **An `http://` index with no `trusted-host`.** pip skips it.
  You see `No matching distribution found` for a package bodega holds.

## npm

npm reads the registry from the user's `.npmrc`, so run doctor as the user whose installs it is; as root it also writes the host-wide node-gyp file:

```bash
sudo bodega doctor --configure npm --apply --url https://bodega.example
```

### Files

`~/.npmrc`:

<!-- clientconf: npm .npmrc -->

```ini
registry=https://bodega.example/npm/
```

The trailing slash is what matches the `//bodega.example/npm/:_authToken=` line `bodega doctor --write-credentials` adds.

`/etc/profile.d/bodega-node.sh`, written only when the server has a `binary_upstreams` namespace in `open` mode whose URL is `https://nodejs.org/`, sends node-gyp's header download for native modules through bodega:

<!-- clientconf: npm node-gyp mirror -->

```sh
export NODEJS_ORG_MIRROR='https://bodega.example/binaries/nodejs/dist'
```

Run as a user instead, doctor writes `~/.config/environment.d/60-bodega-node.conf` holding the same line without `export`.

### Check

Run `npm view left-pad version` on the host, then:

```bash
bodega audit events --type serve_fetch --pkg-type npm --client 192.0.2.10
bodega audit events --type serve_fetch --pkg-type binary --client 192.0.2.10   # node-gyp's headers
```

### Traps

- **node-gyp left on nodejs.org.** The registry line does not cover the headers a native build fetches.
  You see node-gyp fail fetching headers from `nodejs.org` on a locked host, and the plan's note when the nodejs.org namespace is in `catalog` mode.
- **A system service that builds native modules.** Neither file reaches a systemd unit.
  You see the same node-gyp failure in a CI runner that works in a login shell; add `Environment=NODEJS_ORG_MIRROR=https://bodega.example/binaries/nodejs/dist` to the unit.
- **A project `.npmrc`.** It overrides the user's file, and doctor does not read it.
  You see the project install from the registry it names, with no row.

## Go modules

The go command reads its own env file on every run, so no shell profile changes:

```bash
bodega doctor --configure gomod --apply --url https://bodega.example
```

### Files

`~/.config/go/env` on Linux and FreeBSD, `~/Library/Application Support/go/env` on macOS, the file `go env -w` writes:

<!-- clientconf: gomod Go env -->

```text
GOPROXY=https://bodega.example/go
```

There is no `,direct` after it: with one, a module bodega does not hold is fetched from its VCS host.
`GOSUMDB` stays at its default, because bodega serves the checksum database through the same proxy.

### Check

Run `go mod download golang.org/x/mod@latest` on the host, then:

```bash
bodega audit events --type serve_fetch --pkg-type gomod --client 192.0.2.10
```

### Traps

- **`GOPROXY` in the environment.** It wins over the env file.
  You see the `goproxy-env` row in `bodega doctor` name the value the environment set.
- **`GOPRIVATE` or `GONOPROXY`.** A module matching either is fetched directly.
  You see `go: ... dial tcp: lookup github.com` on a locked host.
- **A `,direct` added back.** You see the `goproxy-env` row report it as a bypass.

## Cargo

A sparse registry is named in a file, not on the command line:

```bash
bodega doctor --configure cargo --apply --url https://bodega.example
```

### Files

`~/.cargo/config.toml`:

<!-- clientconf: cargo Cargo config -->

```toml
[source.crates-io]
replace-with = "bodega"

[source.bodega]
registry = "sparse+https://bodega.example/cargo/"
```

### Check

Run `cargo fetch` in a crate, then:

```bash
bodega audit events --type serve_fetch --pkg-type cargo --client 192.0.2.10
```

### Traps

- **A `[registries.bodega]` table alone.** It names a second registry and leaves crates.io as the source of every dependency.
  You see Cargo fetch from `index.crates.io` with the file in place.
- **A crate needing a named feature from a cataloged entry.** A generated index line declares `features: {}`.
  You see the crate resolve and download, then fail to compile.
- **The file under `sudo`.** It lands in root's home.
  You see the user's builds still reach crates.io; run doctor as that user.

## Maven

One run writes both Maven's and [Gradle](#gradle)'s files, as the user whose builds they are:

```bash
bodega doctor --configure maven --apply --url https://bodega.example
```

### Files

`~/.m2/settings.xml`, whose `<mirrors>` become bodega's alone; servers, profiles and every other setting in an existing file are kept:

<!-- clientconf: maven Maven settings.xml -->

```xml
<settings>
  <mirrors>
    <mirror>
      <id>bodega</id>
      <mirrorOf>*</mirrorOf>
      <url>https://bodega.example/maven/</url>
    </mirror>
  </mirrors>
</settings>
```

### Check

Run `mvn dependency:resolve` in a project, then:

```bash
bodega audit events --type serve_fetch --pkg-type maven --client 192.0.2.10
```

### Traps

- **The Maven wrapper.** `mvnw` downloads Maven from `distributionUrl` before reading `settings.xml`.
  You see `mvnw` fail before the build starts on a locked host.
  Point `.mvn/wrapper/maven-wrapper.properties` at `https://bodega.example/maven/org/apache/maven/apache-maven/{version}/apache-maven-{version}-bin.zip`; doctor prints the line and does not edit project files.
- **A repository bodega's upstream list does not cover.** `mirrorOf *` sends every repository to bodega, which asks `maven_upstreams` in order.
  You see `Could not find artifact` for one that lives only in a repository the server does not list.

## Gradle

Gradle's file comes from the same run as Maven's:

```bash
bodega doctor --configure maven --apply --url https://bodega.example
```

### Files

`~/.gradle/init.d/bodega.gradle`, bodega's own file, replaced whole on each run.
It removes every network repository a build names and adds bodega's:

<!-- clientconf: maven Gradle init script -->

```groovy
// Written by bodega doctor --configure maven, and replaced whole on every
// run. Every network repository a build names is removed, and bodega's added
// in its place, so a dependency or plugin bodega does not serve fails to
// resolve rather than resolving around it.
def bodegaUrl = 'https://bodega.example/maven/'

def keepRepository = { ArtifactRepository repo ->
    if (repo instanceof FlatDirectoryArtifactRepository) {
        return true
    }
    if (!(repo instanceof UrlArtifactRepository) || repo.url == null) {
        return false
    }
    repo.url.scheme == 'file' || (repo instanceof MavenArtifactRepository && repo.url.toString() == bodegaUrl)
}

def bodegaOnly = { RepositoryHandler repos, boolean add ->
    repos.all { ArtifactRepository repo ->
        if (!keepRepository(repo)) {
            repos.remove(repo)
        }
    }
    if (add) {
        repos.maven {
            name = 'bodega'
            url = bodegaUrl
        }
    }
}

def hasResolutionManagement = org.gradle.util.GradleVersion.current() >= org.gradle.util.GradleVersion.version('6.8')
def projectRepositories = true

beforeSettings { settings ->
    bodegaOnly(settings.buildscript.repositories, true)
    bodegaOnly(settings.pluginManagement.repositories, true)
    if (hasResolutionManagement) {
        bodegaOnly(settings.dependencyResolutionManagement.repositories, true)
    }
}

settingsEvaluated { settings ->
    if (hasResolutionManagement) {
        projectRepositories = settings.dependencyResolutionManagement.repositoriesMode.get().name() == 'PREFER_PROJECT'
    }
}

allprojects { project ->
    bodegaOnly(project.buildscript.repositories, true)
    bodegaOnly(project.repositories, projectRepositories)
}
```

### Check

Run `./gradlew dependencies` in a project, then:

```bash
bodega audit events --type serve_fetch --pkg-type maven --client 192.0.2.10
```

### Traps

- **The Gradle wrapper.** `gradlew` downloads Gradle from `distributionUrl` before any init script runs.
  You see `gradlew` fail downloading the distribution before the build starts.
  With a `binary_upstreams` namespace `gradle-dist` in `open` mode on `https://services.gradle.org/`, set `distributionUrl=https\://bodega.example/binaries/gradle-dist/distributions/gradle-{version}-bin.zip` in `gradle/wrapper/gradle-wrapper.properties`.
- **Plugins from the Gradle Plugin Portal.** The init script sends them to bodega too.
  You see `Plugin [id: '...'] was not found` unless `maven_upstreams` lists `https://plugins.gradle.org/m2`.

## RubyGems and Bundler

gem and Bundler read different files, and doctor writes both:

```bash
bodega doctor --configure rubygems --apply --url https://bodega.example
```

### Files

`~/.gemrc` replaces gem's source list, so a miss cannot go to rubygems.org:

<!-- clientconf: rubygems gem sources -->

```yaml
---
:sources:
- https://bodega.example/rubygems/
```

`~/.bundle/config` rewrites `https://rubygems.org` in every Gemfile to bodega without editing one:

<!-- clientconf: rubygems Bundler mirror -->

```yaml
---
BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/: "https://bodega.example/rubygems/"
```

### Check

Run `bundle install` in a project, then:

```bash
bodega audit events --type serve_fetch --pkg-type rubygems --client 192.0.2.10
```

### Traps

- **A Gemfile source other than rubygems.org.** The mirror setting rewrites that one URL.
  You see Bundler fetch a private or vendor source directly, with no row.
- **The files under `sudo`.** They land in root's home.
  You see the user's `bundle install` still reach rubygems.org.

## Composer

Composer reads `config.json` in its home, which doctor resolves the way Composer does:

```bash
bodega doctor --configure composer --apply --url https://bodega.example
```

### Files

`~/.config/composer/config.json` on Linux and `~/.composer/config.json` elsewhere, or `$COMPOSER_HOME/config.json`.
An existing file is merged: bodega's repository is added and `packagist.org` set `false`:

<!-- clientconf: composer Composer global config -->

```json
{
    "repositories": {
        "bodega": {
            "type": "composer",
            "url": "https://bodega.example/composer"
        },
        "packagist.org": false
    }
}
```

### Check

Run `composer install` in a project, then:

```bash
bodega audit events --type serve_fetch --pkg-type composer --client 192.0.2.10
```

### Traps

- **A committed `composer.lock`.** `composer install` fetches each archive from the `dist.url` the lock recorded, never reading the global repository.
  You see downloads from `api.github.com`, or a failure on a locked host.
  `bodega doctor --composer-lock composer.lock --url https://bodega.example` counts them, and `composer update --lock` rewrites the URLs.
- **A source-only release.** A version with no `dist` is cloned from its `source` URL.
  You see `git clone` reach GitHub directly.

## Helm

helm reads one `repositories.yaml`:

```bash
bodega doctor --configure helm --apply --url https://bodega.example
```

### Files

`~/.config/helm/repositories.yaml` on Linux and FreeBSD, `~/Library/Preferences/helm/repositories.yaml` on macOS:

<!-- clientconf: helm repositories.yaml -->

```yaml
apiVersion: ""
generated: "0001-01-01T00:00:00Z"
repositories:
- name: bodega
  url: https://bodega.example/helm
```

On a host that already has the file, `helm repo add bodega https://bodega.example/helm` adds the same entry.

### Check

Run `helm repo update && helm pull bodega/{chart}`, then:

```bash
bodega audit events --type serve_fetch --pkg-type helm --client 192.0.2.10
```

### Traps

- **The list item without the document around it.** helm unmarshals the whole file.
  You see `Error: no repositories to show` from `helm repo list`.
- **`HELM_REPOSITORY_CONFIG` or `XDG_CONFIG_HOME`.** Either moves the file helm reads.
  You see `helm repo list` ignore the file doctor wrote.

## Docker Engine

Which registries go through bodega depends on the image store `dockerd` runs, so read the store before anything else.

```bash
sudo bodega doctor --configure oci --apply --url https://bodega.example
```

doctor writes for every runtime on `PATH`; [containerd](#containerd) and [podman](#podman) cover the others.

### Image stores

Docker Engine sends Docker Hub through `registry-mirrors` under either image store, and every other registry through `/etc/docker/certs.d/{registry}/hosts.toml` only under the containerd image store.
On the overlay2 store an image from `ghcr.io` or `quay.io` pulls from its own registry whatever the files say.
The containerd store is the default on a fresh Docker 29 install; a host upgraded from an older release usually keeps overlay2.

`docker info` names the store.
The containerd store prints `driver-type: io.containerd.snapshotter.v1` under `Storage Driver`:

```bash
docker info --format '{{ .DriverStatus }}'
# containerd store:  [[driver-type io.containerd.snapshotter.v1]]
# overlay2:          [[Backing Filesystem extfs] [Supports d_type true] ...]
```

`registry-mirrors` and `insecure-registries` are among the keys `dockerd` reloads when it gets SIGHUP, so a change to them alone applies without stopping a container:

```bash
sudo systemctl reload docker
```

Turning the containerd store on takes `"features": {"containerd-snapshotter": true}` in `daemon.json` and a restart, since the store is chosen when `dockerd` starts.
The switch hides every image and container the daemon held: they stay on disk under the old store, and `docker ps -a` and `docker images` list none of them.
So every compose project the daemon runs has to be pulled and recreated.
List the projects before the restart, because `docker compose ls` finds them through the containers it is about to lose sight of:

```bash
docker compose ls --all --format json > /root/compose-projects.json
sudo systemctl restart docker
# then, in each project's directory:
docker compose pull && docker compose up -d --force-recreate
```

doctor never sets the key for you.
To switch back, set `"containerd-snapshotter": false` and restart again: the overlay2 images and containers reappear, the ones created under the containerd store are hidden in turn, and registries other than Docker Hub bypass bodega again.

### Files

`/etc/docker/daemon.json`, merged into an existing file with every other key kept:

<!-- clientconf: oci Docker daemon.json -->

```json
{
  "registry-mirrors": [
    "https://bodega.example/"
  ]
}
```

Under the containerd store only, one `hosts.toml` per registry the server serves, in containerd's format, here `/etc/docker/certs.d/ghcr.io/hosts.toml`:

<!-- clientconf: oci containerd hosts.toml (ghcr.io) -->

```toml
server = "https://ghcr.io"

[host."https://bodega.example"]
  capabilities = ["pull", "resolve"]
```

doctor writes `docker.io` and `quay.io` the same way.

### Check

Run `docker pull ghcr.io/{owner}/{image}`, then:

```bash
bodega audit events --type serve_fetch --pkg-type oci --client 192.0.2.10
```

The name column reads `ghcr.io/{owner}/{image}`.
Docker Engine sends no credential to a mirror, so `--identity` finds no row; use `--client`.

### Traps

- **Expecting `ghcr.io` through bodega on overlay2.** You see Docker Hub pulls in the audit trail and none for any other registry, and on a locked host `dial tcp: lookup ghcr.io ... no such host`.
  The `oci-docker` row in `bodega doctor` names the registries that bypass bodega.
- **The restart doctor prints.** `--apply` prints `systemctl restart docker`, which stops every running container unless `live-restore` is set.
  For `registry-mirrors` alone, `systemctl reload docker` is enough.
- **The store switch.** You see `docker ps -a` empty and every compose service gone after the restart.
  Recreate each project, or switch back.
- **A `{host}_{port}_` directory beside a `{host}:{port}` one.** `dockerd` reads the first. doctor refuses the plan, naming that directory, and writes nothing.
- **Docker Engine before 29.1.3.** It resolves `docker.io` once per pull even through the mirror and connects nowhere afterwards.
  You see that lookup in the resolver's log on a locked host while pulls succeed.

## containerd

containerd reads one `hosts.toml` per registry, from the directory `config_path` names:

```bash
sudo bodega doctor --configure oci --apply --url https://bodega.example
```

### Files

`/etc/containerd/certs.d/docker.io/hosts.toml`, and one like it per registry the server serves:

<!-- clientconf: oci containerd hosts.toml (docker.io) -->

```toml
server = "https://registry-1.docker.io"

[host."https://bodega.example"]
  capabilities = ["pull", "resolve"]
```

`/etc/containerd/config.toml`, for a host with none; an existing file gains `config_path` only where it sets none:

<!-- clientconf: oci containerd config.toml -->

```toml
version = 2

[plugins."io.containerd.grpc.v1.cri".registry]
  config_path = "/etc/containerd/certs.d"
```

Restart containerd after `config.toml` changes: `sudo systemctl restart containerd`.

### Check

Run `sudo ctr image pull --hosts-dir /etc/containerd/certs.d docker.io/library/alpine:3.22`, or pull through the CRI, then:

```bash
bodega audit events --type serve_fetch --pkg-type oci --client 192.0.2.10
```

### Traps

- **`ctr` without `--hosts-dir`.** `ctr` does not read `config_path`.
  You see the pull reach the registry directly, with no row. nerdctl reads the same `certs.d` on its own.
- **A `config_path` already set elsewhere.** doctor keeps it and the hosts files go where it points.
  You see the `oci-containerd` row name the directory containerd reads.
- **bodega down.** containerd falls back to each registry's own server.
  You see pulls succeed around bodega on an open host, and bodega's error on a locked one.

## podman

podman, buildah and CRI-O read a drop-in under `/etc/containers/registries.conf.d/`:

```bash
sudo bodega doctor --configure oci --apply --url https://bodega.example
```

### Files

`/etc/containers/registries.conf.d/99-bodega.conf`, a mirror per registry at `{bodega host}/{registry}`:

<!-- clientconf: oci registries.conf drop-in -->

```toml
[[registry]]
prefix = "docker.io"
location = "docker.io"

[[registry.mirror]]
location = "bodega.example/docker.io"

[[registry]]
prefix = "ghcr.io"
location = "ghcr.io"

[[registry.mirror]]
location = "bodega.example/ghcr.io"

[[registry]]
prefix = "quay.io"
location = "quay.io"

[[registry.mirror]]
location = "bodega.example/quay.io"
```

podman and buildah read it on their next run; CRI-O on restart.

### Check

Run `podman pull docker.io/library/alpine:3.22`, then:

```bash
bodega audit events --type serve_fetch --pkg-type oci --client 192.0.2.10
```

### Traps

- **A short image name.** `podman pull alpine` resolves through `unqualified-search-registries`, and a registry the drop-in does not list is pulled directly.
  You see a pull with no row; write the full reference.
- **`CONTAINERS_REGISTRIES_CONF`.** It replaces the file podman reads.
  You see the `oci-podman` row in `bodega doctor` name the file it read.
- **bodega down.** podman falls back to the registry itself, as containerd does.
  You see bodega's error on a locked host.

## git

A `git_upstreams` namespace on the server gives every clone from its forge a route through bodega:

```bash
bodega doctor --configure git --apply --url https://bodega.example
```

### Files

`~/.gitconfig` gains one rewrite per namespace, here a `github` namespace on `https://github.com/`:

<!-- markdownlint-disable MD010 -->

<!-- clientconf: git Git config -->

```ini
[url "https://bodega.example/git/github/"]
	insteadOf = https://github.com/
```

<!-- markdownlint-enable MD010 -->

That rewrite covers the whole forge, which suits a developer's account and an `open` namespace.
For a service host fetching one repository, rewrite that repository alone, as [Applications that fetch on their own](#applications-that-fetch-on-their-own) shows.
See [Git smart-HTTP](usage.md#git-smart-http) for the server side.

### Check

Run `git ls-remote https://github.com/{owner}/{repo}.git`, then:

```bash
bodega audit events --type serve_fetch --pkg-type git --client 192.0.2.10
```

The name column is the namespace, `github`.

### Traps

- **A repository nobody cataloged.** A namespace with no `mode` is in `catalog` mode, which answers anything no manifest entry names with a bare `404`.
  You see `fatal: repository 'https://github.com/{owner}/{repo}.git/' not found` and no audit event.
- **`git push` through a forge-wide rewrite.** `insteadOf` rewrites push URLs too, and bodega refuses every push.
  You see `The requested URL returned error: 403`.
  Add a `pushInsteadOf` back to the forge, or narrow the rewrite.
- **The first clone of a large repository.** bodega mirrors it first and waits 30 seconds.
  You see `remote: bodega is mirroring ... for the first time` and `503`; retry after a minute.
- **A private repository.** bodega reaches the forge anonymously.
  You see a failed clone, not a credential prompt.

## osquery

doctor loads bodega's osquery extension, which an `origins` source needs; the setup script merges bodega's flags into the flagfile `osqueryd` reads, writes the enroll secret and restarts `osqueryd`:

```bash
sudo bodega doctor --configure osquery --apply --url https://bodega.example
read -r BODEGA_OSQUERY_SECRET && export BODEGA_OSQUERY_SECRET
sudo -E sh setup.sh --url https://bodega.example --systems osquery --apply   # setup.sh fetched and checked as the setup script describes
```

Mint the secret on the server with `bodega osquery secret create osq web-01`.
[Mode A](usage.md#mode-a-bodega-as-the-osquery-server) covers which flags bodega owns and how the merge keeps the rest.

### Files

`/etc/osquery/osquery.flags` on Linux, `/usr/local/etc/osquery/osquery.flags` on FreeBSD, or the file `FLAG_FILE` or `osqueryd_flagfile` names.
A Linux host with no flags file ends up with:

<!-- clientconf: osquery osquery.flags -->

```text
--tls_hostname=bodega.example
--tls_server_certs=/etc/ssl/certs/ca-certificates.crt
--enroll_secret_path=/etc/osquery/bodega.secret
--enroll_tls_endpoint=/api/v1/inventory/sources/osq/enroll
--config_plugin=tls
--config_tls_endpoint=/api/v1/inventory/sources/osq/config
--config_refresh=3600
--host_identifier=uuid
--logger_plugin=filesystem,tls
--logger_tls_endpoint=/api/v1/inventory/sources/osq/log
```

`/etc/osquery/bodega.secret` holds the enroll secret, mode 0600, owned by root.
On FreeBSD `--tls_server_certs` is `/etc/ssl/cert.pem` and the secret is `/usr/local/etc/osquery/bodega.secret`.

### Check

osqueryd talks to bodega's API, which writes no `serve_fetch` row.
A failed enrollment is a `denied` row naming the check that failed, and a working host shows in `bodega inventory hosts`:

```bash
bodega audit events --type denied --client 192.0.2.10
bodega inventory hosts
```

### Traps

- **A plaintext `public_url`.** osquery speaks only HTTPS to its tls plugins, so the plan skips osquery.
  You see the plan's `osquery` record skip with `osqueryd speaks only https to its server`.
- **A private CA added only to osquery's own bundle.** `--tls_server_certs` names the system trust store.
  You see `osqueryd` log TLS handshake failures until the CA is added with `update-ca-certificates` or `certctl rehash`.
- **An expired or revoked secret.** Every check answers the same `node_invalid`.
  You see `osqueryd` re-enroll in a loop and a `denied` row naming the check.

## Binary downloads

A binary is downloaded by URL, not configured, so the plan has nothing to write:

```bash
bodega doctor --configure binary --apply --url https://bodega.example
```

That run refuses with `binary entries are downloaded by URL, not configured, so there is no client file`.
Point the download at bodega instead.

### Files

None.
A binary entry is served at a URL like this one, which the TUI and the web UI show per entry:

<!-- clientconf: binary Package URL -->

```text
https://bodega.example/binaries/kubernetes/release/v1.34.2/bin/linux/amd64/kubectl
```

A `binary_upstreams` namespace serves `/binaries/{namespace}/{path}` from `{url}{path}`, so an installer whose download URL names the upstream needs that URL rewritten by hand.

### Check

Run the download on the host, then:

```bash
bodega audit events --type serve_fetch --pkg-type binary --client 192.0.2.10
```

### Traps

- **A namespace in `catalog` mode.** It answers only paths a manifest entry names.
  You see `404` for every other download, and a `no_manifest` discovery row when `discover_mode` is `observe`.
- **A hardcoded upstream URL in an installer script.** Nothing on the host rewrites an HTTP download.
  You see the download succeed from upstream on an open host, and no row.

## Applications that fetch on their own

Some software on a host fetches outside its package manager: an updater script pulling its own repository, an agent checking for new releases, an OS service phoning home.
None of the files above reaches them.

### Updater scripts

An updater that runs `git pull` or `git clone https://github.com/acme/updater.git` is pointed at bodega with a rewrite in `/etc/gitconfig`, which every account on the host reads, naming that one repository:

```bash
sudo git config --system url."https://bodega.example/git/github/acme/updater.git".insteadOf https://github.com/acme/updater.git
```

<!-- markdownlint-disable MD010 -->

```ini
[url "https://bodega.example/git/github/acme/updater.git"]
	insteadOf = https://github.com/acme/updater.git
```

<!-- markdownlint-enable MD010 -->

The rewrite names the repository rather than the forge.
A forge-wide rewrite sends every clone and push on the host from github.com to bodega, so each repository nobody cataloged starts answering `404` and every push `403`, in software that has nothing to do with the updater.
`insteadOf` matches a prefix, so write the URL the script uses, `.git` included: a rewrite of `https://github.com/acme/updater` would also catch `https://github.com/acme/updater-plugins`.

The namespace defaults to `catalog` mode, which answers an uncataloged repository with a bare `404` and no audit event, so catalog the repository on the server:

```json
[{"config_version": 1, "name": "github/acme/updater", "type": "git",
  "versions": [{"url": "https://github.com/acme/updater.git", "mode": "proxy", "version_constraint": "any"}]}]
```

```bash
bodega pkg import updater.json
```

The name is the namespace followed by `{owner}/{repo}` without `.git`.
Opening the namespace instead, `"mode": "open"` on its `git_upstreams` entry, lets any client that reaches bodega make it mirror any repository on that forge; prefer it only for a forge whose publishing you already control.
See [`bodega pkg import`](usage.md#bodega-pkg-import-file-file) and [Git smart-HTTP](usage.md#git-smart-http).

An updater that downloads a release asset over HTTP is a [binary download](#binary-downloads), and `insteadOf` does nothing for it.

### OS services

`bodega doctor` flags three channels on Ubuntu that bodega does not serve, each of which reaches the internet whatever the package sources say:

- **snapd.** It checks `api.snapcraft.io` for refreshes on its own schedule.
  The `snapd-refresh` row warns until refreshes are held.
  `--quiet-os-callers` runs `snap refresh --hold`; to keep snaps current from inside the network, run a Snap Store Proxy and set `snap set system proxy.store={store-id}`.
- **The Ubuntu Pro apt hook.** `/etc/apt/apt.conf.d/20apt-esm-hook.conf` starts `apt-news.service` and `esm-cache.service` on every `apt-get update`, and both reach `esm.ubuntu.com`.
  The `ubuntu-pro-hook` row warns on a host that is not attached to Ubuntu Pro.
  `--quiet-ubuntu-pro` sets `pro config set apt_news=false` and masks `esm-cache.service`; an attached host pays for what the hook fetches and gets no row.
- **`ubuntu-release-upgrader`.** Its new-release check fetches `changelogs.ubuntu.com/meta-release-lts` from two timers and the motd.
  It fetches no packages, but on a locked host it fails on every run and fills the drop log.
  `--quiet-os-callers` sets `Prompt=never` in `/etc/update-manager/release-upgrades`.

Each quieting step joins a `--configure` run and is recorded, so it can be undone:

```bash
sudo bodega doctor --configure apt --quiet-ubuntu-pro --quiet-os-callers --apply --url https://bodega.example
sudo bodega doctor --restore-os-callers
sudo bodega doctor --restore-ubuntu-pro
```

`--quiet-os-callers` also quiets `motd-news`, and the `chrony-nts` row covers the time service; see the [`bodega doctor` reference](usage.md#bodega-doctor---write-credentials---token-token---url-url---configure-systems---apply---suite-codename---abi-abi---release-n---quiet-ubuntu-pro---quiet-os-callers---restore-ubuntu-pro---restore-os-callers---restore-apt-sources---ntp-server-host---write-apt-sources---write-pkg-repo---allow-plaintext).
