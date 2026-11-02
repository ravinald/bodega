# Operations runbook

Bodega is pre-1.0. Read the release notes before upgrading and validate the package types your hosts depend on against the [package support](https://github.com/ravinald/bodega#features).

## Before you put clients on it

1. Follow the [quick start](quickstart.md) with a single package and a disposable client.
2. Configure [TLS and client trust](usage.md#http-server). Use the hostname of your own package server.
3. Configure [authentication and scopes](usage.md#authentication). Separate client reads from administration and approvals.
4. Review [source policy, release age, and vulnerability handling](usage.md#supply-chain-management) for each package type you serve.
5. Run `bodega doctor` on the relevant hosts and inspect the findings. Review changes before applying client configuration.
6. Install the [systemd unit](usage.md#running-under-systemd) or [rc.d service](usage.md#running-under-rcd), then test service restart and a real client installation.

## Check repository health

Use `bodega status` to inspect repository state and `bodega build status` to inspect the build pipeline. Use the [audit trail](usage.md#audit-trail) to investigate refusals and fetch activity. The [web dashboard](usage.md#web-dashboard) and [shell](usage.md#tui) provide interactive views.

The [inventory guide](usage.md#inventory) explains how to compare installed packages with what Bodega served. A working server alone does not prove clients are using it.

## Investigate a failed install

| Symptom | Check first |
| --- | --- |
| TLS or trust error | Client CA trust, server certificate, hostname, and the configured registry URL. |
| Authentication or access refusal | Token expiry and scope, network identity, host profile, and the matching audit event. |
| Version missing or refused | Source policy, hidden or frozen versions, admission checks, and client-visible metadata. |
| Upstream fetch failure | Upstream reachability, registry credentials, proxy configuration, and whether the artifact already exists in storage. |
| Checksum mismatch | The recorded digest and upstream bytes. Preserve the evidence and investigate before replacing artifacts or changing trust. |
| Manifest or storage disagreement | [Manifest integrity and repair](usage.md#manifest-integrity), plus [storage placement](usage.md#configuration). |

Consult the [command reference](usage.md#commands) for the relevant inspection command and its options. Keep the failure time, package type, package name, version, and host identity together when investigating.

## Quarantine a compromised version

Follow the [quarantine workflow](quarantine/README.md) to tombstone the bad version and pin a known-good release. The guide covers the [CLI](quarantine/cli.md), [TUI](quarantine/tui.md), and [API](quarantine/api.md), including rollback.

Quarantining affects what the repository serves. It does not uninstall software already on a host. Use inventory to identify affected hosts and perform remediation there.

## Back up and restore

Back up the configuration, manifest state, artifact storage, audit database, and signing keys as a coordinated set. The actual locations depend on your [configuration](usage.md#configuration) and [storage backends](usage.md#storage-layout). Keep signing keys and credentials protected separately from public artifacts.

For a filesystem backup, stop writers while capturing repository state, or use a backup mechanism that provides a consistent snapshot. Use a SQLite-aware backup or a cleanly stopped database; copying only the database file during active writes can miss committed WAL data. S3 object versioning helps recovery but does not replace a tested backup and retention plan.

Test restoration on an isolated server: restore the matching configuration and state, verify ownership and access, run repository checks, and install representative packages using native clients. Check the signing-key fingerprints before directing production clients at the restored instance.

## Upgrade and roll back

Read the [release notes](https://github.com/ravinald/bodega/releases), verify the release using the [security guide](../SECURITY.md), and keep the previous binary and a pre-upgrade state backup. Test the upgrade with the same package types and policies your production hosts use.

The CLI, configuration, and manifest formats can change before 1.0. Do not assume a previous binary can read state written by a newer version. If rollback requires an older state format, restore the matching backup in a maintenance window.

## Understand the security boundary

Read the [threat model](threat-model.md) before depending on a control. Bodega can govern requests that reach it; preventing clients from bypassing it requires the network and host controls described there. Feature and test coverage vary by package type.
