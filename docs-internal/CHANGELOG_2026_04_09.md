# Documentation Update - 2026-04-09

## Summary

Comprehensive rewrite of four core documentation files to reflect the current architecture and command structure. All command examples now use correct syntax, manifest examples show config_version 2 format, and new features are documented with practical examples.

## Files Updated

### 1. README.md (Root)

**Changes:**
- Updated quick start commands to use correct syntax (`bodega build fetch`, `bodega build upload`)
- Simplified feature list to match current implementation
- Clarified the distinction between quick start and full documentation

**Key fixes:**
- Old: `./dist/bodega fetch` → New: `./dist/bodega build fetch`
- Old: `./dist/bodega upload` → New: `./dist/bodega build upload`
- Added supply chain control to feature list

### 2. docs/QUICKSTART.md

**Changes:**
- Rewrote all command examples to use correct pipeline syntax
- Added comprehensive apt workflow section with three distinct modes:
  1. Package name mode (apt-cache lookup)
  2. Direct URL mode (binary download)
  3. Source build mode (git + build or apt-get source)
- Added supply chain scenario example (handling bad dependencies)
- Updated client configuration examples for all seven types

**Key additions:**
- Apt three-mode workflow section with concrete examples
- Supply chain management scenario with `bodega hide` command
- Cross-references to DESIGN.md and USAGE.md for deeper topics

### 3. docs/DESIGN.md

**Changes:**
- Complete rewrite of manifest structure section to reflect config_version 2
- Updated S3 layout to show per-package manifest files
- Added version policies and constraints documentation
- New sections on dep_policy and supply chain management
- Clarified serve modes and pipeline stages

**Key additions:**
- PackageManifest wrapper format with config_version 2
- VersionEntry structure with all ecosystem-specific fields
- Explanation of wildcard policy entries (e.g., `python3@*`)
- Version constraint types (exact, compatible, patch, any)
- Dep policy ("none", "direct", "transitive") for auto-discovery
- Web UI and dashboard section
- Supply chain management patterns

**Structural improvements:**
- Clear separation between manifest structure and manifest metadata
- Better explanation of the three-mode apt workflow
- Supply chain management as a first-class concept (not a footnote)

### 4. docs/USAGE.md

**Changes:**
- Completely reorganized command reference to match actual CLI
- Updated all command syntax to use correct subcommand structure
- Added missing commands: `bodega show`, `bodega hide`, `bodega refresh`, `bodega repair`
- Replaced old monolithic manifest examples with config_version 2 format
- New major section on supply chain management

**Key additions:**
- Full `bodega show repo` and `bodega show pkg` command documentation
- `bodega hide` and `bodega refresh` commands with examples
- `bodega repair` command with all five consistency check phases
- Complete manifest structure section showing all fields per type
- Supply chain management section with real-world scenarios:
  - Hiding bad versions
  - Freezing policy entries
  - Dependency graph inspection
  - Supply chain audit
- Web dashboard section
- Updated S3 layout to reflect per-package manifests

## Writing Style

All documentation follows the voice of a 30-year network engineer:
- Practical and direct language
- Avoids buzzwords ("leveraging", "robust", "seamless", etc.)
- Explains trade-offs and when to use features
- Uses real-world scenarios instead of abstract explanations
- Minimal em dashes and no emojis
- Active voice preferred over passive

## Specific Improvements

### Command Accuracy
- All pipeline commands corrected: `build fetch`, `build run`, `build sync`, `build upload`
- Show commands documented: `show repo` (client view), `show pkg` (admin view)
- Hide and refresh commands documented with practical examples

### Manifest Examples
- All JSON examples use `config_version: 2`
- PackageManifest wrapper shown in context
- Concrete version entries alongside policy entries
- Ecosystem-specific fields documented per type
- Metadata map field explained for apt Architecture, Maintainer, Section

### Supply Chain Management
- New section in USAGE.md with three real-world scenarios
- `bodega hide` command explained with version-specific and package-wide toggle
- `bodega freeze` command behavior clarified for policy entries
- Dependency graph inspection through `bodega show repo`
- Audit trail for supply chain compliance

### Apt Workflow
- Three distinct modes clearly separated:
  1. Package name (apt-cache based)
  2. Direct URL (binary)
  3. Source build (git repo + build cmd, or apt-get source)
- Each mode shows actual command examples
- Explains when to use each mode (supply chain control, simplicity, etc.)

## Removed Content

- References to old monolithic manifest format (apt.json, git.json, etc.)
- Outdated command examples (`bodega fetch` without subcommand)
- Old manifest structure documentation (config_version 1)
- Generic "next steps" sections that merely summarized upcoming content

## Cross-References

- README.md links to QUICKSTART.md and USAGE.md
- QUICKSTART.md links to DESIGN.md and USAGE.md for deeper topics
- USAGE.md references DESIGN.md for architecture details
- Supply chain section in USAGE.md cross-references docs/DESIGN.md

## Testing Notes

- All command examples have been verified against actual CLI command structure
- Manifest JSON examples match the Go struct definitions in internal/manifest/types.go
- Service client configuration examples tested and current
