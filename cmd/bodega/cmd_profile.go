package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/pins"
)

func newProfileCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "profile <create|list|show|bind|unbind|set|add|remove|pin|pins|unpin|diff|check>",
		Short: "Declare what one class of host may fetch",
		Long: `A profile names the set of packages one class of host may fetch, and the
version rule each of them carries for that class.

Nothing else in bodega varies by consumer: the upstream allow-list, the age
and OSV gates, hidden and frozen versions and every version constraint hold
one answer for the whole fleet. In a fleet of any size that answer is the
union of every host's needs, which is the widest set anyone needs rather than
the set any host needs.

A profile is a view over one catalog, never a second catalog. Storage, object
keys, the checksum table and the manifests do not learn about profiles: an
artifact reached through two profiles is one artifact with one checksum.

Three levels:

  1. the profile          bound to the identities that resolve to it
  2. the per-type marker  membership (closed|open) and version default
                          (pinned|floating), one pair per package type
  3. the entry            one package, optionally with a constraint that
                          overrides its type's version default

The third level is what makes the ordinary case expressible: everything
tracks except postgres, held at 14 because 15 breaks the config.

Examples:
  bodega profile create web --description "public web tier"
  bodega profile set web apt --membership closed --version-default floating
  bodega profile add web apt nginx
  bodega profile pin web apt postgresql-14 14.11 --reason "15 breaks the config"
  bodega profile pins --stale
  bodega profile bind web db01
  bodega profile diff web --origin db01
  bodega profile check`,
	}
	// The write verbs signal, the read verbs do not. A profile edit used to
	// change nothing the server held that a TTL would not pick up on its own,
	// because every index filter ran over the response on the way out. apt is
	// generated instead: a filtered codename is built and signed at snapshot
	// time, so without the signal `bodega profile add` lands in the index at
	// the next hourly tick with nothing saying so.
	parent.AddCommand(
		signalsReload(newProfileCreateCmd(gf)),
		newProfileListCmd(gf),
		newProfileShowCmd(gf),
		signalsReload(newProfileBindCmd(gf)),
		signalsReload(newProfileUnbindCmd(gf)),
		signalsReload(newProfileSetCmd(gf)),
		signalsReload(newProfileAddCmd(gf)),
		signalsReload(newProfileRemoveCmd(gf)),
		signalsReload(newProfilePinCmd(gf)),
		newProfilePinsCmd(gf),
		signalsReload(newProfileUnpinCmd(gf)),
		newProfileDiffCmd(gf),
		newProfileCheckCmd(gf),
	)
	return parent
}

// profileDoc is the baseline document --from-origin writes and --from-file
// reads. It exists so a host's inventory passes through a file an operator can
// edit before any of it becomes a control; see newProfileCreateCmd.
type profileDoc struct {
	ConfigVersion int               `json:"config_version"`
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	Origin        string            `json:"origin,omitempty"`
	Types         []profileDocType  `json:"types"`
	Entries       []profileDocEntry `json:"entries"`
}

type profileDocType struct {
	Type           string `json:"type"`
	Membership     string `json:"membership"`
	VersionDefault string `json:"version_default"`
	// Expansion is omitted when it is the default, so a baseline stays about
	// what the host has rather than about a posture nobody chose. An absent
	// value reads as warn on the way in.
	Expansion string `json:"expansion,omitempty"`
	// AptBase is the mirrored codename an apt rule's filtered index is
	// generated from. It is in the document because a baseline read off a host
	// already knows which release that host runs, and leaving it out would
	// make the one field a filtered index cannot be built without the one
	// field --from-file cannot set.
	AptBase string `json:"apt_base,omitempty"`
}

type profileDocEntry struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Constraint  string `json:"constraint_kind,omitempty"`
	Version     string `json:"version,omitempty"`
	Origin      string `json:"origin,omitempty"`
	Reason      string `json:"reason,omitempty"`
	ReviewAfter string `json:"review_after,omitempty"`
}

func newProfileCreateCmd(gf *globalFlags) *cobra.Command {
	var description, fromOrigin, fromFile, out string
	var pins []string
	var force, overwrite bool

	c := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a profile, optionally from a host's cataloged packages",
		Long: `Create a profile.

With no flags the profile is empty: it states no rule for any type, so it
permits everything until a marker and some entries are written.

--from-origin builds a baseline from the rows 'bodega pkg convert --origin'
recorded for a host. It writes that baseline to the file named by --out and
creates nothing. Read it, edit it, then create the profile from the file:

  bodega profile create web --from-origin db01 --out web.json
  $EDITOR web.json
  bodega profile create web --from-file web.json

The round trip is the point, and it is why --from-origin refuses to create a
profile directly. A host's inventory holds its accidents alongside its
requirements, and locking membership to it enshrines whatever was installed by
hand at 03:00. 'bodega pkg convert' is two commands with an editor between
them for the same reason.

Entries default to name-only with constraint_kind "any", so the baseline says
what the host may fetch and not which build of it. --pin names the exceptions:
a package whose version is held, which is a claim an operator makes about one
package and not a shape a generator should give every package. A baseline that
pins every version is re-authored monthly until somebody stops, which is how a
control becomes ignored.

A --pin takes a bare name, or <type>/<name> where one name is cataloged under
more than one type. A bare name matching two types is refused rather than
resolved: the baseline is walked in a fixed type order, and letting that order
decide which package is held would pin one and leave the other floating with
nothing said about it.

A slash is read as the qualifier only when what precedes it is one of the
eight types, so @babel/core and github.com/lib/pq are each one name. One
package named by two --pin spellings is refused: the pin count is what you
check against the flags you typed.

--out refuses a path that already holds something. The file it names is the
one an operator edited between the two commands, and re-running the generator
over it is how that edit is lost. --overwrite replaces it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if fromOrigin != "" && fromFile != "" {
				return fmt.Errorf("--from-origin builds a baseline and --from-file creates from one; " +
					"run them as two commands with an editor between")
			}
			if fromOrigin != "" {
				return writeBaseline(gf, name, description, fromOrigin, out, pins, overwrite)
			}
			if out != "" {
				return fmt.Errorf("--out names where a baseline is written and only --from-origin writes one")
			}
			if overwrite {
				return fmt.Errorf("--overwrite governs the baseline --out writes and only --from-origin writes one")
			}
			if len(pins) > 0 {
				return fmt.Errorf("--pin names an exception in a --from-origin baseline; " +
					"pin a package in an existing profile with 'bodega profile pin'")
			}

			doc := &profileDoc{ConfigVersion: 1, Name: name, Description: description}
			if fromFile != "" {
				var err error
				if doc, err = readBaseline(fromFile, name, description); err != nil {
					return err
				}
			}
			return createFromDoc(gf, doc, force)
		},
	}
	c.Flags().StringVar(&description, "description", "", "What class of host this profile is for")
	c.Flags().StringVar(&fromOrigin, "from-origin", "", "Build a baseline from the packages cataloged from this host")
	c.Flags().StringVarP(&out, "out", "o", "", "Write the --from-origin baseline here")
	c.Flags().StringVar(&fromFile, "from-file", "", "Create the profile from a baseline file")
	c.Flags().StringArrayVar(&pins, "pin", nil, "Pin this package's version in the baseline, as <name> or <type>/<name> (repeatable)")
	c.Flags().BoolVar(&force, "force", false, "Accept a closed type with no entries, which permits nothing of that type")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "Replace an existing --out file, discarding whatever it holds")
	return c
}

// writeBaseline collects what a host was cataloged with and writes it as a
// document. It creates no profile: that is --from-file's job, and the split is
// the review step.
func writeBaseline(gf *globalFlags, name, description, origin, out string, pins []string, overwrite bool) error {
	if err := requireBaselineFile(out, "--out"); err != nil {
		return err
	}
	if err := requireBaselineAbsent(out, overwrite); err != nil {
		return err
	}
	store, err := loadStore(gf)
	if err != nil {
		return fmt.Errorf("load manifests: %w", err)
	}
	found, err := packagesFromOrigin(store, origin)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return fmt.Errorf("no cataloged package records %s as an origin, so the baseline would be empty.\n"+
			"  Catalog the host first:  bodega pkg convert <type> --origin %s | bodega pkg import -\n"+
			"  What is recorded:        bodega show pkg <type> <name>", origin, origin)
	}

	doc := &profileDoc{ConfigVersion: 1, Name: name, Description: description, Origin: origin}
	seenTypes := map[string]bool{}
	seenEntries := map[string]bool{}
	var renamed []string
	for _, p := range found {
		if !seenTypes[p.Type] {
			seenTypes[p.Type] = true
			doc.Types = append(doc.Types, profileDocType{
				Type:           p.Type,
				Membership:     audit.MembershipClosed,
				VersionDefault: audit.VersionFloating,
				Expansion:      audit.ExpansionWarn,
			})
		}
		entry := p.entryName()
		if entry != p.Name {
			renamed = append(renamed, p.Name+" -> "+entry)
		}
		// One apt source builds many binaries, and a host installs several of
		// them. Listing the source once is the set the filter will close over;
		// repeating it is the duplicate validateDoc refuses on the way back in.
		key := profileKey(p.Type, entry)
		if seenEntries[key] {
			continue
		}
		seenEntries[key] = true
		doc.Entries = append(doc.Entries, profileDocEntry{
			Type:       p.Type,
			Name:       entry,
			Constraint: manifest.ConstraintAny,
			Origin:     origin,
		})
	}
	sort.Slice(doc.Types, func(i, j int) bool { return doc.Types[i].Type < doc.Types[j].Type })

	pinned, err := applyBaselinePins(doc, found, pins, out)
	if err != nil {
		return err
	}

	blob, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, append(blob, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Printf("Wrote a baseline for %s to %s: %d package(s) across %d type(s), %d pinned.\n",
		origin, out, len(doc.Entries), len(doc.Types), pinned)
	if len(renamed) > 0 {
		// ListPackages answers in index order, so an unsorted list reorders
		// itself between two runs over one unchanged catalog.
		sort.Strings(renamed)
		fmt.Printf("%d apt binar%s %s listed under the source package %s built from, which is what a filtered codename closes over:\n  %s\n",
			len(renamed), plural(len(renamed), "y", "ies"), plural(len(renamed), "is", "are"),
			plural(len(renamed), "it was", "they were"), strings.Join(renamed, "\n  "))
	}
	fmt.Printf("Nothing was created. Read it, edit it, then:\n  bodega profile create %s --from-file %s\n", name, out)
	return nil
}

// applyBaselinePins turns --pin arguments into exact constraints, refusing a
// package the host reports at more than one version. Choosing between them
// here would invent a rule the operator did not state, and the version they
// meant is the one thing a pin has to get right.
//
// A pin names either one package (apt/postgresql-14) or, where the name is
// unambiguous across the baseline, the bare name.
func applyBaselinePins(doc *profileDoc, found []originPackage, pins []string, out string) (int, error) {
	if len(pins) == 0 {
		return 0, nil
	}
	count := 0
	pinnedBy := map[string]string{}
	for _, pin := range pins {
		p, err := resolveBaselinePin(doc, found, pin, out)
		if err != nil {
			return 0, err
		}
		if len(p.Versions) != 1 {
			return 0, fmt.Errorf("--pin %s: %s/%s is cataloged from %s at %d versions (%s), so a pin here would pick one for you.\n"+
				"  Create the profile, then name the version:  bodega profile pin %s %s %s <version> --reason <why>",
				pin, p.Type, p.Name, doc.Origin, len(p.Versions), strings.Join(p.Versions, ", "),
				doc.Name, p.Type, p.Name)
		}
		key := p.Type + "/" + p.entryName()
		if first, ok := pinnedBy[key]; ok {
			return 0, fmt.Errorf("--pin %s and --pin %s both name %s, which is either a slip or two versions meant for one package.\n"+
				"  Name it once:  --pin %s", first, pin, key, key)
		}
		pinnedBy[key] = pin
		for i := range doc.Entries {
			if doc.Entries[i].Type == p.Type && doc.Entries[i].Name == p.entryName() {
				doc.Entries[i].Constraint = manifest.ConstraintExact
				doc.Entries[i].Version = p.Versions[0]
				count++
			}
		}
	}
	return count, nil
}

// resolveBaselinePin picks the one package a --pin argument names.
//
// A bare name matching two types is refused rather than resolved, for the
// reason the two-version case above is refused: the baseline is walked in
// manifest.AllTypes order, so picking one would let an enumeration order
// decide which package an operator holds, and the one they meant would stay
// floating with the success line counting the pin.
//
// The <type>/<name> form is taken only when the prefix is one of the eight
// types, none of which contains a slash. Every gomod module path and every
// npm scoped name carries a slash of its own, so reading the first one as a
// type would leave two ecosystems reachable by qualified spelling alone.
func resolveBaselinePin(doc *profileDoc, found []originPackage, pin, out string) (originPackage, error) {
	if typ, name, qualified := strings.Cut(pin, "/"); qualified && slices.Contains(manifest.AllTypes, typ) {
		i := slices.IndexFunc(found, func(p originPackage) bool { return p.Type == typ && p.Name == name })
		if i < 0 {
			return originPackage{}, fmt.Errorf("--pin %s: the baseline holds no %s package named %s.\n"+
				"  What %s was cataloged with:  bodega show pkg %s %s\n"+
				"  Or write it without --pin and read the names out of the file:  bodega profile create %s --from-origin %s --out %s",
				pin, typ, name, doc.Origin, typ, name, doc.Name, doc.Origin, out)
		}
		return found[i], nil
	}

	var matches []originPackage
	for _, p := range found {
		if p.Name == pin {
			matches = append(matches, p)
		}
	}
	switch len(matches) {
	case 0:
		hint := ""
		if typ, _, qualified := strings.Cut(pin, "/"); qualified && !slices.Contains(manifest.AllTypes, typ) {
			hint = fmt.Sprintf("  Read as one name, because %q is no package type; bodega serves: %s\n",
				typ, strings.Join(manifest.AllTypes, ", "))
		}
		return originPackage{}, fmt.Errorf("--pin %s: the baseline holds no package by that name.\n"+
			"%s"+
			"  It lists what %s was cataloged with:  bodega show pkg <type> %s\n"+
			"  Or write it without --pin and read the names out of the file:  bodega profile create %s --from-origin %s --out %s",
			pin, hint, doc.Origin, pin, doc.Name, doc.Origin, out)
	case 1:
		return matches[0], nil
	default:
		var types, spellings []string
		for _, m := range matches {
			types = append(types, m.Type)
			spellings = append(spellings, "  --pin "+m.Type+"/"+m.Name)
		}
		return originPackage{}, fmt.Errorf("--pin %s: %s is cataloged from %s under %d types (%s), so a pin here would pick one for you.\n"+
			"  Name the one you mean:\n%s",
			pin, pin, doc.Origin, len(matches), strings.Join(types, ", "), strings.Join(spellings, "\n"))
	}
}

// readBaseline reads a document back. The file is the review step, so stdin is
// refused here; requireBaselineFile says why.
func readBaseline(path, name, description string) (*profileDoc, error) {
	if err := requireBaselineFile(path, "--from-file"); err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var doc profileDoc
	if err := json.Unmarshal(blob, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if doc.Name != "" && doc.Name != name {
		return nil, fmt.Errorf("%s is a baseline for profile %q and the command names %q; "+
			"create it under the name the file carries, or edit the file's name field",
			path, doc.Name, name)
	}
	doc.Name = name
	if description != "" {
		doc.Description = description
	}
	return &doc, nil
}

// requireBaselineFile refuses stdin and stdout for the baseline. The round
// trip through a file is what --from-origin is for, and `-` on either side
// turns it back into one command nobody read the middle of.
func requireBaselineFile(path, flag string) error {
	if path == "" {
		return fmt.Errorf("%s needs a file path.\n"+
			"  bodega profile create <name> --from-origin <host> --out baseline.json\n"+
			"  $EDITOR baseline.json\n"+
			"  bodega profile create <name> --from-file baseline.json\n"+
			"A host's inventory holds its accidents alongside its requirements, so the "+
			"baseline is reviewed in a file before any of it becomes a control", flag)
	}
	if path == "-" {
		return fmt.Errorf("%s takes a path, not stdin or stdout: a baseline piped straight from the "+
			"command that produced it was never read by anyone, which is the one thing this step is for", flag)
	}
	return nil
}

// requireBaselineAbsent refuses to write over a file that already exists.
//
// The generate-edit-create round trip means the path named by --out is, on
// every run after the first, the file an operator has already spent time on.
// A silent overwrite discards the review this whole split exists to force,
// and reports success while doing it.
func requireBaselineAbsent(path string, overwrite bool) error {
	if overwrite {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", path, err)
	}
	return fmt.Errorf("%s already exists, and a baseline is written to be edited before it is used.\n"+
		"  Read what is there:  bodega profile create <name> --from-file %s\n"+
		"  Write somewhere else:  --out <other path>\n"+
		"  Replace it, losing whatever it holds:  --overwrite", path, path)
}

// createFromDoc writes a whole document: the profile, its markers, its
// entries. Every write is one audit event naming the profile.
func createFromDoc(gf *globalFlags, doc *profileDoc, force bool) error {
	if err := validateDoc(doc); err != nil {
		return err
	}
	if err := checkClosedAndEmpty(doc, force); err != nil {
		return err
	}
	ctx := backgroundCtx()
	adb, err := openProfileStore(gf)
	if err != nil {
		return err
	}
	defer adb.Close()

	actor := audit.CurrentActor()
	types := make([]audit.ProfileTypeRule, 0, len(doc.Types))
	for _, t := range doc.Types {
		types = append(types, audit.ProfileTypeRule{
			Profile: doc.Name, Type: t.Type, Membership: t.Membership,
			VersionDefault: t.VersionDefault, Expansion: t.Expansion, AptBase: t.AptBase, Actor: actor,
		})
	}
	entries := make([]audit.ProfileEntry, 0, len(doc.Entries))
	for _, e := range doc.Entries {
		entries = append(entries, audit.ProfileEntry{
			Profile: doc.Name, Type: e.Type, Name: e.Name, Constraint: e.Constraint,
			Version: e.Version, Origin: e.Origin, Reason: e.Reason,
			ReviewAfter: e.ReviewAfter, Actor: actor,
		})
	}
	if err := adb.CreateProfileWith(ctx, audit.Profile{
		Name: doc.Name, Description: doc.Description, Actor: actor,
	}, types, entries); err != nil {
		return err
	}
	recordProfileEvent(ctx, adb, audit.EventCreate, doc.Name, "",
		fmt.Sprintf("types=%d entries=%d origin=%s", len(doc.Types), len(doc.Entries), doc.Origin))

	fmt.Printf("Created profile %s: %d type rule(s), %d entr%s.\n",
		doc.Name, len(doc.Types), len(doc.Entries), plural(len(doc.Entries), "y", "ies"))
	if len(doc.Types) == 0 {
		fmt.Printf("It states no rule for any type yet, so it permits everything.\n"+
			"  bodega profile set %s apt --membership closed --version-default floating\n", doc.Name)
	}
	return nil
}

// validateDoc runs the whole document through the checks the interactive
// verbs make, before the first row is written.
//
// The hand-edited file is the path --from-origin makes mandatory, so it is
// where a typo is most likely and it earns the strictest reading rather than
// the loosest: a marker under a type bodega does not serve governs nothing,
// and the type the operator meant stays open with nothing reporting it.
func validateDoc(doc *profileDoc) error {
	firstType := map[string]int{}
	for i, t := range doc.Types {
		if err := requirePackageType(t.Type); err != nil {
			return fmt.Errorf("types[%d]: %w", i, err)
		}
		if j, dup := firstType[t.Type]; dup {
			return fmt.Errorf("types[%d] and types[%d] both state a rule for %s: one type carries one membership "+
				"and one version default, so the later row would replace the earlier without saying so.\n"+
				"  Delete one. Merging them would invent a rule neither row states", j, i, t.Type)
		}
		firstType[t.Type] = i
		if t.AptBase != "" && t.Type != manifest.TypeApt {
			return fmt.Errorf("types[%d]: apt_base is read on the apt rule alone; on %s it stores a control nothing consults", i, t.Type)
		}
		if t.AptBase != "" && t.Type == manifest.TypeApt {
			if t.Membership != audit.MembershipClosed {
				return fmt.Errorf("types[%d]: apt_base needs membership closed; an open apt rule admits every package the archive "+
					"publishes, so the filtered index would be the same document under a second name, signed by bodega "+
					"instead of by the archive", i)
			}
			if !refusesUnlisted(t.Expansion) {
				return fmt.Errorf("types[%d]: %w", i, aptBaseNeedsBlockRefusal(doc.Name, audit.ProfileTypeRule{
					Type: t.Type, Membership: t.Membership, Expansion: t.Expansion, AptBase: t.AptBase,
				}))
			}
		}
	}
	firstEntry := map[string]int{}
	for i, e := range doc.Entries {
		if err := requirePackageType(e.Type); err != nil {
			return fmt.Errorf("entries[%d]: %w", i, err)
		}
		if strings.TrimSpace(e.Name) == "" {
			return fmt.Errorf("entries[%d]: an entry needs a package name", i)
		}
		if err := requireConstraintVersion(e.Constraint, e.Version); err != nil {
			return fmt.Errorf("entries[%d] (%s/%s): %w", i, e.Type, e.Name, err)
		}
		key := profileKey(e.Type, e.Name)
		if j, dup := firstEntry[key]; dup {
			spelling := ""
			if doc.Entries[j].Name != e.Name {
				spelling = fmt.Sprintf("\n  %q and %q are one project once the name is normalized, which is the form "+
					"the gate compares", doc.Entries[j].Name, e.Name)
			}
			return fmt.Errorf("entries[%d] and entries[%d] both name %s, which is one entry: the later row would "+
				"replace the earlier, taking its constraint, reason and review date with it.%s\n"+
				"  Keep the one you mean", j, i, key, spelling)
		}
		firstEntry[key] = i
	}
	return nil
}

// checkClosedAndEmpty refuses a document whose closed type lists nothing.
func checkClosedAndEmpty(doc *profileDoc, force bool) error {
	for _, t := range doc.Types {
		if t.Membership != audit.MembershipClosed || !refusesUnlisted(t.Expansion) {
			continue
		}
		listed := 0
		for _, e := range doc.Entries {
			if e.Type == t.Type {
				listed++
			}
		}
		if listed == 0 && !force {
			return closedAndEmptyRefusal(doc.Name, t.Type)
		}
	}
	return nil
}

// closedAndEmptyRefusal is the one refusal this command tree makes on its own
// authority, and it follows the empty admin_permit_cidr precedent: the state
// is reachable, it is almost never meant, and nothing downstream reports it
// because a profile permitting nothing looks exactly like one nobody consults.
func closedAndEmptyRefusal(profile, typ string) error {
	return fmt.Errorf("profile %s would be closed for %s with no %s entries and expansion %s, which permits nothing of that type.\n"+
		"  Every %s request from a host bound to this profile is refused, and the refusal names no package because none is listed.\n"+
		"  List something:  bodega profile add %s %s <name>\n"+
		"  Open the type:   bodega profile set %s %s --membership open\n"+
		"  Detect instead:  bodega profile set %s %s --expansion warn\n"+
		"  Mean it:         re-run with --force, which accepts the empty closed set as written",
		profile, typ, typ, audit.ExpansionBlock, typ, profile, typ, profile, typ, profile, typ)
}

// refusesUnlisted reports whether a closed type's expansion action turns an
// unlisted package into a 403. It is the discriminator for every warning about
// an empty closed set: under warn and ignore that set records or serves, and a
// refusal text promising an outage would be describing a state the profile is
// not in.
func refusesUnlisted(expansion string) bool { return expansion == audit.ExpansionBlock }

func newProfileListCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every profile",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			adb, err := openProfileReader(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			ctx := backgroundCtx()
			profiles, err := adb.ListProfiles(ctx)
			if err != nil {
				return fmt.Errorf("list profiles: %w", err)
			}
			if len(profiles) == 0 {
				fmt.Println("No profiles. Nothing bodega serves varies by consumer yet.")
				fmt.Println("  bodega profile create <name> --description <what class of host>")
				return nil
			}
			bindings, err := adb.ListProfileBindings(ctx, "")
			if err != nil {
				return fmt.Errorf("list profile bindings: %w", err)
			}
			bound := map[string]int{}
			for _, b := range bindings {
				bound[b.Profile]++
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "PROFILE\tTYPES\tENTRIES\tHOSTS\tCREATED\tDESCRIPTION")
			for _, p := range profiles {
				d, err := adb.GetProfile(ctx, p.Name)
				if err != nil {
					return err
				}
				fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%s\t%s\n",
					p.Name, len(d.Types), len(d.Entries), bound[p.Name],
					p.CreatedAt.Format("2006-01-02"), p.Description)
			}
			return w.Flush()
		},
	}
}

func newProfileShowCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "show <profile>",
		Short: "Show a profile's type rules, entries and bound hosts",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			adb, err := openProfileReader(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			ctx := backgroundCtx()
			d, err := adb.GetProfile(ctx, args[0])
			if err != nil {
				return err
			}
			bindings, err := adb.ListProfileBindings(ctx, args[0])
			if err != nil {
				return fmt.Errorf("list profile bindings: %w", err)
			}
			resolvable, err := resolvableIdentities(ctx, adb)
			if err != nil {
				return err
			}

			fmt.Printf("Profile:     %s\n", d.Profile.Name)
			if d.Profile.Description != "" {
				fmt.Printf("Description: %s\n", d.Profile.Description)
			}
			fmt.Printf("Created:     %s by %s\n", d.Profile.CreatedAt.Format("2006-01-02 15:04"), d.Profile.Actor)

			fmt.Printf("\nHosts (%d):\n", len(bindings))
			if len(bindings) == 0 {
				fmt.Printf("  none — bind an identity:  bodega profile bind %s <identity>\n", d.Profile.Name)
			}
			for _, b := range bindings {
				fmt.Printf("  %s\n", b.Identity)
				if !resolvable[b.Identity] {
					fmt.Printf("    no identity binding resolves to this name, so no request reaches this profile\n"+
						"    bodega identity bind cidr <cidr> %s\n", b.Identity)
				}
			}

			fmt.Printf("\nType rules (%d):\n", len(d.Types))
			if len(d.Types) == 0 {
				fmt.Println("  none — this profile states no rule for any type, so it permits everything")
			} else {
				w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
				fmt.Fprintln(w, "  TYPE\tMEMBERSHIP\tVERSION DEFAULT\tEXPANSION\tAPT BASE\tENTRIES")
				for _, t := range d.Types {
					n := 0
					for _, e := range d.Entries {
						if e.Type == t.Type {
							n++
						}
					}
					expansion := "-"
					if t.Membership == audit.MembershipClosed {
						// An open type lists nothing to be outside of, so
						// printing a value there would read as a rule in force.
						expansion = t.Expansion
					}
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%d\n",
						t.Type, t.Membership, t.VersionDefault, expansion, orDash(t.AptBase), n)
				}
				_ = w.Flush()
			}

			fmt.Printf("\nEntries (%d):\n", len(d.Entries))
			if len(d.Entries) > 0 {
				w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
				fmt.Fprintln(w, "  TYPE\tPACKAGE\tCONSTRAINT\tVERSION\tORIGIN\tREVIEW AFTER\tREASON")
				for _, e := range d.Entries {
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
						e.Type, e.Name, orDash(e.Constraint), orDash(e.Version),
						orDash(e.Origin), orDash(e.ReviewAfter), orDash(e.Reason))
				}
				_ = w.Flush()
			}
			reportClosedAndEmpty(d)
			return nil
		},
	}
}

// reportClosedAndEmpty says so when a stored profile is in the state create
// and remove refuse. --force is a legal way in, and a profile that permits
// nothing of a type reads the same as one nobody consults.
func reportClosedAndEmpty(d *audit.ProfileDetail) {
	for _, t := range d.Types {
		if t.Membership != audit.MembershipClosed {
			continue
		}
		if slices.ContainsFunc(d.Entries, func(e audit.ProfileEntry) bool { return e.Type == t.Type }) {
			continue
		}
		if refusesUnlisted(t.Expansion) {
			fmt.Printf("\nClosed for %s with nothing listed: every %s request from a bound host is refused.\n",
				t.Type, t.Type)
			continue
		}
		fmt.Printf("\nClosed for %s with nothing listed, expansion %s: every %s request from a bound host is served and recorded as a reach outside this class.\n"+
			"  Read what it recorded:  bodega discover list %s\n",
			t.Type, t.Expansion, t.Type, t.Type)
	}
}

func newProfileBindCmd(gf *globalFlags) *cobra.Command {
	var comment string
	var force bool
	c := &cobra.Command{
		Use:   "bind <profile> <identity>",
		Short: "Bind an identity to a profile",
		Long: `Bind one of the identities 'bodega identity' resolves to a profile.

The identity is the name the serve path already resolves a request to, from a
token or a CIDR. Reusing it is what keeps one resolution path: bodega answers
"which host is this" once, and the profile says what that host may fetch.

One identity resolves to at most one profile. Binding an identity that is
already bound moves it, and says which profile it came from.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, identity := args[0], args[1]
			ctx := backgroundCtx()
			adb, err := openProfileStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			if err := requireIdentity(ctx, adb, identity, force); err != nil {
				return err
			}
			previous, err := adb.BindProfile(ctx, audit.ProfileBinding{
				Identity: identity, Profile: profile,
				Comment: comment, Actor: audit.CurrentActor(),
			})
			if err != nil {
				return err
			}
			if previous == profile {
				fmt.Printf("%s is already bound to %s.\n", identity, profile)
				return nil
			}
			recordProfileEvent(ctx, adb, audit.EventCreate, profile, identity, "bind identity="+identity)
			if previous != "" {
				fmt.Printf("Bound %s to %s, moved from %s.\n", identity, profile, previous)
				return nil
			}
			fmt.Printf("Bound %s to %s.\n", identity, profile)
			return nil
		},
	}
	c.Flags().StringVar(&comment, "comment", "", "Note stored with the binding")
	c.Flags().BoolVar(&force, "force", false, "Bind an identity no identity binding resolves to")
	return c
}

// requireIdentity refuses a profile binding to a name no identity binding
// produces. A profile bound to a typo is inert and looks identical to one that
// works: no request ever resolves to that name, so the profile is never
// consulted and nothing reports it.
func requireIdentity(ctx context.Context, adb *audit.DB, identity string, force bool) error {
	if force {
		return nil
	}
	resolvable, err := resolvableIdentities(ctx, adb)
	if err != nil {
		return err
	}
	if resolvable[identity] {
		return nil
	}
	return fmt.Errorf("no identity binding resolves to %q, so no request would ever reach this profile.\n"+
		"  The names:   bodega identity list\n"+
		"  A new one:   bodega identity bind cidr <cidr> %s\n"+
		"  Bind anyway: --force, for a name whose identity binding comes later",
		identity, identity)
}

// resolvableIdentities is the set of names an identity binding produces. bind
// refuses a name outside it, and the same inertness arrives later when the
// identity binding is removed underneath a live profile binding, which is why
// show consults it too: nothing else reports a binding that stopped resolving.
func resolvableIdentities(ctx context.Context, adb *audit.DB) (map[string]bool, error) {
	bindings, err := adb.ListIdentityBindings(ctx)
	if err != nil {
		return nil, fmt.Errorf("read identity bindings: %w", err)
	}
	out := make(map[string]bool, len(bindings))
	for _, b := range bindings {
		out[b.Identity] = true
	}
	return out, nil
}

func newProfileUnbindCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "unbind <identity>",
		Short: "Remove an identity's profile binding",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			identity := args[0]
			ctx := backgroundCtx()
			adb, err := openProfileStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			bindings, err := adb.ListProfileBindings(ctx, "")
			if err != nil {
				return err
			}
			profile := ""
			for _, b := range bindings {
				if b.Identity == identity {
					profile = b.Profile
				}
			}
			removed, err := adb.UnbindProfile(ctx, identity)
			if err != nil {
				return err
			}
			if !removed {
				fmt.Printf("%s is not bound to a profile.\n", identity)
				return nil
			}
			recordProfileEvent(ctx, adb, audit.EventDelete, profile, identity, "unbind identity="+identity)
			fmt.Printf("Unbound %s from %s.\n", identity, profile)
			return nil
		},
	}
}

func newProfileSetCmd(gf *globalFlags) *cobra.Command {
	var membership, versionDefault, expansion, base string
	var force bool
	c := &cobra.Command{
		Use:   "set <profile> <type>",
		Short: "Set membership, the version default and the expansion action for one package type",
		Long: `Write the per-type marker: which packages of this type the profile covers,
the version rule they carry unless an entry overrides it, and what happens to
a fetch outside the set.

  --membership closed    only the packages this profile lists
  --membership open      every package of this type in the catalog

  --version-default pinned     only the version each entry names
  --version-default floating   any version

  --expansion warn       serve it, and record the reach outside the class
  --expansion block      refuse it with 403
  --expansion ignore     serve it and record nothing

  --base <codename>      apt only: the mirrored codename this profile's
                         filtered index is generated from

--base is what makes apt enforceable under a profile, and it applies to a
closed apt rule alone. bodega serves the profile a codename of its own,
"<base>-<profile>", holding a filtered view of the base's Packages signed with
bodega's own key; a host reads that codename instead of the base. Without it a
closed apt rule filters nothing, because refusing a .deb at the pool would
abort an apt transaction the client had already planned.

  bodega profile set web apt --membership closed --base noble
  bodega doctor --write-apt-sources --token ... --url https://bodega.internal

--expansion defaults to warn and applies to a closed type alone, because an
open type lists nothing to be outside of. warn rather than block: a new
transitive dependency is ordinary upstream maintenance, and the cost of
refusing it is a host that stops getting patched. Read what warn records, then
narrow. The rows land with decision "denied" in the discovery table:

  bodega discover list npm

The marker's presence is itself an answer. A type with no marker is one the
profile states no rule for, and the fleet-wide controls decide it alone; a
type with a marker is decided by the profile even when no entry names a
package. That is why 'closed with nothing listed' is a state you can reach,
and why this command refuses it without --force.

Both flags are optional on a type that already has a marker: what you do not
name keeps the value it has.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, typ := args[0], args[1]
			if err := requirePackageType(typ); err != nil {
				return err
			}
			if membership == "" && versionDefault == "" && expansion == "" && !cmd.Flags().Changed("base") {
				return fmt.Errorf("name what to set: --membership <%s>, --version-default <%s>, --expansion <%s> or --base <codename>",
					strings.Join(audit.Memberships(), "|"), strings.Join(audit.VersionDefaults(), "|"),
					strings.Join(audit.Expansions(), "|"))
			}
			if expansion != "" && !audit.ValidExpansion(expansion) {
				return fmt.Errorf("--expansion must be one of: %s", strings.Join(audit.Expansions(), ", "))
			}
			ctx := backgroundCtx()
			adb, err := openProfileStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			d, err := adb.GetProfile(ctx, profile)
			if err != nil {
				return err
			}

			rule := audit.ProfileTypeRule{
				Profile: profile, Type: typ,
				Membership: audit.MembershipOpen, VersionDefault: audit.VersionFloating,
				Expansion: audit.ExpansionWarn,
			}
			for _, t := range d.Types {
				if t.Type == typ {
					rule.Membership, rule.VersionDefault = t.Membership, t.VersionDefault
					rule.Expansion = t.Expansion
				}
			}
			if membership != "" {
				rule.Membership = membership
			}
			if versionDefault != "" {
				rule.VersionDefault = versionDefault
			}
			if expansion != "" {
				rule.Expansion = expansion
			}
			if cmd.Flags().Changed("base") {
				rule.AptBase = base
			}
			if err := checkProfileAptBase(gf, profile, rule); err != nil {
				return err
			}
			rule.Actor = audit.CurrentActor()

			if rule.Membership == audit.MembershipClosed && refusesUnlisted(rule.Expansion) && !force {
				listed := slices.ContainsFunc(d.Entries, func(e audit.ProfileEntry) bool { return e.Type == typ })
				if !listed {
					return closedAndEmptyRefusal(profile, typ)
				}
			}
			if err := adb.SetProfileTypeRule(ctx, rule); err != nil {
				return err
			}
			recordProfileEvent(ctx, adb, audit.EventEdit, profile, typ,
				fmt.Sprintf("membership=%s version_default=%s expansion=%s",
					rule.Membership, rule.VersionDefault, rule.Expansion))
			fmt.Printf("%s %s: membership=%s version_default=%s expansion=%s\n",
				profile, typ, rule.Membership, rule.VersionDefault, rule.Expansion)
			if rule.AptBase != "" {
				fmt.Printf("  filtered codename: %s (from %s), served after the next index rebuild\n",
					config.ProfileAptCodename(rule.AptBase, profile), rule.AptBase)
			}
			return nil
		},
	}
	c.Flags().StringVar(&membership, "membership", "", "closed | open")
	c.Flags().StringVar(&versionDefault, "version-default", "", "pinned | floating")
	c.Flags().StringVar(&expansion, "expansion", "", "warn | block | ignore (closed types only; default warn)")
	c.Flags().StringVar(&base, "base", "", "apt only: the mirrored codename the filtered index is generated from")
	c.Flags().BoolVar(&force, "force", false, "Accept a closed type with no entries, which permits nothing of that type")
	return c
}

// checkProfileAptBase refuses a base this instance could not serve, at the
// write rather than at the next index rebuild.
//
// Stored, a bad base is a control the operator believes they set: nothing
// refuses it, the codename never appears, and the only evidence is one ERROR
// line an hour later in the server's journal. The config read is best-effort
// for the same reason the write is not — an operator setting a profile from a
// host with no config file still gets the shape check, which is the half that
// catches a typo.
func checkProfileAptBase(gf *globalFlags, profile string, rule audit.ProfileTypeRule) error {
	if rule.AptBase == "" {
		return nil
	}
	if rule.Type != manifest.TypeApt {
		return fmt.Errorf("--base is read on the apt rule alone; %q would store it where nothing reads it", rule.Type)
	}
	if rule.Membership != audit.MembershipClosed {
		return fmt.Errorf("--base needs --membership closed: an open apt rule admits every package the archive publishes, "+
			"so the filtered index would be the same document under a second name, signed by bodega instead of by the archive.\n"+
			"  Close it:  bodega profile set %s apt --membership closed --base %s", profile, rule.AptBase)
	}
	if !refusesUnlisted(rule.Expansion) {
		return aptBaseNeedsBlockRefusal(profile, rule)
	}
	cfg, err := loadConfig(gf)
	if err != nil {
		return nil
	}
	codename := config.ProfileAptCodename(rule.AptBase, profile)
	if err := cfg.ValidateProfileAptCodename(codename, rule.AptBase, profile); err != nil {
		return err
	}
	if !cfg.MirrorsAptCodename(rule.AptBase) {
		return fmt.Errorf("no upstream archive is configured for the codename %q, so there is no Packages index to filter.\n"+
			"  Mirrored here:  %s\n"+
			"  Add one:        apt_upstreams in the config file",
			rule.AptBase, orNone(strings.Join(cfg.MirroredAptCodenames(), " ")))
	}
	return nil
}

// aptBaseNeedsBlockRefusal is the second half of the open-membership refusal
// above, reached by the other road. Under warn and ignore the predicate
// permits every package the profile does not list, so the filter keeps every
// upstream paragraph and the codename serves the archive's own index under
// bodega's signature: the host stops verifying against the distro keyring, the
// pool drops from public to private, and nothing is filtered in return.
//
// warn stays the fleet default for the seven other types, where an unlisted
// package is served and reported and the index is not what enforces. apt is
// the one type whose unfiltered outcome costs a signature the host already
// trusts, so it is the one type where the default has to be stated rather than
// inherited.
func aptBaseNeedsBlockRefusal(profile string, rule audit.ProfileTypeRule) error {
	have := audit.ExpansionOrDefault(rule.Expansion)
	if rule.Expansion == "" {
		have += " (the default this rule does not name)"
	}
	return fmt.Errorf("--base needs --expansion %s; this rule takes %s, which permits a package the profile does not list, "+
		"so every upstream paragraph survives the filter and %s would serve the archive's own index under bodega's "+
		"signature instead of the archive's: a host that stops verifying against the distro keyring, for no filtering.\n"+
		"  Filter it:  bodega profile set %s apt --membership closed --expansion %s --base %s\n"+
		"  Or drop the base: the profile then reads the mirrored codename %s unchanged, verified against the distro keyring",
		audit.ExpansionBlock, have, config.ProfileAptCodename(rule.AptBase, profile),
		profile, audit.ExpansionBlock, rule.AptBase, rule.AptBase)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func newProfileAddCmd(gf *globalFlags) *cobra.Command {
	var constraint, version, reason, reviewAfter, origin string
	c := &cobra.Command{
		Use:   "add <profile> <type> <name>",
		Short: "Add or replace one package entry",
		Long: `Name one package in a profile.

With no --constraint the entry defers to its type's version default: an entry
in a floating type takes any version, one in a pinned type takes the version
it names. --constraint is the third level, and it overrides that default for
this package alone, in either direction:

  --constraint any                        one floating package in a pinned type
  --constraint exact --version 14.11      one pinned package in a floating type
  --constraint compatible --version 5.2   same major, at or above 5.2
  --constraint patch --version 1.26.4     same major.minor, at or above 1.26.4

Adding an entry that already exists edits it: every flag you give is written
and every field you leave out keeps what it held, so changing the version a
package is held at does not drop the reason it was held for. Clearing a
constraint is 'bodega profile unpin'. 'bodega profile pin' is this command
with the pinning arguments already filled in.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := pins.ValidateReviewDate(reviewAfter); err != nil {
				return err
			}
			return putProfileEntry(gf, args[0], args[1], args[2], audit.ProfileEntry{
				Constraint: constraint, Version: version, Reason: reason,
				ReviewAfter: reviewAfter, Origin: origin,
			}, changedFlags(cmd, "constraint", "version", "reason", "review-after", "origin"))
		},
	}
	c.Flags().StringVar(&constraint, "constraint", "", "exact | compatible | patch | any; empty defers to the type's version default")
	c.Flags().StringVar(&version, "version", "", "The version the constraint is measured against")
	c.Flags().StringVar(&reason, "reason", "", "Why this entry is here")
	c.Flags().StringVar(&reviewAfter, "review-after", "", "Date after which this entry should be re-examined (YYYY-MM-DD)")
	c.Flags().StringVar(&origin, "origin", "", "The host this entry was cataloged from")
	return c
}

func newProfilePinCmd(gf *globalFlags) *cobra.Command {
	var reason, reviewAfter string
	var strictClosure bool
	c := &cobra.Command{
		Use:   "pin <profile> <type> <name> <version>",
		Short: "Hold one package at one version, with a reason",
		Long: `Pin one package to one version, whatever its type's version default says.

--reason is required. A pin with no reason outlives the problem it was written
for: nobody who finds it later can tell a deliberate hold from an accident, so
it is never lifted. --review-after gives the same pin a date it stops looking
current on, and 'bodega profile pins --stale' is the gate that finds it.

A pin is not local. The version being held was built against particular
releases of everything it depends on, so holding it holds those too, and the
dependency closure is reported before the pin is written.

  default          report the closure and pin the one package you named
  --strict-closure pin every package in the closure at the version the graph
                   records, so the profile states what it is already implying

Reporting is the default because extending a pin across a closure freezes a
growing set: each package pinned drags its own dependencies in, and a host
stops receiving security updates for all of them without anyone deciding that
it should. --strict-closure is for the operator who has read the report and
wants the implication written down.

--strict-closure never overwrites an entry somebody else gave a reason. Those
are named and left where they are: moving one would take the version backward
across whatever its reason records and replace the reason with a generated
string. Move such an entry with 'bodega profile pin' on the package itself.

On apt, --strict-closure has nothing to pin to unless the dependency was
declared with an '=' relation: a '>=' floor holds no version still, and the
closure reports those members with no version rather than choosing one.`,
		Args: cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("--reason is required on a pin.\n" +
					"  A pin with no reason outlives the problem it was written for: the next operator " +
					"cannot tell a deliberate hold from an accident, so it is never lifted.\n" +
					"  bodega profile pin <profile> <type> <name> <version> --reason \"15 breaks the config\"")
			}
			if err := pins.ValidateReviewDate(reviewAfter); err != nil {
				return err
			}
			profile, typ, name, version := args[0], args[1], args[2], args[3]
			closure, err := reportPinClosure(gf, profile, typ, name, version, strictClosure)
			if err != nil {
				return err
			}
			supplied := changedFlags(cmd, "review-after")
			supplied["constraint"], supplied["version"], supplied["reason"] = true, true, true
			if err := putProfileEntry(gf, profile, typ, name, audit.ProfileEntry{
				Constraint: manifest.ConstraintExact, Version: version,
				Reason: reason, ReviewAfter: reviewAfter, PinnedAt: time.Now().UTC(),
			}, supplied); err != nil {
				return err
			}
			if !strictClosure {
				return nil
			}
			return extendPinAcrossClosure(gf, profile, closure, reason, reviewAfter)
		},
	}
	c.Flags().StringVar(&reason, "reason", "", "Why this version is held (required)")
	c.Flags().StringVar(&reviewAfter, "review-after", "", "Date after which the pin should be re-examined (YYYY-MM-DD)")
	c.Flags().BoolVar(&strictClosure, "strict-closure", false,
		"Also pin every package in the dependency closure, at the version the graph records. "+
			"Off by default: the default reports the closure and freezes nothing beyond the package you named")
	return c
}

// reportPinClosure prints what else the pin holds still, before anything is
// written. It returns the closure so --strict-closure does not walk it twice.
//
// A graph bodega cannot read is reported and does not stop the pin. The
// closure is what the operator learns from the command, not a control the pin
// depends on, and refusing to hold a package because graph.json is missing
// would make an unrelated catalog defect block a security decision.
func reportPinClosure(gf *globalFlags, profile, typ, name, version string, strict bool) (pins.Closure, error) {
	closure := pins.Closure{Type: typ, Name: name, Version: version}
	store, err := loadStore(gf)
	if err != nil {
		return closure, fmt.Errorf("load manifests: %w", err)
	}
	ctx := backgroundCtx()
	if err := store.LoadGraph(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "could not read the dependency graph, so this pin's closure is unreported: %v\n", err)
		return closure, nil
	}
	closure = pins.Of(store.Edges(), typ, name, version)
	if len(closure.Members) == 0 {
		return closure, nil
	}

	fmt.Printf("Pinning %s at %s holds %d other package(s) still:\n", closure.Ref(), version, len(closure.Members))
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  PACKAGE\tHELD AT\tVIA\tSPEC")
	for _, m := range closure.Members {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", m.Ref(), orDash(m.Version), m.Via, orDash(m.RawSpec))
	}
	_ = w.Flush()

	adb, err := openProfileReader(gf)
	if err != nil {
		return closure, err
	}
	defer adb.Close()
	d, err := adb.GetProfile(ctx, profile)
	if err != nil {
		return closure, err
	}
	for _, c := range closure.Conflicts(entitle.New(checkView(d))) {
		fmt.Printf("  conflict: %s\n", c.Reason)
	}
	if !strict && len(closure.Resolved()) > 0 {
		fmt.Printf("  Pin the closure too:  --strict-closure\n")
	}
	return closure, nil
}

// impliedReasonPrefix opens the reason --strict-closure writes. It is how the
// command tells an entry it wrote itself from one an operator authored: the
// first may be refreshed, the second is a record that only its author may
// replace.
const impliedReasonPrefix = "implied by the "

// impliedReason is the reason --strict-closure records on a closure member,
// naming the pin that implied it so the entry says why it is there without
// anyone reading the graph.
func impliedReason(closure pins.Closure, reason string) string {
	return fmt.Sprintf("%s%s pin at %s: %s", impliedReasonPrefix, closure.Ref(), closure.Version, reason)
}

// extendPinAcrossClosure writes the pins the closure implies, at the versions
// the graph records.
//
// A member the graph names no version for is skipped and said so: the edge
// records that the package is depended on and not which release, so pinning it
// would mean choosing a version on the operator's behalf, which is the one
// thing a pin must never be.
//
// A member already carrying an operator-authored reason is skipped too, and
// that is the case this command exists to report. The conflict it prints one
// line earlier is precisely an entry somebody else pinned deliberately;
// overwriting it would move the version backward across whatever fix the
// reason names and replace the reason with a generated string, leaving the
// word "Updated" as the only trace. The operator moves it with 'bodega profile
// pin', where they say why.
func extendPinAcrossClosure(gf *globalFlags, profile string, closure pins.Closure, reason, reviewAfter string) error {
	resolved := closure.Resolved()
	if len(resolved) == 0 {
		fmt.Printf("--strict-closure: the graph records no version for anything %s reaches, so nothing more was pinned.\n",
			closure.Ref())
		return nil
	}

	held, err := profileEntriesByRef(gf, profile)
	if err != nil {
		return fmt.Errorf("--strict-closure: read %s: %w", profile, err)
	}

	implied := impliedReason(closure, reason)
	var refused []audit.ProfileEntry
	for _, m := range resolved {
		if e, ok := held[m.Ref()]; ok && operatorAuthored(e) {
			refused = append(refused, e)
			continue
		}
		supplied := map[string]bool{
			"constraint": true, "version": true, "reason": true, "review-after": reviewAfter != "",
		}
		if err := putProfileEntry(gf, profile, m.Type, m.Name, audit.ProfileEntry{
			Constraint: manifest.ConstraintExact, Version: m.Version,
			Reason: implied, ReviewAfter: reviewAfter, PinnedAt: time.Now().UTC(),
		}, supplied); err != nil {
			return fmt.Errorf("--strict-closure: pin %s: %w", m.Ref(), err)
		}
	}
	for _, e := range refused {
		fmt.Printf("--strict-closure: left %s/%s at %s alone; it carries a reason somebody wrote: %s\n",
			e.Type, e.Name, orDash(e.Version), e.Reason)
		fmt.Printf("  Move it deliberately:  bodega profile pin %s %s %s <version> --reason <why>\n",
			profile, e.Type, e.Name)
	}
	if skipped := len(closure.Members) - len(resolved); skipped > 0 {
		fmt.Printf("--strict-closure: %d closure member(s) carry no version in the graph and were left floating; pin them by name once you know the release.\n", skipped)
	}
	return nil
}

// operatorAuthored answers whether a profile entry carries a record that only
// its author may replace. An entry --strict-closure wrote itself is not one:
// refreshing those is the whole of what a second run does.
func operatorAuthored(e audit.ProfileEntry) bool {
	r := strings.TrimSpace(e.Reason)
	return r != "" && !strings.HasPrefix(r, impliedReasonPrefix)
}

// profileEntriesByRef reads a profile's entries keyed as "type/name".
func profileEntriesByRef(gf *globalFlags, profile string) (map[string]audit.ProfileEntry, error) {
	adb, err := openProfileReader(gf)
	if err != nil {
		return nil, err
	}
	defer adb.Close()
	d, err := adb.GetProfile(backgroundCtx(), profile)
	if err != nil {
		return nil, err
	}
	held := make(map[string]audit.ProfileEntry, len(d.Entries))
	for _, e := range d.Entries {
		held[e.Type+"/"+e.Name] = e
	}
	return held, nil
}

func newProfilePinsCmd(gf *globalFlags) *cobra.Command {
	var stale, asJSON bool
	c := &cobra.Command{
		Use:   "pins [profile]",
		Short: "List every pin with its reason, its review date and the advisories against it",
		Long: `Report every version a profile holds, and what bodega knows about it.

A pin is a decision to stop receiving updates for one package. "Pinned at
14.9" and "not receiving security updates for postgres" are the same sentence,
and this is where the second one is written down: each pin is listed with the
reason an operator gave, who gave it, when, the review date, and the OSV
advisories recorded against the version being held.

A pin accepts the known vulnerabilities in that version for the life of the
pin. Nothing here tracks what is done about them: no suppression state, no
ticket, no severity clock. The reason and the review date are the whole of
bodega's suppression concept, and the report is what a tool that does track
remediation reads.

The OSV column is the stamp 'bodega policy osv rescan' writes. A version no run
has ever answered for reads 'unchecked' rather than 'clean': an empty advisory
list means nobody looked as often as it means there is nothing to find, and a
pin is the one place that distinction decides whether somebody acts.

--stale narrows the report to the pins past their review date and exits 1, so
it works as a CI or cron gate. A pin with no review date is never stale, which
is why 'pin --review-after' is worth writing.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var profile string
			if len(args) == 1 {
				profile = args[0]
			}
			adb, err := openProfileReader(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			all, err := pins.Collect(backgroundCtx(), adb, store, profile, time.Now().UTC())
			if err != nil {
				return err
			}
			shown := all
			if stale {
				shown = pins.Stale(all)
			}
			if asJSON {
				if shown == nil {
					// An empty array rather than null, matching the endpoint:
					// a consumer has to tell "no pins" from a field it failed
					// to parse, and null reads as the second.
					shown = []pins.Pin{}
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if err := enc.Encode(shown); err != nil {
					return err
				}
			} else {
				printPins(shown, all, stale)
			}
			if stale && len(shown) > 0 {
				return fmt.Errorf("%d pin(s) past their review date", len(shown))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&stale, "stale", false, "Only the pins past their review date; exits 1 when any is found")
	c.Flags().BoolVar(&asJSON, "json", false, "Emit the records GET /api/v1/profiles/{name}/pins returns")
	return c
}

// printPins renders the report. The advisory ids and their scores go under the
// table rather than in it: a version carrying three GHSAs with two scores each
// is a paragraph, and a column wide enough for it makes every other row
// unreadable.
func printPins(shown, all []pins.Pin, stale bool) {
	if len(shown) == 0 {
		if stale {
			fmt.Printf("No pin is past its review date (%d pin(s) checked).\n", len(all))
			return
		}
		fmt.Println("No pins. Nothing in any profile holds a package at one version.")
		fmt.Println("  bodega profile pin <profile> <type> <name> <version> --reason <why>")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tTYPE\tPACKAGE\tVERSION\tPINNED\tBY\tREVIEW AFTER\tOVERDUE\tOSV\tCHECKED\tREASON")
	for _, p := range shown {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			p.Profile, p.Type, p.Name, p.Version, pinDate(p.PinnedAt), orDash(p.Actor),
			orDash(p.ReviewAfter), overdueCell(p), p.OSV.State, pinDate(p.OSV.Checked), orDash(p.Reason))
	}
	_ = w.Flush()

	for _, p := range shown {
		if len(p.OSV.Vulns) == 0 {
			continue
		}
		fmt.Printf("\n%s %s/%s at %s accepts %d known advisory(ies) for the life of the pin:\n",
			p.Profile, p.Type, p.Name, p.Version, len(p.OSV.Vulns))
		for _, id := range p.OSV.Vulns {
			scores := p.OSV.Severity[id]
			if len(scores) == 0 {
				fmt.Printf("  %s  (OSV recorded no score)\n", id)
				continue
			}
			var rendered []string
			for _, sev := range scores {
				rendered = append(rendered, strings.TrimSpace(sev.Type+" "+sev.Score))
			}
			fmt.Printf("  %s  %s\n", id, strings.Join(rendered, ", "))
		}
	}
	for _, p := range shown {
		if !p.Cataloged {
			fmt.Printf("\n%s %s/%s: the catalog holds no version %s, so nothing can be checked against it.\n"+
				"  What it holds:  bodega show pkg %s %s\n",
				p.Profile, p.Type, p.Name, p.Version, p.Type, p.Name)
		}
	}
}

// pinDate renders a date cell, "-" for a date nothing recorded.
func pinDate(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(pins.ReviewDateLayout)
}

// overdueCell says how far past its review date a pin is. A pin with a review
// date still ahead of it reads "-" rather than a negative number of days: the
// column answers "is this overdue and by how much", and a countdown in it
// would need a second reading to tell the two apart.
func overdueCell(p pins.Pin) string {
	if !p.Stale {
		return "-"
	}
	return fmt.Sprintf("%dd", p.OverdueDays)
}

func newProfileUnpinCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "unpin <profile> <type> <name>",
		Short: "Release a pin, leaving the package listed",
		Long: `Drop the version constraint from an entry and keep the entry.

The version the pin named stays on the entry as its base, because that is the
shape a pinned type default reads: an entry with a version and no constraint
of its own is held at that version, and one with neither is a pin with nothing
to pin to, which permits no version at all. A floating default ignores the base
and takes any version, so keeping it costs nothing there.

Removing the entry outright is 'bodega profile remove', and on a closed type
that is a different decision: the package stops being permitted at all.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, typ, name := args[0], args[1], args[2]
			ctx := backgroundCtx()
			adb, err := openProfileStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			d, err := adb.GetProfile(ctx, profile)
			if err != nil {
				return err
			}
			idx := findProfileEntry(d.Entries, typ, name)
			if idx < 0 {
				return fmt.Errorf("profile %s does not list %s/%s, so there is no pin to release.\n"+
					"  What it lists:  bodega profile show %s", profile, typ, name, profile)
			}
			e := d.Entries[idx]
			if e.Constraint == "" {
				fmt.Printf("%s/%s carries no constraint of its own; it already takes the %s version default.\n",
					typ, name, typ)
				return nil
			}
			e.Constraint, e.Actor = "", audit.CurrentActor()
			if _, err := adb.PutProfileEntry(ctx, e); err != nil {
				return err
			}
			recordProfileEvent(ctx, adb, audit.EventEdit, profile, typ+"/"+name, "unpin")
			fmt.Printf("Released the pin on %s/%s in %s; %s\n",
				typ, name, profile, unpinConsequence(d.Types, profile, typ, name, e.Version))
			return nil
		},
	}
}

// unpinConsequence names what the entry permits now, resolved against the
// type marker. "It takes the type default again" is true and useless: under a
// pinned default the answer turns on whether the entry still names a version,
// and an operator releasing a hold is entitled to know they did not impose a
// total one.
func unpinConsequence(types []audit.ProfileTypeRule, profile, typ, name, version string) string {
	i := slices.IndexFunc(types, func(t audit.ProfileTypeRule) bool { return t.Type == typ })
	if i < 0 {
		return fmt.Sprintf("the profile states no rule for %s, so nothing in it governs %s.", typ, name)
	}
	if types[i].VersionDefault == audit.VersionFloating {
		return fmt.Sprintf("the %s default is floating, so it takes any version.", typ)
	}
	if version == "" {
		return fmt.Sprintf("the %s default is pinned and the entry names no version, so it now permits nothing.\n"+
			"  Give it one:   bodega profile pin %s %s %s <version> --reason <why>\n"+
			"  Or float it:   bodega profile add %s %s %s --constraint any",
			typ, profile, typ, name, profile, typ, name)
	}
	return fmt.Sprintf("the %s default is pinned, so it holds at %s.", typ, version)
}

// putProfileEntry is the one write behind add and pin. supplied names the
// fields the operator gave; everything else is carried over from the stored
// entry, so a second `add` edits rather than replaces.
//
// The alternative, writing whatever the flags hold, means a bare `add` on a
// pinned package erases the pin, its reason and its review date in one
// command with nothing said about it. `unpin` is the deliberate path and it
// preserves all three, so replace-on-add destroys more by accident than the
// verb written to do it destroys on purpose.
func putProfileEntry(gf *globalFlags, profile, typ, name string, e audit.ProfileEntry, supplied map[string]bool) error {
	if err := requirePackageType(typ); err != nil {
		return err
	}
	ctx := backgroundCtx()
	adb, err := openProfileStore(gf)
	if err != nil {
		return err
	}
	defer adb.Close()

	d, err := adb.GetProfile(ctx, profile)
	if err != nil {
		return err
	}
	// Adopting the stored spelling is what keeps this an edit. The upsert
	// conflicts on the name as written, so re-adding an entry under pypi's
	// other spelling would insert a second row, and entitle.New would index
	// both under one key and keep whichever it read last.
	if i := findProfileEntry(d.Entries, typ, name); i >= 0 {
		e = mergeProfileEntry(d.Entries[i], e, supplied)
		name = d.Entries[i].Name
	}
	if err := requireConstraintVersion(e.Constraint, e.Version); err != nil {
		return err
	}

	e.Profile, e.Type, e.Name = profile, typ, name
	e.Actor = audit.CurrentActor()
	created, err := adb.PutProfileEntry(ctx, e)
	if err != nil {
		return err
	}
	ev := audit.EventEdit
	if created {
		ev = audit.EventCreate
	}
	recordProfileEvent(ctx, adb, ev, profile, typ+"/"+name,
		fmt.Sprintf("constraint=%s version=%s reason=%s", e.Constraint, e.Version, e.Reason))

	verb := "Updated"
	if created {
		verb = "Added"
	}
	fmt.Printf("%s %s/%s in %s%s.\n", verb, typ, name, profile, constraintSuffix(e))
	return nil
}

// changedFlags reports which of names the operator actually gave, which is
// what separates "set this to empty" from "leave this alone".
func changedFlags(cmd *cobra.Command, names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = cmd.Flags().Changed(n)
	}
	return out
}

// mergeProfileEntry overwrites only the fields supplied names, leaving the
// stored value for the rest.
func mergeProfileEntry(stored, e audit.ProfileEntry, supplied map[string]bool) audit.ProfileEntry {
	out := stored
	if supplied["constraint"] {
		out.Constraint = e.Constraint
	}
	if supplied["version"] {
		out.Version = e.Version
	}
	if supplied["reason"] {
		out.Reason = e.Reason
	}
	if supplied["review-after"] {
		out.ReviewAfter = e.ReviewAfter
	}
	if supplied["origin"] {
		out.Origin = e.Origin
	}
	// PinnedAt moves only when the caller sets it, which is the pin path
	// alone. An `add` that edits a pin's reason carries the stored date
	// through, so correcting a typo does not re-date the decision and reset
	// the review clock it is measured against.
	if !e.PinnedAt.IsZero() {
		out.PinnedAt = e.PinnedAt
	}
	return out
}

// requireConstraintVersion refuses a constraint with nothing to measure. It is
// the same rule for a flag and for a line in a baseline file.
func requireConstraintVersion(kind, version string) error {
	if kind == "" || kind == manifest.ConstraintAny || version != "" {
		return nil
	}
	return fmt.Errorf("constraint %s is measured against a version and none was given: --version <v>", kind)
}

func constraintSuffix(e audit.ProfileEntry) string {
	switch {
	case e.Constraint == "":
		return " (takes the type's version default)"
	case e.Version == "":
		return " (" + e.Constraint + ")"
	default:
		return " (" + e.Constraint + " " + e.Version + ")"
	}
}

func newProfileRemoveCmd(gf *globalFlags) *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "remove <profile> <type> <name>",
		Short: "Remove one package entry",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile, typ, name := args[0], args[1], args[2]
			ctx := backgroundCtx()
			adb, err := openProfileStore(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			d, err := adb.GetProfile(ctx, profile)
			if err != nil {
				return err
			}
			if i := findProfileEntry(d.Entries, typ, name); i >= 0 {
				name = d.Entries[i].Name
			}
			if !force && lastEntryOfClosedType(d, typ, name) {
				return closedAndEmptyRefusal(profile, typ)
			}
			removed, err := adb.RemoveProfileEntry(ctx, profile, typ, name)
			if err != nil {
				return err
			}
			if !removed {
				fmt.Printf("Profile %s does not list %s/%s.\n", profile, typ, name)
				return nil
			}
			recordProfileEvent(ctx, adb, audit.EventDelete, profile, typ+"/"+name, "remove entry")
			fmt.Printf("Removed %s/%s from %s.\n", typ, name, profile)
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "Remove the last entry of a closed type, which leaves it permitting nothing")
	return c
}

// findProfileEntry returns the index of the entry the gate would match for a
// typed name, -1 for none. An operator types whatever spelling they have in
// front of them, and for pypi that is routinely not the one stored: comparing
// raw reports a listed package as absent and leaves the entry in force.
func findProfileEntry(entries []audit.ProfileEntry, typ, name string) int {
	key := profileKey(typ, name)
	return slices.IndexFunc(entries, func(e audit.ProfileEntry) bool {
		return profileKey(e.Type, e.Name) == key
	})
}

// profileKey is entitle.Key qualified by type, which is how the CLI holds a
// package: entitle keeps one map per type and these maps do not, so dropping
// the prefix would merge pypi/requests with npm/requests.
func profileKey(typ, name string) string {
	return typ + "/" + entitle.Key(typ, name)
}

// lastEntryOfClosedType reports whether removing this entry would leave a
// closed type with nothing listed.
func lastEntryOfClosedType(d *audit.ProfileDetail, typ, name string) bool {
	closed := slices.ContainsFunc(d.Types, func(t audit.ProfileTypeRule) bool {
		return t.Type == typ && t.Membership == audit.MembershipClosed && refusesUnlisted(t.Expansion)
	})
	if !closed {
		return false
	}
	remaining := 0
	for _, e := range d.Entries {
		if e.Type == typ && e.Name != name {
			remaining++
		}
	}
	return remaining == 0
}

func newProfileDiffCmd(gf *globalFlags) *cobra.Command {
	var origin string
	c := &cobra.Command{
		Use:   "diff <profile>",
		Short: "Compare a profile against what a host was cataloged with",
		Long: `Name what a host has that its profile does not list, and what the profile
lists that the host does not have.

Without this a baseline is an assertion nobody can falsify: a profile written
from db01 six months ago and a db01 that has moved on look identical from the
outside.

The host side is the packages carrying that origin in the catalog, which is
what 'bodega pkg convert --origin' recorded. A host that was never cataloged
compares as empty, and this says so rather than reporting the whole profile as
drift.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := args[0]
			if origin == "" {
				return fmt.Errorf("--origin names the host to compare against: bodega profile diff %s --origin <host>", profile)
			}
			adb, err := openProfileReader(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			d, err := adb.GetProfile(backgroundCtx(), profile)
			if err != nil {
				return err
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}
			found, err := packagesFromOrigin(store, origin)
			if err != nil {
				return err
			}

			// Keyed by what the gate compares, printed as each side spells it:
			// a pypi entry written django against a package cataloged as Django
			// is one package, and keying raw reports it as drift on both sides.
			onHost := map[string]originPackage{}
			for _, p := range found {
				onHost[profileKey(p.Type, p.Name)] = p
			}
			inProfile := map[string]audit.ProfileEntry{}
			for _, e := range d.Entries {
				inProfile[profileKey(e.Type, e.Name)] = e
			}

			var hostOnly, profileOnly []string
			for k := range onHost {
				if _, ok := inProfile[k]; !ok {
					hostOnly = append(hostOnly, k)
				}
			}
			for k := range inProfile {
				if _, ok := onHost[k]; !ok {
					profileOnly = append(profileOnly, k)
				}
			}
			sort.Strings(hostOnly)
			sort.Strings(profileOnly)

			if len(found) == 0 {
				fmt.Printf("No cataloged package records %s as an origin, so there is nothing to compare against.\n"+
					"  bodega pkg convert <type> --origin %s | bodega pkg import -\n\n", origin, origin)
			}
			w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
			fmt.Fprintf(w, "On %s, not in %s (%d):\n", origin, profile, len(hostOnly))
			for _, k := range hostOnly {
				p := onHost[k]
				fmt.Fprintf(w, "  %s/%s\t%s\n", p.Type, p.Name, strings.Join(p.Versions, ", "))
			}
			fmt.Fprintf(w, "\nIn %s, not on %s (%d):\n", profile, origin, len(profileOnly))
			for _, k := range profileOnly {
				e := inProfile[k]
				fmt.Fprintf(w, "  %s/%s\t%s\n", e.Type, e.Name, orDash(e.Constraint+" "+e.Version))
			}
			_ = w.Flush()
			if len(hostOnly) == 0 && len(profileOnly) == 0 && len(found) > 0 {
				fmt.Printf("\n%s and %s name the same %d package(s).\n", profile, origin, len(found))
			}
			return nil
		},
	}
	c.Flags().StringVar(&origin, "origin", "", "The host to compare against")
	return c
}

func newProfileCheckCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "check [profile]",
		Short: "Verify every profile entry still resolves in the catalog",
		Long: `Walk every profile, or the one named, and report entries naming a package
the catalog does not hold or a version it does not carry.

Exit code 1 if any violation is found — suitable for CI pipelines, and the
same contract 'bodega policy check' has.

An entry that stopped resolving is a control that stopped controlling: on a
closed type the package it named is simply absent, and on a pinned entry the
version it holds is one nothing can serve.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			adb, err := openProfileReader(gf)
			if err != nil {
				return err
			}
			defer adb.Close()
			ctx := backgroundCtx()

			var names []string
			if len(args) == 1 {
				names = []string{args[0]}
			} else {
				profiles, err := adb.ListProfiles(ctx)
				if err != nil {
					return fmt.Errorf("list profiles: %w", err)
				}
				for _, p := range profiles {
					names = append(names, p.Name)
				}
			}
			if len(names) == 0 {
				fmt.Println("No profiles to check.")
				return nil
			}
			store, err := loadStore(gf)
			if err != nil {
				return fmt.Errorf("load manifests: %w", err)
			}

			var violations int
			var srcIndex aptSourceIndex
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			for _, name := range names {
				d, err := adb.GetProfile(ctx, name)
				if err != nil {
					return err
				}
				resolved := entitle.New(checkView(d))
				if base, _ := resolved.AptScope(); base != "" && srcIndex == nil {
					if srcIndex, err = newAptSourceIndex(ctx, store); err != nil {
						_ = w.Flush()
						return err
					}
				}
				for _, e := range d.Entries {
					reason, err := entryResolves(ctx, store, resolved, e, srcIndex)
					if err != nil {
						_ = w.Flush()
						return err
					}
					if reason == "" {
						continue
					}
					if violations == 0 {
						fmt.Fprintln(w, "PROFILE\tTYPE\tPACKAGE\tREASON")
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", name, e.Type, e.Name, reason)
					violations++
				}
			}
			_ = w.Flush()
			if violations == 0 {
				fmt.Printf("OK: every entry in %d profile(s) resolves in the catalog.\n", len(names))
				return nil
			}
			return fmt.Errorf("%d profile violation(s) detected", violations)
		},
	}
}

// checkView supplies an open, floating marker for a type that has entries and
// no marker of its own.
//
// Without it an entry pinned to a version the catalog dropped passes the gate
// whenever its type is unmarked, because the predicate correctly reports the
// whole type as ungoverned and permits everything. The gate asks a narrower
// question than the serve path does: an entry carrying its own constraint is
// the third level, which overrides a default whatever the default is, so a
// broken pin is broken before anyone writes the marker that puts it in force.
// open+floating is the identity for that substitution — it constrains nothing
// on its own and leaves each entry answering for itself.
func checkView(d *audit.ProfileDetail) *audit.ProfileDetail {
	marked := map[string]bool{}
	for _, t := range d.Types {
		marked[t.Type] = true
	}
	view := *d
	view.Types = slices.Clone(d.Types)
	for _, e := range d.Entries {
		if marked[e.Type] {
			continue
		}
		marked[e.Type] = true
		view.Types = append(view.Types, audit.ProfileTypeRule{
			Profile: d.Profile.Name, Type: e.Type,
			Membership: audit.MembershipOpen, VersionDefault: audit.VersionFloating,
		})
	}
	return &view
}

// entryResolves returns why an entry does not resolve, or empty when it does.
//
// The version half runs through entitle.Permits rather than comparing strings
// here. An entry pinned to a version the catalog dropped and one whose range
// constraint no cataloged version satisfies are the same defect — a control
// that refuses everything it names — and a second implementation of "does this
// constraint match" is what internal/admit exists to have prevented.
//
// A hidden version counts as absent, because every handler that builds an
// answer excludes it, so an entry whose only match is hidden names a version
// nothing can serve. Frozen is deliberately not the same: it blocks build,
// edit and delete, and the version still serves.
// A manifest the store cannot read is returned as an error rather than a
// reason, because the two repairs are opposite ones: a missing package means
// the entry names something the catalog dropped, and an operator reading that
// in CI removes the entry. A read failure means the catalog is broken and the
// entry is very likely fine.
func entryResolves(ctx context.Context, store *manifest.Store, p *entitle.Profile, e audit.ProfileEntry, srcIndex aptSourceIndex) (string, error) {
	pm, err := store.GetPackage(ctx, e.Type, e.Name)
	if err != nil {
		return "", fmt.Errorf("load %s/%s: %w", e.Type, e.Name, err)
	}
	versions, reason := entryVersions(p, e, pm, srcIndex)
	if reason != "" {
		return reason, nil
	}
	var servable, hidden, hiddenMatch []string
	var last entitle.Decision
	for _, ve := range versions {
		last = p.Permits(e.Type, e.Name, ve.Version)
		if ve.Hidden {
			hidden = append(hidden, ve.Version)
			if last.Permitted {
				hiddenMatch = append(hiddenMatch, ve.Version)
			}
			continue
		}
		if last.Permitted {
			return "", nil
		}
		servable = append(servable, ve.Version)
	}
	switch {
	case len(versions) == 0:
		return "the catalog holds the package with no versions", nil
	case len(servable) == 0:
		return fmt.Sprintf("every cataloged version is hidden (%s), so nothing serves this package",
			strings.Join(hidden, ", ")), nil
	case len(hiddenMatch) > 0:
		return fmt.Sprintf("%s permits only hidden versions (%s), which nothing serves",
			orDash(strings.TrimSpace(e.Constraint+" "+e.Version)), strings.Join(hiddenMatch, ", ")), nil
	case last.Rule != nil && last.Entry == nil:
		// The type's version default refused on its own, and the entry's own
		// fields are empty because the default is what stood in for them.
		// entitle has already written the sentence that names the rule; a
		// message rebuilt from the entry here would name nothing.
		return last.Reason, nil
	}
	return fmt.Sprintf("%s permits none of the cataloged versions (%s)",
		orDash(strings.TrimSpace(e.Constraint+" "+e.Version)), strings.Join(servable, ", ")), nil
}

// aptSourceIndex maps a Debian source package to every version entry the
// catalog holds for a binary built from it. nil is the unbuilt index and
// answers nothing, which is what a check with no apt-scoped profile wants: the
// walk costs one GetPackage per apt package and buys nothing there.
type aptSourceIndex map[string][]manifest.VersionEntry

// newAptSourceIndex walks the apt catalog once per check run.
func newAptSourceIndex(ctx context.Context, store *manifest.Store) (aptSourceIndex, error) {
	idx := aptSourceIndex{}
	for _, name := range store.ListPackages(manifest.TypeApt) {
		pm, err := store.GetPackage(ctx, manifest.TypeApt, name)
		if err != nil {
			return nil, fmt.Errorf("load %s/%s: %w", manifest.TypeApt, name, err)
		}
		if pm == nil {
			continue
		}
		for _, ve := range pm.Versions {
			if ve.SourcePackage != "" {
				idx[ve.SourcePackage] = append(idx[ve.SourcePackage], ve)
			}
		}
	}
	return idx, nil
}

// entryVersions returns the cataloged versions an entry is checked against,
// or the reason it names nothing the profile could ever serve.
//
// For seven types that is the package's own version list. apt under a filtered
// codename is the eighth, because membership there closes on the source
// package: filterAptPackages reads Source: out of each upstream paragraph and
// aptPoolGate reads the source segment out of the pool path, so an entry naming
// a source the catalog holds only as binaries is correct and resolves, and an
// entry naming a binary whose source differs is a control that matches no
// paragraph in the index it governs.
//
// The second case is reported rather than repaired, and the filter is
// deliberately not taught to match either spelling: a set closed on binary
// names fires on every rename, split and transition Ubuntu ships as ordinary
// maintenance, which is the closure this item rejected.
func entryVersions(p *entitle.Profile, e audit.ProfileEntry, pm *manifest.PackageManifest, srcIndex aptSourceIndex) ([]manifest.VersionEntry, string) {
	filtered := false
	if e.Type == manifest.TypeApt {
		base, _ := p.AptScope()
		filtered = base != ""
	}
	if !filtered {
		if pm == nil {
			return nil, "no " + e.Type + " package by that name in the catalog"
		}
		return pm.Versions, ""
	}

	built := srcIndex[e.Name]
	if pm == nil {
		if len(built) == 0 {
			return nil, "no apt package by that name in the catalog, and nothing cataloged names it as a source package"
		}
		return built, ""
	}
	if src := aptBinarySource(pm, e.Name); src != "" {
		return nil, fmt.Sprintf("this profile serves a filtered apt codename, which closes on the source package; "+
			"%s is a binary built from source %s, so it matches no paragraph in the index. List %s instead",
			e.Name, src, src)
	}
	return append(slices.Clone(pm.Versions), built...), ""
}

// aptBinarySource returns the source package a cataloged binary was built
// from when it differs from name, and "" when it agrees or when no capture
// recorded one.
//
// Any agreeing entry clears the package: source and binary coincide for most
// of the archive, and a single four-field capture recording no source is not
// evidence of a divergence.
func aptBinarySource(pm *manifest.PackageManifest, name string) string {
	first := ""
	for _, ve := range pm.Versions {
		switch ve.SourcePackage {
		case "", name:
			return ""
		default:
			if first == "" {
				first = ve.SourcePackage
			}
		}
	}
	return first
}

// originPackage is one cataloged package that names a host as an origin.
type originPackage struct {
	Type     string
	Name     string
	Source   string
	Versions []string
}

// entryName is the name a baseline lists this package under, which for apt is
// the source package and for every other type is the package's own name.
//
// apt membership is closed over the source on both paths that consult it:
// filterAptPackages reads Source: out of each upstream paragraph, and
// aptPoolGate reads the source segment out of the pool path. A baseline
// listing binaries therefore matches nothing: a host running nginx-common
// catalogs as nginx-common and the filter looks up nginx, so every divergent
// binary is reported to the host as kept back, which is the silent partial
// service docs/DESIGN.md names as the reason not-signing lost.
//
// A capture that recorded no source falls back to the binary name rather than
// dropping the entry. The four-field dpkg-query format carries no Source:
// column, so an older capture has nothing better to offer, and a name that is
// right whenever the two coincide beats an entry that is absent.
func (p originPackage) entryName() string {
	if p.Type == manifest.TypeApt && p.Source != "" {
		return p.Source
	}
	return p.Name
}

// packagesFromOrigin walks the catalog for packages carrying origin on at
// least one version entry. It reads the field 'bodega pkg convert --origin'
// writes, through the same accessor the merge path uses.
func packagesFromOrigin(store *manifest.Store, origin string) ([]originPackage, error) {
	ctx := backgroundCtx()
	var out []originPackage
	for _, typ := range manifest.AllTypes {
		for _, name := range store.ListPackages(typ) {
			pm, err := store.GetPackage(ctx, typ, name)
			if err != nil {
				return nil, fmt.Errorf("load %s/%s: %w", typ, name, err)
			}
			var versions []string
			source := ""
			for _, ve := range pm.Versions {
				if !slices.Contains(admit.Origins(ve), origin) {
					continue
				}
				versions = append(versions, ve.Version)
				if source == "" {
					source = ve.SourcePackage
				}
			}
			if len(versions) > 0 {
				out = append(out, originPackage{Type: typ, Name: pm.Name, Source: source, Versions: versions})
			}
		}
	}
	return out, nil
}

// requirePackageType refuses a type outside the eight, so a typo does not
// become a marker or an entry nothing will ever read.
func requirePackageType(typ string) error {
	if slices.Contains(manifest.AllTypes, typ) {
		return nil
	}
	return fmt.Errorf("no package type named %q; bodega serves: %s",
		typ, strings.Join(manifest.AllTypes, ", "))
}

// openProfileStore refuses a read-only install and opens the audit database,
// where the profiles live. Every mutation needs both.
func openProfileStore(gf *globalFlags) (*audit.DB, error) {
	_, adb, err := openACLStore(gf)
	return adb, err
}

// openProfileReader opens the audit database for a read command, which needs
// neither a writable install nor a writable database.
func openProfileReader(gf *globalFlags) (*audit.DB, error) {
	adb, err := openAuditDBErr(gf)
	if err != nil {
		return nil, err
	}
	if adb == nil {
		return nil, fmt.Errorf("could not open the audit database, which is where the profiles live.\n" +
			"  Check audit_db (or log_dir) in config.json, then: bodega status")
	}
	return adb, nil
}

// recordProfileEvent writes one audit row per mutation, in the shape `bodega
// acl` writes: the profile in pkg_name, what inside it in pkg_version.
func recordProfileEvent(ctx context.Context, adb *audit.DB, ev audit.EventType, profile, target, details string) {
	_ = adb.Record(ctx, audit.Event{
		EventType:  ev,
		PkgType:    "profile",
		PkgName:    profile,
		PkgVersion: target,
		Actor:      audit.CurrentActor(),
		Status:     "success",
		Details:    details,
	})
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return strings.TrimSpace(s)
}
