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

	"github.com/spf13/cobra"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/entitle"
	"github.com/ravinald/bodega/internal/manifest"
)

func newProfileCmd(gf *globalFlags) *cobra.Command {
	parent := &cobra.Command{
		Use:   "profile <create|list|show|bind|unbind|set|add|remove|pin|unpin|diff|check>",
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
  bodega profile bind web db01
  bodega profile diff web --origin db01
  bodega profile check`,
	}
	parent.AddCommand(
		newProfileCreateCmd(gf),
		newProfileListCmd(gf),
		newProfileShowCmd(gf),
		newProfileBindCmd(gf),
		newProfileUnbindCmd(gf),
		newProfileSetCmd(gf),
		newProfileAddCmd(gf),
		newProfileRemoveCmd(gf),
		newProfilePinCmd(gf),
		newProfileUnpinCmd(gf),
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
	var force bool

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
control becomes ignored.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if fromOrigin != "" && fromFile != "" {
				return fmt.Errorf("--from-origin builds a baseline and --from-file creates from one; " +
					"run them as two commands with an editor between")
			}
			if fromOrigin != "" {
				return writeBaseline(gf, name, description, fromOrigin, out, pins)
			}
			if out != "" {
				return fmt.Errorf("--out names where a baseline is written and only --from-origin writes one")
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
	c.Flags().StringArrayVar(&pins, "pin", nil, "Pin this package's version in the baseline (repeatable)")
	c.Flags().BoolVar(&force, "force", false, "Accept a closed type with no entries, which permits nothing of that type")
	return c
}

// writeBaseline collects what a host was cataloged with and writes it as a
// document. It creates no profile: that is --from-file's job, and the split is
// the review step.
func writeBaseline(gf *globalFlags, name, description, origin, out string, pins []string) error {
	if err := requireBaselineFile(out, "--out"); err != nil {
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
	for _, p := range found {
		if !seenTypes[p.Type] {
			seenTypes[p.Type] = true
			doc.Types = append(doc.Types, profileDocType{
				Type:           p.Type,
				Membership:     audit.MembershipClosed,
				VersionDefault: audit.VersionFloating,
			})
		}
		doc.Entries = append(doc.Entries, profileDocEntry{
			Type:       p.Type,
			Name:       p.Name,
			Constraint: manifest.ConstraintAny,
			Origin:     origin,
		})
	}
	sort.Slice(doc.Types, func(i, j int) bool { return doc.Types[i].Type < doc.Types[j].Type })

	pinned, err := applyBaselinePins(doc, found, pins)
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
	fmt.Printf("Nothing was created. Read it, edit it, then:\n  bodega profile create %s --from-file %s\n", name, out)
	return nil
}

// applyBaselinePins turns --pin names into exact constraints, refusing a
// package the host reports at more than one version. Choosing between them
// here would invent a rule the operator did not state, and the version they
// meant is the one thing a pin has to get right.
func applyBaselinePins(doc *profileDoc, found []originPackage, pins []string) (int, error) {
	if len(pins) == 0 {
		return 0, nil
	}
	byName := map[string]originPackage{}
	for _, p := range found {
		byName[p.Name] = p
	}
	count := 0
	for _, pin := range pins {
		p, ok := byName[pin]
		if !ok {
			return 0, fmt.Errorf("--pin %s: the baseline holds no package by that name.\n"+
				"  It lists what %s was cataloged with; check the spelling against 'bodega profile create %s --from-origin %s --out -'",
				pin, doc.Origin, doc.Name, doc.Origin)
		}
		if len(p.Versions) != 1 {
			return 0, fmt.Errorf("--pin %s: %s is cataloged from %s at %d versions (%s), so a pin here would pick one for you.\n"+
				"  Create the profile, then name the version:  bodega profile pin %s %s %s <version> --reason <why>",
				pin, p.Name, doc.Origin, len(p.Versions), strings.Join(p.Versions, ", "),
				doc.Name, p.Type, p.Name)
		}
		for i := range doc.Entries {
			if doc.Entries[i].Type == p.Type && doc.Entries[i].Name == p.Name {
				doc.Entries[i].Constraint = manifest.ConstraintExact
				doc.Entries[i].Version = p.Versions[0]
				count++
			}
		}
	}
	return count, nil
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

// createFromDoc writes a whole document: the profile, its markers, its
// entries. Every write is one audit event naming the profile.
func createFromDoc(gf *globalFlags, doc *profileDoc, force bool) error {
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
	if err := adb.CreateProfile(ctx, audit.Profile{
		Name: doc.Name, Description: doc.Description, Actor: actor,
	}); err != nil {
		return err
	}
	recordProfileEvent(ctx, adb, audit.EventCreate, doc.Name, "",
		fmt.Sprintf("types=%d entries=%d origin=%s", len(doc.Types), len(doc.Entries), doc.Origin))

	for _, t := range doc.Types {
		if err := adb.SetProfileTypeRule(ctx, audit.ProfileTypeRule{
			Profile: doc.Name, Type: t.Type, Membership: t.Membership,
			VersionDefault: t.VersionDefault, Actor: actor,
		}); err != nil {
			return fmt.Errorf("%s: %w", t.Type, err)
		}
	}
	for _, e := range doc.Entries {
		if _, err := adb.PutProfileEntry(ctx, audit.ProfileEntry{
			Profile: doc.Name, Type: e.Type, Name: e.Name, Constraint: e.Constraint,
			Version: e.Version, Origin: e.Origin, Reason: e.Reason,
			ReviewAfter: e.ReviewAfter, Actor: actor,
		}); err != nil {
			return fmt.Errorf("%s/%s: %w", e.Type, e.Name, err)
		}
	}
	fmt.Printf("Created profile %s: %d type rule(s), %d entr%s.\n",
		doc.Name, len(doc.Types), len(doc.Entries), plural(len(doc.Entries), "y", "ies"))
	if len(doc.Types) == 0 {
		fmt.Printf("It states no rule for any type yet, so it permits everything.\n"+
			"  bodega profile set %s apt --membership closed --version-default floating\n", doc.Name)
	}
	return nil
}

// checkClosedAndEmpty refuses a document whose closed type lists nothing.
func checkClosedAndEmpty(doc *profileDoc, force bool) error {
	for _, t := range doc.Types {
		if t.Membership != audit.MembershipClosed {
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
	return fmt.Errorf("profile %s would be closed for %s with no %s entries, which permits nothing of that type.\n"+
		"  Every %s request from a host bound to this profile is refused, and the refusal names no package because none is listed.\n"+
		"  List something:  bodega profile add %s %s <name>\n"+
		"  Open the type:   bodega profile set %s %s --membership open\n"+
		"  Mean it:         re-run with --force, which accepts the empty closed set as written",
		profile, typ, typ, typ, profile, typ, profile, typ)
}

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
			}

			fmt.Printf("\nType rules (%d):\n", len(d.Types))
			if len(d.Types) == 0 {
				fmt.Println("  none — this profile states no rule for any type, so it permits everything")
			} else {
				w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
				fmt.Fprintln(w, "  TYPE\tMEMBERSHIP\tVERSION DEFAULT\tENTRIES")
				for _, t := range d.Types {
					n := 0
					for _, e := range d.Entries {
						if e.Type == t.Type {
							n++
						}
					}
					fmt.Fprintf(w, "  %s\t%s\t%s\t%d\n", t.Type, t.Membership, t.VersionDefault, n)
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
		if !slices.ContainsFunc(d.Entries, func(e audit.ProfileEntry) bool { return e.Type == t.Type }) {
			fmt.Printf("\nClosed for %s with nothing listed: every %s request from a bound host is refused.\n",
				t.Type, t.Type)
		}
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
			recordProfileEvent(ctx, adb, audit.EventCreate, profile, identity, "bind identity="+identity)
			if previous == profile {
				fmt.Printf("%s is already bound to %s.\n", identity, profile)
				return nil
			}
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
	bindings, err := adb.ListIdentityBindings(ctx)
	if err != nil {
		return fmt.Errorf("read identity bindings: %w", err)
	}
	for _, b := range bindings {
		if b.Identity == identity {
			return nil
		}
	}
	return fmt.Errorf("no identity binding resolves to %q, so no request would ever reach this profile.\n"+
		"  The names:   bodega identity list\n"+
		"  A new one:   bodega identity bind cidr <cidr> %s\n"+
		"  Bind anyway: --force, for a name whose identity binding comes later",
		identity, identity)
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
	var membership, versionDefault string
	var force bool
	c := &cobra.Command{
		Use:   "set <profile> <type>",
		Short: "Set membership and the version default for one package type",
		Long: `Write the per-type marker: which packages of this type the profile covers,
and the version rule they carry unless an entry overrides it.

  --membership closed    only the packages this profile lists
  --membership open      every package of this type in the catalog

  --version-default pinned     only the version each entry names
  --version-default floating   any version

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
			if membership == "" && versionDefault == "" {
				return fmt.Errorf("name what to set: --membership <%s> or --version-default <%s>",
					strings.Join(audit.Memberships(), "|"), strings.Join(audit.VersionDefaults(), "|"))
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
			}
			for _, t := range d.Types {
				if t.Type == typ {
					rule.Membership, rule.VersionDefault = t.Membership, t.VersionDefault
				}
			}
			if membership != "" {
				rule.Membership = membership
			}
			if versionDefault != "" {
				rule.VersionDefault = versionDefault
			}
			rule.Actor = audit.CurrentActor()

			if rule.Membership == audit.MembershipClosed && !force {
				listed := slices.ContainsFunc(d.Entries, func(e audit.ProfileEntry) bool { return e.Type == typ })
				if !listed {
					return closedAndEmptyRefusal(profile, typ)
				}
			}
			if err := adb.SetProfileTypeRule(ctx, rule); err != nil {
				return err
			}
			recordProfileEvent(ctx, adb, audit.EventEdit, profile, typ,
				fmt.Sprintf("membership=%s version_default=%s", rule.Membership, rule.VersionDefault))
			fmt.Printf("%s %s: membership=%s version_default=%s\n",
				profile, typ, rule.Membership, rule.VersionDefault)
			return nil
		},
	}
	c.Flags().StringVar(&membership, "membership", "", "closed | open")
	c.Flags().StringVar(&versionDefault, "version-default", "", "pinned | floating")
	c.Flags().BoolVar(&force, "force", false, "Accept a closed type with no entries, which permits nothing of that type")
	return c
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

Adding an entry that already exists replaces it, because changing the version
a package is held at is the ordinary edit and a remove-then-add loses the
reason in the gap. 'bodega profile pin' is this command with the pinning
arguments already filled in.`,
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return putProfileEntry(gf, args[0], args[1], args[2], audit.ProfileEntry{
				Constraint: constraint, Version: version, Reason: reason,
				ReviewAfter: reviewAfter, Origin: origin,
			})
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
	c := &cobra.Command{
		Use:   "pin <profile> <type> <name> <version>",
		Short: "Hold one package at one version, with a reason",
		Long: `Pin one package to one version, whatever its type's version default says.

--reason is required. A pin with no reason outlives the problem it was written
for: nobody who finds it later can tell a deliberate hold from an accident, so
it is never lifted. --review-after gives the same pin a date it stops looking
current on.`,
		Args: cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("--reason is required on a pin.\n" +
					"  A pin with no reason outlives the problem it was written for: the next operator " +
					"cannot tell a deliberate hold from an accident, so it is never lifted.\n" +
					"  bodega profile pin <profile> <type> <name> <version> --reason \"15 breaks the config\"")
			}
			return putProfileEntry(gf, args[0], args[1], args[2], audit.ProfileEntry{
				Constraint: manifest.ConstraintExact, Version: args[3],
				Reason: reason, ReviewAfter: reviewAfter,
			})
		},
	}
	c.Flags().StringVar(&reason, "reason", "", "Why this version is held (required)")
	c.Flags().StringVar(&reviewAfter, "review-after", "", "Date after which the pin should be re-examined (YYYY-MM-DD)")
	return c
}

func newProfileUnpinCmd(gf *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "unpin <profile> <type> <name>",
		Short: "Release a pin, leaving the package listed",
		Long: `Drop the version constraint from an entry and keep the entry.

The package stays a member of the profile and takes its type's version default
again. Removing the entry outright is 'bodega profile remove', and on a closed
type that is a different decision: the package stops being permitted at all.`,
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
			idx := slices.IndexFunc(d.Entries, func(e audit.ProfileEntry) bool {
				return e.Type == typ && e.Name == name
			})
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
			e.Constraint, e.Version, e.Actor = "", "", audit.CurrentActor()
			if _, err := adb.PutProfileEntry(ctx, e); err != nil {
				return err
			}
			recordProfileEvent(ctx, adb, audit.EventEdit, profile, typ+"/"+name, "unpin")
			fmt.Printf("Released the pin on %s/%s in %s; it takes the %s version default again.\n",
				typ, name, profile, typ)
			return nil
		},
	}
}

// putProfileEntry is the one write behind add and pin.
func putProfileEntry(gf *globalFlags, profile, typ, name string, e audit.ProfileEntry) error {
	if err := requirePackageType(typ); err != nil {
		return err
	}
	if e.Constraint != "" && e.Constraint != manifest.ConstraintAny && e.Version == "" {
		return fmt.Errorf("constraint %s is measured against a version and none was given: --version <v>", e.Constraint)
	}
	ctx := backgroundCtx()
	adb, err := openProfileStore(gf)
	if err != nil {
		return err
	}
	defer adb.Close()

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

// lastEntryOfClosedType reports whether removing this entry would leave a
// closed type with nothing listed.
func lastEntryOfClosedType(d *audit.ProfileDetail, typ, name string) bool {
	closed := slices.ContainsFunc(d.Types, func(t audit.ProfileTypeRule) bool {
		return t.Type == typ && t.Membership == audit.MembershipClosed
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

			onHost := map[string]originPackage{}
			for _, p := range found {
				onHost[p.Type+"/"+p.Name] = p
			}
			inProfile := map[string]audit.ProfileEntry{}
			for _, e := range d.Entries {
				inProfile[e.Type+"/"+e.Name] = e
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
				fmt.Fprintf(w, "  %s\t%s\n", k, strings.Join(onHost[k].Versions, ", "))
			}
			fmt.Fprintf(w, "\nIn %s, not on %s (%d):\n", profile, origin, len(profileOnly))
			for _, k := range profileOnly {
				e := inProfile[k]
				fmt.Fprintf(w, "  %s\t%s\n", k, orDash(e.Constraint+" "+e.Version))
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
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			for _, name := range names {
				d, err := adb.GetProfile(ctx, name)
				if err != nil {
					return err
				}
				resolved := entitle.New(checkView(d))
				for _, e := range d.Entries {
					reason := entryResolves(ctx, store, resolved, e)
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
func entryResolves(ctx context.Context, store *manifest.Store, p *entitle.Profile, e audit.ProfileEntry) string {
	pm, err := store.GetPackage(ctx, e.Type, e.Name)
	if err != nil || pm == nil {
		return "no " + e.Type + " package by that name in the catalog"
	}
	var have []string
	for _, ve := range pm.Versions {
		if p.Permits(e.Type, e.Name, ve.Version).Permitted {
			return ""
		}
		have = append(have, ve.Version)
	}
	if len(have) == 0 {
		return "the catalog holds the package with no versions"
	}
	return fmt.Sprintf("%s permits none of the cataloged versions (%s)",
		orDash(strings.TrimSpace(e.Constraint+" "+e.Version)), strings.Join(have, ", "))
}

// originPackage is one cataloged package that names a host as an origin.
type originPackage struct {
	Type     string
	Name     string
	Versions []string
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
			for _, ve := range pm.Versions {
				if slices.Contains(admit.Origins(ve), origin) {
					versions = append(versions, ve.Version)
				}
			}
			if len(versions) > 0 {
				out = append(out, originPackage{Type: typ, Name: pm.Name, Versions: versions})
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
