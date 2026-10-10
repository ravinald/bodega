package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/inventory/reconcile"
	"github.com/ravinald/bodega/internal/manifest"
)

// invCLI is a config on disk with one cyclonedx source, and the frame a
// running server would ingest through, so the commands read what a push
// would have stored.
type invCLI struct {
	dir, manifests string
	gf             *globalFlags
	db             *audit.DB
	frame          *inventory.Frame
	inst           *inventory.Instance
}

func newInvCLI(t *testing.T) *invCLI {
	t.Helper()
	dir := t.TempDir()
	c := &invCLI{dir: dir, manifests: filepath.Join(dir, "manifests"), gf: &globalFlags{}}
	adbPath := filepath.Join(dir, "audit.db")
	body := fmt.Sprintf(`{"storage_backend":"local","storage_path":%q,"manifest_dir":%q,"audit_db":%q,"log_dir":%q,
"allow_plaintext":true,"apt_codename":"noble","pypi_upstream":"https://pypi.example.org",
"inventory_sources":{"cdx":{"type":"cyclonedx","enabled":true}}}`,
		filepath.Join(dir, "storage"), c.manifests, adbPath, dir)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.manifests, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)
	db, err := audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	insts, err := inventory.Configure(map[string]config.InventorySource{"cdx": {"type": "cyclonedx", "enabled": true}})
	if err != nil {
		t.Fatal(err)
	}
	c.db, c.inst = db, insts[0]
	c.frame = inventory.NewFrame(insts, db, nil, nil)
	rc := &reconcile.Reconciler{DB: db, Catalog: manifest.NewLocalStore(c.manifests), Instances: insts}
	c.frame.OnReport = rc.Ingested
	return c
}

func (c *invCLI) push(t *testing.T, identity string, comps ...string) {
	t.Helper()
	doc := fmt.Sprintf(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[%s]}`, strings.Join(comps, ","))
	b, err := c.inst.Source.Normalize([]byte(doc), identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.frame.Ingest(context.Background(), c.inst, inventory.Principal{ExternalID: identity, Identity: identity}, b); err != nil {
		t.Fatal(err)
	}
}

func cdxComp(purl, name, version string) string {
	return fmt.Sprintf(`{"name":%q,"version":%q,"purl":%q}`, name, version, purl)
}

func (c *invCLI) reconciler(t *testing.T) *reconcile.Reconciler {
	t.Helper()
	rc, done, err := openReconciler(c.gf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(done)
	return rc
}

// report alerts on unknown, groups worst first, filters by --class without
// changing the verdict, and prints the same thing as JSON.
func TestInventoryReportAlertsAndFilters(t *testing.T) {
	c := newInvCLI(t)
	if err := c.db.Record(context.Background(), audit.Event{EventType: audit.EventServeFetch, PkgType: "pypi",
		PkgName: "requests", PkgVersion: "2.31.0", Identity: "web-01", ObjectKey: "pypi/wheels/requests-2.31.0-py3-none-any.whl"}); err != nil {
		t.Fatal(err)
	}
	c.push(t, "web-01",
		cdxComp("pkg:pypi/requests@2.31.0", "requests", "2.31.0"),
		cdxComp("pkg:pypi/leftpad@0.1", "leftpad", "0.1"),
	)
	rc := c.reconciler(t)
	ctx := context.Background()

	var out bytes.Buffer
	alert, err := runInventoryReport(ctx, &out, rc, "web-01", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if !alert {
		t.Error("an unknown component must make report exit 1")
	}
	if i, j := strings.Index(text, "UNKNOWN (1)"), strings.Index(text, "SERVED (1)"); i < 0 || j < 0 || i > j {
		t.Errorf("want UNKNOWN before SERVED:\n%s", text)
	}
	for _, want := range []string{"pypi leftpad 0.1  [cdx]", "no catalog entry", "SOURCES", "cdx"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}

	out.Reset()
	alert, err = runInventoryReport(ctx, &out, rc, "web-01", []string{reconcile.ClassServed}, true)
	if err != nil {
		t.Fatal(err)
	}
	var rep reconcile.HostReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !alert || !rep.Alert || len(rep.Components) != 1 || rep.Components[0].Name != "requests" {
		t.Errorf("--class served --json: alert %v, components %+v; want requests alone and the host's verdict kept", alert, rep.Components)
	}
	if _, err := runInventoryReport(ctx, &out, rc, "web-01", []string{"bogus"}, false); err == nil {
		t.Error("an unknown --class was accepted")
	}

	out.Reset()
	if err := runInventoryHosts(ctx, &out, rc, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "web-01") {
		t.Errorf("hosts lacks web-01:\n%s", out.String())
	}
}

// accept records actor, time and comment; baseline shows them; the next
// report reads the accepted components as baseline.
func TestInventoryAcceptAndBaseline(t *testing.T) {
	c := newInvCLI(t)
	c.push(t, "web-01", cdxComp("pkg:deb/debian/bash@5.2.15-2", "bash", "5.2.15-2"))

	accept := newInventoryAcceptCmd(c.gf)
	accept.SetArgs([]string{"web-01", "--comment", "golden image"})
	accept.SilenceUsage, accept.SilenceErrors = true, true
	out := captureStdout(t, func() {
		if err := accept.Execute(); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Accepted 1 components") {
		t.Errorf("accept printed %q", out)
	}

	var buf bytes.Buffer
	if err := runInventoryBaseline(context.Background(), &buf, c.reconciler(t), "web-01", false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"comment: golden image", "accepted ", "bash", "5.2.15-2", audit.CurrentActor()} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("baseline lacks %q:\n%s", want, buf.String())
		}
	}

	c.push(t, "web-01", cdxComp("pkg:deb/debian/bash@5.2.15-2", "bash", "5.2.15-2"))
	rep, err := c.reconciler(t).Host(context.Background(), "web-01")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Alert || rep.Components[0].Class != reconcile.ClassBaseline {
		t.Errorf("after accept: %+v, want bash as baseline and no alert", rep.Components)
	}

	bad := newInventoryAcceptCmd(c.gf)
	bad.SetArgs([]string{"web-01", "--profile", "web"})
	bad.SilenceUsage, bad.SilenceErrors = true, true
	if err := bad.Execute(); err == nil {
		t.Error("an identity and --profile together were accepted")
	}
}

// An unknown inventory component promotes to a manifest entry the way a
// no_manifest row does; a served one does not promote.
func TestDiscoverPromoteFromInventory(t *testing.T) {
	c := newInvCLI(t)
	if err := c.db.Record(context.Background(), audit.Event{EventType: audit.EventServeFetch, PkgType: "pypi",
		PkgName: "requests", PkgVersion: "2.31.0", Identity: "web-01", ObjectKey: "pypi/wheels/requests-2.31.0-py3-none-any.whl"}); err != nil {
		t.Fatal(err)
	}
	c.push(t, "web-01",
		cdxComp("pkg:pypi/Left_Pad@0.1", "Left_Pad", "0.1"),
		cdxComp("pkg:pypi/requests@2.31.0", "requests", "2.31.0"),
		cdxComp("pkg:deb/debian/htop@3.2.2-2", "htop", "3.2.2-2"),
	)

	run := func(args ...string) (string, error) {
		var err error
		out := captureStdout(t, func() {
			cmd := newDiscoverPromoteCmd(c.gf)
			cmd.SetArgs(args)
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			err = cmd.Execute()
		})
		return out, err
	}
	if out, err := run("pypi", "left-pad", "--inventory", "web-01"); err != nil || !strings.Contains(out, "+ pypi left-pad@0.1") {
		t.Fatalf("promote pypi: %v\n%s", err, out)
	}
	if _, err := run("apt", "htop", "--inventory", "web-01"); err != nil {
		t.Fatalf("promote apt: %v", err)
	}
	store := manifest.NewLocalStore(c.manifests)
	pm, err := store.GetPackage(context.Background(), "pypi", "left-pad")
	if err != nil || pm == nil || len(pm.Versions) != 1 {
		t.Fatalf("left-pad manifest = %+v, %v", pm, err)
	}
	if ve := pm.Versions[0]; ve.Version != "0.1" || ve.Mode != manifest.ModeProxy || ve.URL != "https://pypi.example.org" {
		t.Errorf("left-pad entry = %+v, want 0.1 proxied from the configured pypi upstream", ve)
	}
	apt, err := store.GetPackage(context.Background(), "apt", "htop")
	if err != nil || apt == nil || apt.Versions[0].Version != "3.2.2-2" || apt.Versions[0].SourceName != "htop" {
		t.Errorf("htop manifest = %+v, %v; want 3.2.2-2 fetched by its source name", apt, err)
	}

	if _, err := run("pypi", "requests", "--inventory", "web-01"); err == nil || !strings.Contains(err.Error(), "served") {
		t.Errorf("promoting a served component: err = %v, want a refusal naming its class", err)
	}
	if _, err := run("pypi", "left-pad", "--inventory", "web-01", "--as", "policy"); err == nil {
		t.Error("--inventory with --as policy was accepted")
	}
}
