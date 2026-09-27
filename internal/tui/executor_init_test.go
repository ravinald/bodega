package tui

import (
	"bytes"
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/ravinald/bodega/internal/config"
	bos3 "github.com/ravinald/bodega/internal/s3"
	"github.com/ravinald/bodega/internal/storage"
)

// chainRegion is what the fake dialer reports for an entry that configures no
// region, standing in for AWS_REGION or a profile.
const chainRegion = "eu-west-1"

func fakeDial(dialed *[]string) storage.S3Dialer {
	return func(_ context.Context, bucket, region string) (*bos3.Client, error) {
		*dialed = append(*dialed, bucket)
		if region == "" {
			region = chainRegion
		}
		return bos3.NewClientFromConfig(aws.Config{Region: region}, bucket, region), nil
	}
}

type initCall struct{ bucket, region string }

func fakeInitBucket(calls *[]initCall) initBucketFunc {
	return func(_ context.Context, _ bos3.BucketAPI, _ io.Writer, bucket, region string) error {
		*calls = append(*calls, initCall{bucket, region})
		return nil
	}
}

func pressI(t *testing.T, m appModel) (appModel, tea.Cmd) {
	t.Helper()
	next, cmd := m.handleSourcesKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("I")})
	return next.(appModel), cmd
}

// TestInitRefusesLocalDefaultWithoutDialing is the install B96 names: the
// local driver with a bucket key left over. I must print what `bodega init`
// prints and reach nothing in AWS.
func TestInitRefusesLocalDefaultWithoutDialing(t *testing.T) {
	cfg := &config.Config{Bucket: "stray", Region: "us-west-2"}
	m := newAppModel(cfg, nil, nil, nil, nil)
	m.dialS3 = func(context.Context, string, string) (*bos3.Client, error) {
		t.Fatal("I dialed AWS for a local-driver backend")
		return nil, nil
	}
	m.initBucket = func(context.Context, bos3.BucketAPI, io.Writer, string, string) error {
		t.Fatal("I initialized a bucket for a local-driver backend")
		return nil
	}

	m, cmd := pressI(t, m)
	if m.popup.Active() {
		t.Fatalf("I opened popup kind %d for a local-driver backend", m.popup.kind)
	}
	if cmd == nil {
		t.Fatal("I returned no command, so nothing reports the refusal")
	}
	msg, ok := cmd().(cmdOutputMsg)
	if !ok {
		t.Fatalf("I produced %T, want a cmdOutputMsg carrying the refusal", msg)
	}
	_, want := storage.ResolveS3Target(cfg, storage.DefaultName)
	if msg.err == nil || want == nil || msg.err.Error() != want.Error() {
		t.Fatalf("err = %v, want the bodega init refusal %v", msg.err, want)
	}
	if !strings.Contains(msg.err.Error(), `"default" uses the local driver`) {
		t.Errorf("refusal does not name the driver: %v", msg.err)
	}
}

func TestInitOffersEachS3Backend(t *testing.T) {
	backends := map[string]config.StorageSpec{
		"nearby":  {Driver: "s3", Bucket: "nearby-bucket"},
		"archive": {Driver: "s3", Bucket: "archive-bucket", Region: "ap-south-1"},
		"bulk":    {Driver: "local", Path: "/srv/bulk"},
	}
	cases := []struct {
		name   string
		driver string
		want   []string
	}{
		{name: "s3 default", driver: "s3", want: []string{"default", "archive", "nearby"}},
		{name: "local default", driver: "local", want: []string{"archive", "nearby"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{StorageBackend: tc.driver, Bucket: "main-bucket", Region: "us-west-2", StorageBackends: backends}
			m, _ := pressI(t, newAppModel(cfg, nil, nil, nil, nil))
			if m.popup.kind != popupChoice {
				t.Fatalf("popup kind = %d, want the backend choice", m.popup.kind)
			}
			if !reflect.DeepEqual(m.popup.choices, tc.want) {
				t.Errorf("choices = %v, want %v", m.popup.choices, tc.want)
			}
		})
	}
}

// TestInitUsesTheResolvedRegion walks I end to end for a named entry with no
// region of its own, the case where the TUI used to create the bucket in
// cfg.Region while the service dialed wherever the SDK chain pointed.
func TestInitUsesTheResolvedRegion(t *testing.T) {
	cfg := &config.Config{
		StorageBackend: "s3", Bucket: "main-bucket", Region: "us-west-2",
		StorageBackends: map[string]config.StorageSpec{
			"nearby": {Driver: "s3", Bucket: "nearby-bucket", Prefix: "cold"},
		},
	}
	var dialed []string
	var calls []initCall
	m := newAppModel(cfg, nil, nil, nil, nil)
	m.dialS3 = fakeDial(&dialed)
	m.initBucket = fakeInitBucket(&calls)

	m, _ = pressI(t, m)
	var next tea.Model
	next, _ = m.handlePopupKey(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(appModel)
	next, cmd := m.handlePopupKey(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(appModel)
	if cmd == nil {
		t.Fatal("choosing a backend returned no command")
	}
	if len(dialed) != 0 {
		t.Fatalf("dialed %v before the command ran", dialed)
	}

	next, _ = m.Update(cmd())
	m = next.(appModel)
	if !reflect.DeepEqual(dialed, []string{"nearby-bucket"}) {
		t.Fatalf("dialed %v, want nearby-bucket alone", dialed)
	}
	if m.popup.kind != popupConfirm {
		t.Fatalf("popup kind = %d, want the confirmation", m.popup.kind)
	}
	for _, want := range []string{`"nearby"`, "s3://nearby-bucket", chainRegion} {
		if !strings.Contains(m.popup.message, want) {
			t.Errorf("confirmation %q does not name %s", m.popup.message, want)
		}
	}

	out, ok := m.popup.pendingAsyncCmd().(cmdOutputMsg)
	if !ok || out.err != nil {
		t.Fatalf("init = %+v, want success", out)
	}
	if want := []initCall{{"nearby-bucket", chainRegion}}; !reflect.DeepEqual(calls, want) {
		t.Errorf("InitBucket calls = %v, want %v (cfg.Region is %s)", calls, want, cfg.Region)
	}
	if !strings.Contains(out.output, "cold is not applied") {
		t.Errorf("output does not say the prefix is not applied:\n%s", out.output)
	}
}

func TestRunInitRefusesAnEmptyResolvedRegion(t *testing.T) {
	var calls []initCall
	target := storage.S3Target{Name: "nearby", Bucket: "nearby-bucket"}
	client := bos3.NewClientFromConfig(aws.Config{}, target.Bucket, "")
	var buf bytes.Buffer
	err := runInit(&buf, target, client, fakeInitBucket(&calls))
	if err == nil || !strings.Contains(err.Error(), `add "region" to that entry`) {
		t.Errorf("err = %v, want the missing-region refusal", err)
	}
	if len(calls) != 0 {
		t.Errorf("InitBucket ran with no region: %v", calls)
	}
}
