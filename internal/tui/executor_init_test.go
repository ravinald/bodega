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

func key(m appModel, k string) appModel {
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
	switch k {
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	}
	next, _ := m.Update(msg)
	return next.(appModel)
}

// blockingDial holds every dial until release is closed, so a test controls
// when a resolution reaches the event loop relative to the keys around it.
func blockingDial(started chan<- string, release <-chan struct{}) storage.S3Dialer {
	return func(ctx context.Context, bucket, region string) (*bos3.Client, error) {
		started <- bucket
		select {
		case <-release:
		case <-ctx.Done():
		}
		if region == "" {
			region = chainRegion
		}
		return bos3.NewClientFromConfig(aws.Config{Region: region}, bucket, region), nil
	}
}

func runAsync(cmd tea.Cmd) <-chan tea.Msg {
	out := make(chan tea.Msg, 1)
	go func() { out <- cmd() }()
	return out
}

// TestInitPendingHoldsTheScreen is the review's reproduction: I, then C while
// the dial is pending. The pending popup takes the C, so there is no form for
// the late confirmation to replace.
func TestInitPendingHoldsTheScreen(t *testing.T) {
	cfg := &config.Config{StorageBackend: "s3", Bucket: "main-bucket", Region: "us-west-2"}
	m := newAppModel(cfg, nil, nil, nil, nil)
	started, release := make(chan string, 1), make(chan struct{})
	m.dialS3 = blockingDial(started, release)

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("I")})
	m = next.(appModel)
	result := runAsync(cmd)
	<-started
	for _, k := range []string{"C", "x", "I"} {
		m = key(m, k)
		if m.popup.kind != popupInitPending {
			t.Fatalf("after %q popup kind = %d, want the pending init to keep the screen", k, m.popup.kind)
		}
	}
	close(release)
	next, _ = m.Update(<-result)
	m = next.(appModel)
	if m.popup.kind != popupConfirm || !strings.Contains(m.popup.message, "s3://main-bucket") {
		t.Fatalf("popup kind = %d message %q, want the main-bucket confirmation", m.popup.kind, m.popup.message)
	}
}

// TestCanceledInitLeavesLaterEditsAlone cancels a pending init, opens the
// config form and edits it; the canceled dial finishing afterwards must not
// touch the form.
func TestCanceledInitLeavesLaterEditsAlone(t *testing.T) {
	cfg := &config.Config{StorageBackend: "s3", Bucket: "main-bucket", Region: "us-west-2"}
	m := newAppModel(cfg, nil, nil, nil, nil)
	started := make(chan string, 1)
	m.dialS3 = blockingDial(started, make(chan struct{}))

	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("I")})
	m = next.(appModel)
	result := runAsync(cmd)
	<-started
	m = key(m, "esc")
	if m.popup.Active() {
		t.Fatalf("Esc left popup kind %d", m.popup.kind)
	}
	// The dial only returns because Esc canceled its context.
	late := <-result

	m = key(m, "C")
	m = key(m, "x")
	before := fieldValue(m.popup.formFields, "Bucket")
	if m.popup.kind != popupForm || before == cfg.Bucket {
		t.Fatal("setup did not open and edit the config form")
	}
	next, _ = m.Update(late)
	m = next.(appModel)
	if after := fieldValue(m.popup.formFields, "Bucket"); m.popup.kind != popupForm || after != before {
		t.Fatalf("canceled init replaced the form: before %q; after kind=%d bucket=%q message=%q",
			before, m.popup.kind, after, m.popup.message)
	}
}

// TestStaleInitDoesNotRetarget chooses one backend, cancels, chooses another,
// and delivers the first dial last and first: neither order may put the
// abandoned backend on the confirmation.
func TestStaleInitDoesNotRetarget(t *testing.T) {
	cfg := &config.Config{
		StorageBackend: "s3", Bucket: "main-bucket", Region: "us-west-2",
		StorageBackends: map[string]config.StorageSpec{
			"nearby": {Driver: "s3", Bucket: "nearby-bucket"},
		},
	}
	for _, staleLast := range []bool{false, true} {
		m := newAppModel(cfg, nil, nil, nil, nil)
		started, release := make(chan string, 2), make(chan struct{})
		m.dialS3 = blockingDial(started, release)

		m = key(m, "I")
		m = key(m, "j")
		next, stale := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m = next.(appModel)
		staleResult := runAsync(stale)
		if b := <-started; b != "nearby-bucket" {
			t.Fatalf("first dial reached %s, want nearby-bucket", b)
		}
		m = key(m, "esc")
		m = key(m, "I")
		next, fresh := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m = next.(appModel)
		freshResult := runAsync(fresh)
		<-started
		close(release)

		staleMsg, freshMsg := <-staleResult, <-freshResult
		order := []tea.Msg{staleMsg, freshMsg}
		if staleLast {
			order = []tea.Msg{freshMsg, staleMsg}
		}
		for _, msg := range order {
			next, _ = m.Update(msg)
			m = next.(appModel)
		}
		if m.popup.kind != popupConfirm || !strings.Contains(m.popup.message, `"default"`) ||
			strings.Contains(m.popup.message, "nearby") {
			t.Fatalf("staleLast=%v: popup kind=%d message %q, want the default confirmation alone",
				staleLast, m.popup.kind, m.popup.message)
		}
	}
}

func TestInitDialFailureClosesThePendingPopup(t *testing.T) {
	cfg := &config.Config{StorageBackend: "s3", Bucket: "main-bucket"}
	m := newAppModel(cfg, nil, nil, nil, nil)
	m.dialS3 = func(context.Context, string, string) (*bos3.Client, error) {
		return bos3.NewClientFromConfig(aws.Config{}, "main-bucket", ""), nil
	}
	next, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("I")})
	m = next.(appModel)
	next, _ = m.Update(cmd())
	m = next.(appModel)
	if m.popup.Active() {
		t.Fatalf("popup kind %d stayed open after the dial was refused", m.popup.kind)
	}
	last := m.log.outputLines[len(m.log.outputLines)-1]
	if !strings.Contains(last, "has no AWS region") {
		t.Errorf("log ends %q, want the missing-region refusal", last)
	}
}
