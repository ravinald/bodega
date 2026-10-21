package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// oneQueueRow returns the only open row, failing when there is not exactly
// one.
func oneQueueRow(t *testing.T, s *Server) audit.QueueRow {
	t.Helper()
	rows, err := s.auditDB.ListQueue(t.Context(), audit.QueueFilter{State: audit.QueueOpen})
	if err != nil {
		t.Fatalf("ListQueue: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("open queue rows = %+v, want one", rows)
	}
	return rows[0]
}

// An allow-list refusal on the proxy path queues a row with discover_mode
// off, carrying the exact name as the rule to add, and a repeat counts on
// the same row. Approving it admits the next request.
func TestAllowListRefusalQueuesWithDiscoveryOff(t *testing.T) {
	s := newDiscoveryServer(t)
	s.discoverMode = ""
	if err := s.store.AddVersion(t.Context(), manifest.TypeNpm, "leftpad", manifest.VersionEntry{
		Version: "1.2.0", Mode: manifest.ModeProxy,
	}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	if err := s.auditDB.InsertPolicy(t.Context(), audit.PolicyInfo{
		ID: "npm-elsewhere", RegistryType: manifest.TypeNpm, RuleKind: policy.KindPackage, Pattern: "rightpad",
	}); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	s.policy.Invalidate()

	var inc string
	for range 2 {
		rec := doRequest(s, http.MethodGet, "/npm/leftpad/-/leftpad-1.2.0.tgz", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
		}
		inc = refusalIncident(t, rec.Header(), checkAllowList)
	}
	q := oneQueueRow(t, s)
	if q.PkgType != manifest.TypeNpm || q.PkgName != "leftpad" || q.PkgVersion != "1.2.0" || q.Check != admit.QueueAllowList ||
		q.Pattern != "leftpad" || q.RequestCount != 2 || q.Incident != inc {
		t.Errorf("row = %+v", q)
	}
	if len(q.Requesters) != 1 || q.Requesters[0].ClientIP != "127.0.0.1" || q.Requesters[0].RequestCount != 2 {
		t.Errorf("requesters = %+v", q.Requesters)
	}

	if _, err := admit.ApproveQueued(t.Context(), s.auditDB, s.cfg, q.ID, "alice", admit.QueueApproval{Reason: "needed"}, time.Now()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	s.policy.Invalidate()
	if decision, violation, err := s.upstreamPolicyVerdict(t.Context(), manifest.TypeNpm, "leftpad"); err != nil || violation {
		t.Errorf("after approval: %s %v %v, want leftpad allowed", decision, violation, err)
	}
}

// An age refusal on the proxy fill path queues an age row.
func TestAgeRefusalQueues(t *testing.T) {
	stubAgeGate(t)
	s := newDiscoveryServer(t)
	s.cfg.NpmUpstream = "http://127.0.0.1:1"
	if err := s.store.AddVersion(t.Context(), manifest.TypeNpm, "leftpad", manifest.VersionEntry{Version: "1.2.0", Mode: manifest.ModeProxy}); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	if err := s.auditDB.SetAgePolicy(t.Context(), audit.AgePolicy{Ecosystem: manifest.TypeNpm, MinAgeSeconds: 86400, Action: policy.ActionBlock}); err != nil {
		t.Fatalf("set age policy: %v", err)
	}
	rec := doRequest(s, http.MethodGet, "/npm/leftpad/-/leftpad-1.2.0.tgz", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	q := oneQueueRow(t, s)
	if q.Check != admit.QueueAge || q.PkgName != "leftpad" || q.PkgVersion != "1.2.0" || q.Unwaivable != "" ||
		q.Incident != refusalIncident(t, rec.Header(), checkAge) {
		t.Errorf("row = %+v", q)
	}
}

// A profile refusal queues a profile row naming the profile and the host's
// identity; approving it pins the version and the next request is served.
func TestProfileRefusalQueuesAndApprovalAdmits(t *testing.T) {
	s := proxyingServer(t)
	seed(t, s, manifest.TypePypi, map[string]string{
		"pypi/wheels/django-5.0.0-py3-none-any.whl": "wheel",
	})
	f := bindProfile(t, s, "web", "web01",
		[]audit.ProfileTypeRule{closedRule(manifest.TypePypi, audit.VersionFloating, audit.ExpansionBlock)},
		[]audit.ProfileEntry{{Type: manifest.TypePypi, Name: "requests"}})

	if status, body := f.get(t, "/pypi/wheels/django-5.0.0-py3-none-any.whl"); status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", status, body)
	}
	q := oneQueueRow(t, s)
	if q.Check != admit.QueueProfile || q.PkgName != "django" || q.PkgVersion != "5.0.0" ||
		len(q.Profiles) != 1 || q.Profiles[0] != "web" || len(q.Requesters) != 1 || q.Requesters[0].Identity != "web01" {
		t.Fatalf("row = %+v", q)
	}
	if _, err := admit.ApproveQueued(t.Context(), s.auditDB, s.cfg, q.ID, "alice", admit.QueueApproval{Reason: "needed"}, time.Now()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	s.refreshProfiles(t.Context())
	if status, body := f.get(t, "/pypi/wheels/django-5.0.0-py3-none-any.whl"); status != http.StatusOK {
		t.Errorf("after approval: %d %s, want 200", status, body)
	}
}

// The OSV, malware and provenance results queue under their own checks, and
// the two hostile verdicts are recorded as unwaivable at the refusal.
func TestAdmissionResultsQueueUnderTheirChecks(t *testing.T) {
	s := newDenialServer(t, []string{"127.0.0.0/8"}, nil)
	for _, tc := range []struct {
		name, check string
		r           policy.Result
		unwaivable  bool
	}{
		{"advisory", admit.QueueOSV, policy.Result{Check: audit.CheckOSV, Details: map[string]any{"vulns": []string{"GHSA-x"}}}, false},
		{"malware", admit.QueueMalware, policy.Result{Check: audit.CheckOSV, Details: map[string]any{"malware": []string{"MAL-1"}}}, true},
		{"forged", admit.QueueProvenance, policy.Result{Check: audit.CheckUpstreamProvenance,
			Provenance: &audit.UpstreamProvenance{Outcome: audit.ProvenanceInvalid}}, true},
		{"lodahs", admit.QueueSimilarity, policy.Result{Check: audit.CheckNameSimilarity}, false},
	} {
		req := httptest.NewRequest(http.MethodGet, "/npm/x", nil)
		req.RemoteAddr = localAddr
		s.queueResult(req, manifest.TypeNpm, tc.name, "1.0.0", tc.r, newRefusal(checkOSV, manifest.TypeNpm, tc.name, "1.0.0", 403))
		rows, err := s.auditDB.ListQueue(t.Context(), audit.QueueFilter{Check: tc.check})
		if err != nil || len(rows) != 1 || rows[0].PkgName != tc.name || (rows[0].Unwaivable != "") != tc.unwaivable {
			t.Errorf("%s: rows = %+v (%v)", tc.name, rows, err)
		}
	}
}

// The API lists open rows to an admin address, resolves them under the
// token's identity, refuses to approve known malware, and needs a bound
// token for either resolution.
func TestQueueAPI(t *testing.T) {
	s := newOverrideServer(t)
	ctx := t.Context()
	for _, f := range []audit.QueueRefusal{
		{PkgType: manifest.TypeNpm, PkgName: "leftpad", PkgVersion: "1.2.0", Check: admit.QueueAllowList, Pattern: "leftpad"},
		{PkgType: manifest.TypeNpm, PkgName: "evil", PkgVersion: "1.0.0", Check: admit.QueueMalware, Unwaivable: "known malware is never overridden"},
		{PkgType: manifest.TypeNpm, PkgName: "lodahs", PkgVersion: "1.0.0", Check: admit.QueueAllowList, Pattern: "lodahs"},
	} {
		if err := s.auditDB.RecordRefusal(ctx, f, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	list := func(query string) []audit.QueueRow {
		t.Helper()
		rec := send(s, http.MethodGet, "/api/v1/queue"+query, localAddr, "", "")
		var rows []audit.QueueRow
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &rows) != nil {
			t.Fatalf("GET /api/v1/queue%s = %d %s", query, rec.Code, rec.Body)
		}
		return rows
	}
	rows := list("")
	if len(rows) != 3 {
		t.Fatalf("open rows = %+v", rows)
	}
	ids := map[string]string{}
	for _, q := range rows {
		ids[q.PkgName] = strconv.FormatInt(q.ID, 10)
	}
	if got := list("?check=malware"); len(got) != 1 || got[0].PkgName != "evil" {
		t.Errorf("?check=malware = %+v", got)
	}
	if rec := send(s, http.MethodGet, "/api/v1/queue?check=bogus", localAddr, "", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown check = %d", rec.Code)
	}

	approve := `{"reason":"needed"}`
	if rec := send(s, http.MethodPost, "/api/v1/queue/"+ids["leftpad"]+"/approve", localAddr, "", approve); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous approve = %d, want 401", rec.Code)
	}
	if rec := send(s, http.MethodPost, "/api/v1/queue/"+ids["leftpad"]+"/approve", localAddr, aliceToken, `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("approve with no reason = %d %s, want 400", rec.Code, rec.Body)
	}
	rec := send(s, http.MethodPost, "/api/v1/queue/"+ids["leftpad"]+"/approve", localAddr, aliceToken, approve)
	var res admit.QueueResolution
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &res) != nil || res.Rule == nil ||
		res.Rule.CreatedBy != "alice" || res.Row.ResolvedBy != "alice" {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body)
	}
	if rec := send(s, http.MethodPost, "/api/v1/queue/"+ids["leftpad"]+"/approve", localAddr, bobToken, approve); rec.Code != http.StatusConflict {
		t.Errorf("approving an approved row = %d, want 409", rec.Code)
	}

	rec = send(s, http.MethodPost, "/api/v1/queue/"+ids["evil"]+"/approve", localAddr, aliceToken, approve)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "malware") {
		t.Errorf("approving malware = %d %s, want 409 naming malware", rec.Code, rec.Body)
	}

	rec = send(s, http.MethodPost, "/api/v1/queue/"+ids["lodahs"]+"/dismiss", localAddr, bobToken, `{"reason":"typo of lodash"}`)
	var dismissed audit.QueueRow
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &dismissed) != nil ||
		dismissed.State != audit.QueueDismissed || dismissed.ResolvedBy != "bob" {
		t.Errorf("dismiss = %d %s", rec.Code, rec.Body)
	}
	if rec := send(s, http.MethodPost, "/api/v1/queue/12345/dismiss", localAddr, bobToken, `{"reason":"x"}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown id = %d, want 404", rec.Code)
	}
	if got := list(""); len(got) != 1 || got[0].PkgName != "evil" {
		t.Errorf("open after resolving two = %+v, want evil alone", got)
	}

	events, _ := s.auditDB.Query(ctx, audit.Filter{EventType: audit.EventQueue})
	if len(events) != 2 {
		t.Errorf("queue events = %+v, want the approve and the dismiss", events)
	}
}

// An exact rule near a popular name is refused with the popular name and the
// distance in their own fields, and only a confirmation repeating that name
// writes it. A name that is not near one writes whatever the field holds.
func TestCreatePolicyConfirmsANearPopularName(t *testing.T) {
	s := newOverrideServer(t)
	create := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		return send(s, http.MethodPost, "/api/v1/policies", localAddr, aliceToken, body)
	}

	rec := create(`{"registry_type":"pypi","pattern":"reqeusts"}`)
	var refusal struct {
		Error       string `json:"error"`
		NearPopular string `json:"near_popular"`
		Distance    int    `json:"distance"`
	}
	if rec.Code != http.StatusConflict || json.Unmarshal(rec.Body.Bytes(), &refusal) != nil ||
		refusal.NearPopular != "requests" || refusal.Distance != 1 || !strings.Contains(refusal.Error, "confirm_near_popular") {
		t.Fatalf("unconfirmed = %d %s, want 409 naming requests at distance 1", rec.Code, rec.Body)
	}
	if rules, err := s.auditDB.ListPolicies(t.Context()); err != nil || len(rules) != 0 {
		t.Fatalf("rules after a refusal = %+v %v", rules, err)
	}
	if rec := create(`{"registry_type":"pypi","pattern":"reqeusts","confirm_near_popular":"urllib3"}`); rec.Code != http.StatusConflict {
		t.Errorf("confirming another package = %d %s, want 409", rec.Code, rec.Body)
	}

	if rec := create(`{"registry_type":"pypi","pattern":"reqeusts","confirm_near_popular":"requests"}`); rec.Code != http.StatusCreated {
		t.Fatalf("confirmed = %d %s, want 201", rec.Code, rec.Body)
	}
	newestCreate := func() string {
		t.Helper()
		events, err := s.auditDB.Query(t.Context(), audit.Filter{EventType: audit.EventCreate})
		if err != nil || len(events) == 0 {
			t.Fatalf("create events = %+v %v", events, err)
		}
		newest := events[0]
		for _, e := range events {
			if e.ID > newest.ID {
				newest = e
			}
		}
		return newest.Details
	}
	if d := newestCreate(); !strings.Contains(d, "near_popular=requests") || !strings.Contains(d, "distance=1") || !strings.Contains(d, "confirmed=yes") {
		t.Errorf("confirmed event details = %q", d)
	}
	// The rule exists now, so a repeat is a duplicate, not a name to confirm.
	rec = create(`{"registry_type":"pypi","pattern":"reqeusts"}`)
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), "near_popular") || !strings.Contains(rec.Body.String(), "already exists") {
		t.Errorf("repeat = %d %s, want 409 already exists without near_popular", rec.Code, rec.Body)
	}

	if rec := create(`{"registry_type":"pypi","pattern":"requests","confirm_near_popular":"urllib3"}`); rec.Code != http.StatusCreated {
		t.Fatalf("a popular name = %d %s, want 201", rec.Code, rec.Body)
	}
	if d := newestCreate(); strings.Contains(d, "near_popular") {
		t.Errorf("a name near nothing recorded %q", d)
	}
}

// The queue API refuses an allow-list row near a popular name with a 400
// that names the field, and leaves the row open for a confirmed approval.
func TestQueueAPIConfirmsANearPopularName(t *testing.T) {
	s := newOverrideServer(t)
	if err := s.auditDB.RecordRefusal(t.Context(), audit.QueueRefusal{PkgType: manifest.TypePypi, PkgName: "reqeusts",
		PkgVersion: "2.0.0", Check: admit.QueueAllowList, Pattern: "reqeusts"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/queue/" + strconv.FormatInt(oneQueueRow(t, s).ID, 10) + "/approve"
	rec := send(s, http.MethodPost, path, localAddr, aliceToken, `{"reason":"needed"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "confirm_near_popular") {
		t.Fatalf("unconfirmed approve = %d %s, want 400 naming confirm_near_popular", rec.Code, rec.Body)
	}
	oneQueueRow(t, s)
	if rec := send(s, http.MethodPost, path, localAddr, aliceToken, `{"reason":"needed","confirm_near_popular":"requests"}`); rec.Code != http.StatusOK {
		t.Errorf("confirmed approve = %d %s, want 200", rec.Code, rec.Body)
	}
}
