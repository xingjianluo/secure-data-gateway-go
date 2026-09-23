package gateway_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/secure-data-gateway-go/audit"
	"github.com/xingjianluo/secure-data-gateway-go/authz"
	"github.com/xingjianluo/secure-data-gateway-go/gateway"
	"github.com/xingjianluo/secure-data-gateway-go/mask"
	"github.com/xingjianluo/secure-data-gateway-go/model"
	"github.com/xingjianluo/secure-data-gateway-go/policy"
	"github.com/xingjianluo/secure-data-gateway-go/server"
	"github.com/xingjianluo/secure-data-gateway-go/store"
)

func setup(t *testing.T) *gateway.Gateway {
	t.Helper()
	dir := store.NewDirectory()
	data := store.NewDataSource()
	pols := policy.NewStore()

	dir.AddSubject(model.Subject{ID: "u-intern", Clearance: model.SensInternal,
		Attributes: map[string]string{"role": "intern"}, Departments: []string{"engineering"}})
	dir.AddSubject(model.Subject{ID: "u-eng", Clearance: model.SensConfidential,
		Attributes: map[string]string{"role": "engineer"}, Departments: []string{"engineering"}})

	dir.AddResource(model.Resource{ID: "emp-1", OwnerID: "u-eng", Sensitivity: model.SensConfidential,
		Fields: []model.FieldSpec{
			{Name: "name", Level: model.SensPublic, RedactMode: model.RedactNone},
			{Name: "email", Level: model.SensInternal, RedactMode: model.RedactMask},
			{Name: "ssn", Level: model.SensConfidential, RedactMode: model.RedactToken},
			{Name: "salary", Level: model.SensRestricted, RedactMode: model.RedactNone},
		}})
	data.Put("emp-1", map[string]any{
		"name": "Alice", "email": "alice@example.com", "salary": 200000, "ssn": "123-45-6789",
	})

	if err := pols.Load(policyV1()); err != nil {
		t.Fatal(err)
	}
	return gateway.New(dir, data, pols, authz.New(dir), mask.New(), audit.NewLog())
}

func policyV1() *model.Policy {
	return &model.Policy{
		SchemaVersion: "1.0.0", Version: 1, DefaultEffect: "deny", TokenSecret: "secret-v1",
		Rules: []model.Rule{
			{Name: "eng-read-conf", Effect: "allow", Actions: []model.Action{model.ActionRead},
				MinLevel: model.SensConfidential, MaxLevel: model.SensConfidential,
				Departments: []string{"engineering"}},
			{Name: "intern-read-internal", Effect: "allow", Actions: []model.Action{model.ActionRead},
				MinLevel: model.SensInternal, MaxLevel: model.SensInternal,
				Subject: map[string]string{"role": "intern"}},
		},
	}
}

func policyV2() *model.Policy {
	// 向后兼容的新版本：放开实习生对机密资源的读取（演示热更新改变结论）。
	return &model.Policy{
		SchemaVersion: "1.2.0", Version: 2, DefaultEffect: "deny", TokenSecret: "secret-v1",
		Rules: []model.Rule{
			{Name: "eng-read-conf", Effect: "allow", Actions: []model.Action{model.ActionRead},
				MinLevel: model.SensConfidential, MaxLevel: model.SensConfidential,
				Departments: []string{"engineering"}},
			{Name: "intern-read-conf-new", Effect: "allow", Actions: []model.Action{model.ActionRead},
				MinLevel: model.SensInternal, MaxLevel: model.SensConfidential,
				Subject: map[string]string{"role": "intern"}},
		},
	}
}

// TestAccessRecordsAuditBasis 审计事件必须包含输入、结论与逐条判定依据。
func TestAccessRecordsAuditBasis(t *testing.T) {
	gw := setup(t)
	res, ev := gw.Access("u-intern", "emp-1", model.ActionRead)

	t.Logf("INPUT: %s", ev.Input)
	t.Logf("DECISION BASIS: allowed=%v reason=%q hits=%+v default=%v",
		res.Decision.Allowed, res.Decision.Reason, res.Decision.Hits, res.Decision.DefaultUsed)
	t.Logf("FIELDS: data=%v dropped=%v", res.Data, res.DroppedFields)

	if res.Decision.Allowed || res.Decision.Reason != model.DenyNoPermission {
		t.Fatalf("intern denied under v1 expected, got allowed=%v reason=%q",
			res.Decision.Allowed, res.Decision.Reason)
	}
	all := gw.Audit().All()
	if len(all) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(all))
	}
	if all[0].Input == "" || len(all[0].Decision.Hits) == 0 {
		t.Fatal("audit event must record input and decision basis")
	}
	// 拒绝时不得返回任何业务字段（含空值占位）。
	if res.Data != nil {
		t.Fatalf("denied access must return no data fields, got %v", res.Data)
	}
}

// TestMaskingConsistentAcrossRepeatedAccess 同一主体重复访问脱敏结果一致。
func TestMaskingConsistentAcrossRepeatedAccess(t *testing.T) {
	gw := setup(t)
	r1, _ := gw.Access("u-eng", "emp-1", model.ActionRead)
	r2, _ := gw.Access("u-eng", "emp-1", model.ActionRead)

	if fmt.Sprint(r1.Data) != fmt.Sprint(r2.Data) {
		t.Fatalf("repeated access output differs: %v vs %v", r1.Data, r2.Data)
	}
	if _, ok := r1.Data["salary"]; ok {
		t.Fatal("salary above engineer clearance must be dropped")
	}
	t.Logf("input=(u-eng, emp-1, read) repeated output identical: %v; dropped=%v",
		r1.Data, r1.DroppedFields)
}

// TestConcurrentHotUpdateInFlightConsistency 热更新与持续并发判定同时进行：
// 更新窗口内每个判定必须落在某个完整版本（v1 拒绝 或 v2 放行），
// 绝不能出现半更新状态；同一版本下脱敏令牌保持一致；更新两侧的版本都要被观察到。
func TestConcurrentHotUpdateInFlightConsistency(t *testing.T) {
	gw := setup(t)

	const workers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		seenv1   bool
		seenv2   bool
		badCase  int
		v2Tokens = map[string]struct{}{}
		stop     = make(chan struct{})
	)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				r, _ := gw.Access("u-intern", "emp-1", model.ActionRead)
				mu.Lock()
				switch r.Decision.PolicyVersion {
				case 1:
					seenv1 = true
					if r.Decision.Allowed {
						badCase++ // v1 下实习生必须被拒
					}
				case 2:
					seenv2 = true
					if !r.Decision.Allowed {
						badCase++ // v2 下放行
					} else {
						v2Tokens[fmt.Sprint(r.Data["ssn"])] = struct{}{}
					}
				default:
					badCase++
				}
				mu.Unlock()
			}
		}()
	}

	// 略微错开加载，使更新窗口两侧都有在途请求。
	time.Sleep(2 * time.Millisecond)
	if err := gw.Policies().Load(policyV2()); err != nil {
		t.Fatalf("hot load v2: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	close(stop)
	wg.Wait()

	t.Logf("concurrent+hot-update: sawV1=%v sawV2=%v badCases=%d distinctV2Tokens=%d",
		seenv1, seenv2, badCase, len(v2Tokens))

	if badCase != 0 {
		t.Fatalf("observed inconsistent in-flight decisions: %d", badCase)
	}
	if !seenv1 || !seenv2 {
		t.Fatalf("expected decisions under both complete snapshots, seenV1=%v seenV2=%v", seenv1, seenv2)
	}
	if len(v2Tokens) > 1 {
		t.Fatalf("token must stay consistent under same version, got %d distinct tokens", len(v2Tokens))
	}

	// 热更新后再访问必须稳定走 v2。
	r, _ := gw.Access("u-intern", "emp-1", model.ActionRead)
	if !r.Decision.Allowed || r.Decision.PolicyVersion != 2 {
		t.Fatalf("post-update access must be allowed under v2, got %+v", r.Decision)
	}
}

// TestReplayHistoricalVersion 新版本生效后，旧版本下的历史结论仍可复现。
func TestReplayHistoricalVersion(t *testing.T) {
	gw := setup(t)
	before, _ := gw.Access("u-intern", "emp-1", model.ActionRead)
	if before.Decision.Allowed {
		t.Fatal("v1 must deny intern")
	}
	if err := gw.Policies().Load(policyV2()); err != nil {
		t.Fatal(err)
	}
	after, _ := gw.Access("u-intern", "emp-1", model.ActionRead)
	if !after.Decision.Allowed {
		t.Fatal("v2 must allow intern")
	}

	replayed, err := gw.Replay("u-intern", "emp-1", model.ActionRead, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("historical replay v1: allowed=%v reason=%q basis=%+v",
		replayed.Allowed, replayed.Reason, replayed.Hits)

	if replayed.Allowed {
		t.Fatal("replayed v1 decision must reproduce the historical deny")
	}
	if replayed.PolicyVersion != 1 || replayed.Reason != before.Decision.Reason {
		t.Fatalf("replay mismatch: %+v", replayed)
	}
	// 复现当前 v2 结论也应一致。
	cur, _ := gw.Replay("u-intern", "emp-1", model.ActionRead, 2)
	if !cur.Allowed {
		t.Fatal("replay v2 should allow")
	}
}

// TestIncompatibleHotLoadKeepsOldUsable 不兼容加载被拒后，原策略仍可用。
func TestIncompatibleHotLoadKeepsOldUsable(t *testing.T) {
	gw := setup(t)
	bad := policyV2()
	bad.SchemaVersion = "2.0.0" // 主版本不兼容
	if err := gw.Policies().Load(bad); err == nil {
		t.Fatal("schema v2 must be rejected")
	} else {
		t.Logf("incompatible load rejected (old policy stays usable): %v", err)
	}
	r, _ := gw.Access("u-eng", "emp-1", model.ActionRead)
	if !r.Decision.Allowed || r.Decision.PolicyVersion != 1 {
		t.Fatalf("old v1 policy must remain active, got %+v", r.Decision)
	}
}

// TestHTTPEntryMatchesSDKEntry HTTP 入口与直接 SDK 调用结论一致。
func TestHTTPEntryMatchesSDKEntry(t *testing.T) {
	gw := setup(t)
	srv := httptest.NewServer(server.New(gw).Routes())
	defer srv.Close()

	// 同一次判定：SDK
	sdkRes, _ := gw.Access("u-eng", "emp-1", model.ActionRead)

	// HTTP
	resp, err := http.Get(srv.URL + "/data?subject_id=u-eng&resource_id=emp-1&action=read")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var httpBody map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&httpBody); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || httpBody["allowed"] != true {
		t.Fatalf("http entry mismatch: status=%d body=%v", resp.StatusCode, httpBody)
	}
	sdkSSN := fmt.Sprint(sdkRes.Data["ssn"])
	httpSSN := fmt.Sprint(httpBody["data"].(map[string]any)["ssn"])
	if sdkSSN != httpSSN {
		t.Fatalf("token differs across entries: sdk=%s http=%s", sdkSSN, httpSSN)
	}
	if _, present := httpBody["data"].(map[string]any)["salary"]; present {
		t.Fatal("http entry must also drop unauthorized fields")
	}
	t.Logf("cross-entry consistent: sdk token == http token == %s; http hits=%v",
		httpSSN, httpBody["hits"])

	// 拒绝原因经 HTTP 仍可区分：未知主体 403 unknown_subject。
	denyResp, err := http.Get(srv.URL + "/data?subject_id=u-ghost&resource_id=emp-1&action=read")
	if err != nil {
		t.Fatal(err)
	}
	defer denyResp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(denyResp.Body)
	if denyResp.StatusCode != http.StatusForbidden || !bytes.Contains(buf.Bytes(), []byte("unknown_subject")) {
		t.Fatalf("unknown_subject must be distinguishable over HTTP: %d %s",
			denyResp.StatusCode, buf.String())
	}
	t.Logf("http deny response: %s", buf.String())
}
