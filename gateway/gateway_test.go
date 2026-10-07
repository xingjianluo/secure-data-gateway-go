package gateway

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// ---- 测试夹具 ----

func testSubjects() []Subject {
	return []Subject{
		{ID: "alice", Department: "engineering", Role: "engineer", Clearance: LevelConfidential},
		{ID: "bob", Department: "sales", Role: "rep", Clearance: LevelInternal},
		{ID: "carol", Department: "legal", Role: "counsel", Clearance: LevelConfidential},
		{ID: "admin", Department: "engineering", Role: "admin", Clearance: LevelSecret},
	}
}

func testPolicyV1() *Policy {
	return &Policy{
		Version:      "1.0.0",
		MinSupported: "1.0.0",
		Rules: []Rule{
			{ID: "eng-read", Departments: []string{"engineering"}, Actions: []Action{ActionRead}, MinLevel: LevelInternal, Description: "工程部门只读"},
			{ID: "sales-read", Departments: []string{"sales"}, Actions: []Action{ActionRead}, MinLevel: LevelPublic, Description: "销售部门只读"},
			{ID: "eng-admin-write", Departments: []string{"engineering"}, Roles: []string{"admin"}, Actions: []Action{ActionWrite, ActionDelete}, MinLevel: LevelSecret, Description: "工程管理员写删"},
		},
		FieldModes: map[Level]map[Action]FieldMode{
			LevelInternal:     {ActionRead: FieldMask},
			LevelConfidential: {ActionRead: FieldTokenize},
			LevelSecret:       {ActionRead: FieldDrop},
		},
	}
}

func customerLevels() map[string]Level {
	return map[string]Level{
		"name":  LevelPublic,       // 原样
		"phone": LevelInternal,     // 打码
		"email": LevelConfidential, // 令牌化
		"ssn":   LevelSecret,       // 整体剔除
	}
}

func customerData() map[string]any {
	return map[string]any{
		"name":  "Alice Wang",
		"phone": "13812345678",
		"email": "alice@example.com",
		"ssn":   "110101199001011234",
	}
}

func newFixture(t *testing.T) (*Gateway, *bytes.Buffer) {
	t.Helper()
	var log bytes.Buffer
	cat := NewCatalog(testSubjects()...)
	store := NewStore(testPolicyV1())
	gw := New(cat, store, []byte("unit-test-token-secret"), &log)
	ds := NewDataSource()
	ds.Put("cust-1", customerData(), customerLevels())
	// 一条 secret 级资源，用于级别不足场景。
	ds.Put("cust-secret", map[string]any{"name": "Top", "blueprint": "X"},
		map[string]Level{"name": LevelPublic, "blueprint": LevelSecret})
	gw.UseDataSource(ds)
	return gw, &log
}

func readReq(subject, resource string, lvl Level) AccessRequest {
	return AccessRequest{
		SubjectID: subject,
		Action:    ActionRead,
		Resource:  Resource{ID: resource, Level: lvl, Fields: customerLevels()},
	}
}

// ---- 场景一：未知主体必须拒绝，且原因可区分 ----

func TestUnknownSubjectDenied(t *testing.T) {
	gw, _ := newFixture(t)
	req := readReq("ghost", "cust-1", LevelInternal)

	out, d, err := gw.AccessRecord(req, customerData())
	t.Logf("输入: subject_id=%q action=%s resource=%q level=%d", req.SubjectID, req.Action, req.Resource.ID, req.Resource.Level)
	t.Logf("判定依据: allowed=%t reason=%q basis=%v", d.Allowed, d.Reason, d.MatchedRules)

	if out != nil {
		t.Fatalf("未知主体不得返回任何数据, got %v", out)
	}
	if d.Reason != DenyUnknownSubject || !errors.Is(err, ErrUnknownSubject) {
		t.Fatalf("期望 unknown_subject, got reason=%q err=%v", d.Reason, err)
	}
}

// ---- 场景二：各类拒绝归属必须彼此可区分，绝不静默放行 ----

func TestDenyReasonsAreDistinguishable(t *testing.T) {
	gw, _ := newFixture(t)

	cases := []struct {
		name     string
		req      AccessRequest
		reason   DenyReason
		sentinel error
	}{
		{"操作被拒(alice写)", AccessRequest{SubjectID: "alice", Action: ActionWrite, Resource: Resource{ID: "cust-1", Level: LevelInternal, Fields: customerLevels()}}, DenyActionDenied, ErrAccessDenied},
		{"级别不足(alice读secret)", readReq("alice", "cust-secret", LevelSecret), DenyLevelInsufficient, ErrAccessDenied},
		{"无规则覆盖(carol部门无规则)", readReq("carol", "cust-1", LevelInternal), DenyNoMatchingRule, ErrAccessDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := customerData()
			if tc.req.Resource.ID == "cust-secret" {
				data = map[string]any{"name": "Top", "blueprint": "X"}
			}
			out, d, err := gw.AccessRecord(tc.req, data)
			t.Logf("输入: subject=%q action=%s resource=%q resource_level=%d",
				tc.req.SubjectID, tc.req.Action, tc.req.Resource.ID, tc.req.Resource.Level)
			t.Logf("判定依据: allowed=%t reason=%q matched=%v err=%v",
				d.Allowed, d.Reason, d.MatchedRules, err)

			if d.Allowed || out != nil {
				t.Fatalf("必须拒绝且无数据输出, allowed=%v out=%v", d.Allowed, out)
			}
			if d.Reason != tc.reason {
				t.Fatalf("拒绝原因期望 %q, 实得 %q", tc.reason, d.Reason)
			}
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("错误期望包裹 %v, 实得 %v", tc.sentinel, err)
			}
		})
	}

	// 资源不存在：归属为 resource_missing（数据问题），
	// 与任何策略类归属（policy_not_found / no_matching_rule）严格区分。
	t.Run("资源不存在(不混入策略归属)", func(t *testing.T) {
		req := readReq("alice", "no-such-resource", LevelInternal)
		out, d, err := gw.Access(req)
		t.Logf("输入: subject=%q resource=%q -> allowed=%t reason=%q err=%v",
			req.SubjectID, req.Resource.ID, d.Allowed, d.Reason, err)
		if out != nil || d.Allowed {
			t.Fatalf("资源不存在必须拒绝且无数据输出, allowed=%v out=%v", d.Allowed, out)
		}
		if d.Reason != DenyResourceMissing {
			t.Fatalf("资源不存在应归属 %q, 实得 %q", DenyResourceMissing, d.Reason)
		}
		if !errors.Is(err, ErrResourceMissing) {
			t.Fatalf("错误期望包裹 %v, 实得 %v", ErrResourceMissing, err)
		}
		// 资源缺失也必须有审计留痕，且归属与判定一致。
		recs := gw.Audit().Records()
		last := recs[len(recs)-1]
		if last.Decision.Reason != DenyResourceMissing {
			t.Fatalf("资源缺失的审计归属应为 %q, 实得 %q", DenyResourceMissing, last.Decision.Reason)
		}
	})

	// 全部拒绝归属互不相等，防止被静默归为同一类。
	reasons := []DenyReason{
		DenyUnknownSubject, DenyPolicyNotFound, DenyNoMatchingRule,
		DenyResourceMissing, DenyActionDenied, DenyLevelInsufficient,
	}
	for i := range reasons {
		for j := i + 1; j < len(reasons); j++ {
			if reasons[i] == reasons[j] {
				t.Fatalf("拒绝归属不得相同: %q", reasons[i])
			}
		}
	}
}

// ---- 场景三：系统里根本没有可用策略时，归属 policy_not_found ----
// 与“有策略但主体无规则覆盖”（no_matching_rule）严格区分。

func TestNoPolicyAtAll(t *testing.T) {
	cat := NewCatalog(testSubjects()...)
	gw := New(cat, NewStore(nil), []byte("k"), nil)
	_, d, err := gw.AccessRecord(readReq("alice", "cust-1", LevelInternal), customerData())
	t.Logf("无策略存储: subject=%q -> allowed=%t reason=%q err=%v",
		"alice", d.Allowed, d.Reason, err)
	if d.Reason != DenyPolicyNotFound || !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("无策略应 policy_not_found, got %q %v", d.Reason, err)
	}
	if d.Reason == DenyNoMatchingRule {
		t.Fatal("无可用策略不得与无规则覆盖混淆")
	}
}

// ---- 场景四：脱敏/令牌化结果重复与并发一致，无权字段整体剔除 ----

func TestMaskingConsistencyAndDrop(t *testing.T) {
	gw, _ := newFixture(t)
	req := readReq("alice", "cust-1", LevelInternal)

	out1, d1, err := gw.AccessRecord(req, customerData())
	if err != nil || !d1.Allowed {
		t.Fatalf("首次访问应放行, err=%v decision=%+v", err, d1)
	}
	t.Logf("输入字段=%v; 判定依据=%v; 首次输出=%v", customerData(), d1.MatchedRules, out1)

	// 无权字段必须整体剔除：无键、无空值、无占位符。
	if _, exists := out1["ssn"]; exists {
		t.Fatalf("ssn 无权访问, 必须整体剔除而非占位, got %v", out1)
	}
	// phone 打码但保留可读首尾；email 令牌化且不含明文。
	if out1["phone"] != "1****8" {
		t.Fatalf("phone 打码结果异常: %v", out1["phone"])
	}
	emailTok, ok := out1["email"].(string)
	if !ok || emailTok == "alice@example.com" || emailTok[:4] != "tok_" {
		t.Fatalf("email 必须为不可逆令牌, got %v", out1["email"])
	}

	// 重复访问输出一致。
	out2, _, _ := gw.AccessRecord(req, customerData())
	if fmt.Sprint(out1) != fmt.Sprint(out2) {
		t.Fatalf("重复访问脱敏结果必须一致:\n%v\n%v", out1, out2)
	}

	// 并发访问输出一致。
	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			o, _, e := gw.AccessRecord(req, customerData())
			if e != nil || fmt.Sprint(o) != fmt.Sprint(out1) {
				errs <- fmt.Errorf("并发输出不一致: %v err=%v", o, e)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}

	// 状态“重载”（同密钥新建脱敏器）后令牌仍一致，且不可逆。
	fresh := NewMasker([]byte("unit-test-token-secret"))
	reTok, _, _ := fresh.Project(testPolicyV1(), mustSubject(gw, "alice"), ActionRead, customerData(), customerLevels())
	if reTok["email"] != emailTok {
		t.Fatalf("重载后令牌必须保持一致: %v != %v", reTok["email"], emailTok)
	}

	// 不同密钥产生不同令牌，证明无明文可还原路径之外的隔离性。
	projectOther := NewMasker([]byte("another-secret")).Project
	alt, _, _ := projectOther(testPolicyV1(), mustSubject(gw, "alice"), ActionRead, customerData(), customerLevels())
	if alt["email"] == emailTok {
		t.Fatal("不同密钥的令牌不应相同")
	}
}

func mustSubject(gw *Gateway, id string) Subject {
	s, ok := gw.catalog.Get(id)
	if !ok {
		panic("subject missing: " + id)
	}
	return s
}

// ---- 场景五：两个入口的判定与脱敏结论一致 ----

func TestTwoEntriesConsistent(t *testing.T) {
	gw, _ := newFixture(t)
	req := readReq("alice", "cust-1", LevelInternal)

	fromStore, dStore, err := gw.Access(req) // 入口一：按资源 ID 取数
	if err != nil {
		t.Fatal(err)
	}
	fromCaller, dCaller, err := gw.AccessRecord(req, customerData()) // 入口二：自带数据
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(fromStore) != fmt.Sprint(fromCaller) {
		t.Fatalf("两个入口输出必须一致:\n%v\n%v", fromStore, fromCaller)
	}
	if dStore.PolicyVersion != dCaller.PolicyVersion ||
		dStore.Reason != dCaller.Reason || dStore.PolicyID != dCaller.PolicyID {
		t.Fatalf("两个入口判定结论必须一致: %+v vs %+v", dStore, dCaller)
	}
}

// ---- 场景六：审计记录包含输入与判定依据，日志可读 ----

func TestAuditRecordContainsBasis(t *testing.T) {
	gw, logBuf := newFixture(t)
	req := readReq("alice", "cust-1", LevelInternal)
	out, d, _ := gw.AccessRecord(req, customerData())

	recs := gw.Audit().Records()
	if len(recs) != 1 {
		t.Fatalf("期望 1 条审计记录, got %d", len(recs))
	}
	r := recs[0]
	if r.Request.SubjectID != "alice" || r.Request.Action != ActionRead {
		t.Fatalf("审计输入不正确: %+v", r.Request)
	}
	if len(r.Decision.MatchedRules) == 0 || r.Decision.PolicyVersion != "1.0.0" {
		t.Fatalf("审计必须包含判定依据与策略版本: %+v", r.Decision)
	}
	if !containsStr(r.DroppedFields, "ssn") || !containsStr(r.OutputFields, "email") {
		t.Fatalf("审计字段清单异常 kept=%v dropped=%v", r.OutputFields, r.DroppedFields)
	}
	t.Logf("正常访问: 输入=%+v 判定依据=%v 输出=%v", req, d.MatchedRules, out)
	t.Logf("审计日志输出:\n%s", logBuf.String())
	if !bytes.Contains(logBuf.Bytes(), []byte("INPUT")) ||
		!bytes.Contains(logBuf.Bytes(), []byte("basis=[rule=eng-read")) {
		t.Fatal("审计日志必须打印输入与判定依据")
	}
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
