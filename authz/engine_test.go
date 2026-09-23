package authz

import (
	"testing"

	"github.com/xingjianluo/secure-data-gateway-go/model"
	"github.com/xingjianluo/secure-data-gateway-go/policy"
	"github.com/xingjianluo/secure-data-gateway-go/store"
)

func testPolicy() *model.Policy {
	return &model.Policy{
		SchemaVersion: "1.0.0", Version: 1,
		TokenSecret:   "test-secret",
		DefaultEffect: "deny",
		Rules: []model.Rule{
			{
				Name: "eng-read-conf", Effect: "allow",
				Actions:  []model.Action{model.ActionRead},
				MinLevel: model.SensConfidential, MaxLevel: model.SensConfidential,
				Departments: []string{"engineering"},
			},
			{
				Name: "owner-delete", Effect: "allow",
				Actions:    []model.Action{model.ActionDelete},
				OwnersOnly: true,
			},
		},
	}
}

func newTestEngine(t *testing.T) (*Engine, *store.Directory, *policy.Store) {
	t.Helper()
	dir := store.NewDirectory()
	dir.AddSubject(model.Subject{
		ID: "u-eng", Clearance: model.SensConfidential,
		Attributes:  map[string]string{"role": "engineer"},
		Departments: []string{"engineering"},
	})
	dir.AddSubject(model.Subject{
		ID: "u-intern", Clearance: model.SensInternal,
		Attributes:  map[string]string{"role": "intern"},
		Departments: []string{"engineering"},
	})
	dir.AddResource(model.Resource{
		ID: "r-conf", OwnerID: "u-eng", Sensitivity: model.SensConfidential,
	})
	dir.AddResource(model.Resource{
		ID: "r-restricted", OwnerID: "u-eng", Sensitivity: model.SensRestricted,
	})
	ps := policy.NewStore()
	if err := ps.Load(testPolicy()); err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return New(dir), dir, ps
}

// TestAllowEngineerReadConfidential 工程师可读机密资源，且判定依据记录命中规则。
func TestAllowEngineerReadConfidential(t *testing.T) {
	eng, _, ps := newTestEngine(t)
	d := eng.EvaluateRequest("u-eng", "r-conf", model.ActionRead, ps)

	t.Logf("input: subject=u-eng resource=r-conf action=read; decision: allowed=%v reason=%q msg=%q hits=%+v",
		d.Allowed, d.Reason, d.Message, d.Hits)

	if !d.Allowed || d.Reason != model.DenyNone {
		t.Fatalf("expected allow, got %v/%s", d.Allowed, d.Reason)
	}
	if d.Hits[0].RuleName != "eng-read-conf" || !d.Hits[0].Matched {
		t.Fatalf("expected first rule eng-read-conf matched, got %+v", d.Hits[0])
	}
}

// TestDenyNoPermission 实习生越权读取机密资源：no_permission，且依据列出级别不足。
func TestDenyNoPermission(t *testing.T) {
	eng, _, ps := newTestEngine(t)
	d := eng.EvaluateRequest("u-intern", "r-conf", model.ActionRead, ps)

	t.Logf("input: subject=u-intern resource=r-conf action=read; decision: allowed=%v reason=%q basis=%v",
		d.Allowed, d.Reason, d.Hits)

	if d.Allowed {
		t.Fatal("intern must not read confidential resource")
	}
	if d.Reason != model.DenyNoPermission {
		t.Fatalf("expected no_permission, got %q", d.Reason)
	}
	foundLevelReason := false
	for _, h := range d.Hits {
		for _, why := range h.Reasons {
			if contains(why, "clearance") {
				foundLevelReason = true
			}
		}
	}
	if !foundLevelReason {
		t.Fatal("decision basis must record clearance shortfall")
	}
}

// TestDenyResourceTooSensitive 机密级主体访问受限资源被拒，依据含 max level 不满足。
func TestDenyResourceTooSensitive(t *testing.T) {
	eng, _, ps := newTestEngine(t)
	d := eng.EvaluateRequest("u-eng", "r-restricted", model.ActionRead, ps)

	t.Logf("input: subject=u-eng resource=r-restricted action=read; reason=%q basis=%v",
		d.Reason, d.Hits)

	if d.Allowed || d.Reason != model.DenyNoPermission {
		t.Fatalf("expected deny no_permission, got allowed=%v reason=%q", d.Allowed, d.Reason)
	}
	if !contains(d.Message, "default effect") {
		t.Fatalf("expected default deny path, msg=%q", d.Message)
	}
}

// TestDenyUnknownSubject 未注册主体：unknown_subject，与其他拒绝原因可区分。
func TestDenyUnknownSubject(t *testing.T) {
	eng, _, ps := newTestEngine(t)
	d := eng.EvaluateRequest("u-ghost", "r-conf", model.ActionRead, ps)

	t.Logf("input: subject=u-ghost(unknown) resource=r-conf action=read; reason=%q msg=%q",
		d.Reason, d.Message)

	if d.Allowed {
		t.Fatal("unknown subject must be denied")
	}
	if d.Reason != model.DenyUnknownSubject {
		t.Fatalf("expected unknown_subject, got %q", d.Reason)
	}
}

// TestDenyResourceNotFound 资源不存在：resource_not_found。
func TestDenyResourceNotFound(t *testing.T) {
	eng, _, ps := newTestEngine(t)
	d := eng.EvaluateRequest("u-eng", "r-ghost", model.ActionRead, ps)

	t.Logf("input: subject=u-eng resource=r-ghost(unknown) action=read; reason=%q", d.Reason)

	if d.Allowed || d.Reason != model.DenyResourceNotFound {
		t.Fatalf("expected resource_not_found, got %v/%q", d.Allowed, d.Reason)
	}
}

// TestDenyPolicyMissing 无任何策略：policy_not_found。
func TestDenyPolicyMissing(t *testing.T) {
	eng, _, _ := newTestEngine(t)
	empty := policy.NewStore()
	d := eng.EvaluateRequest("u-eng", "r-conf", model.ActionRead, empty)

	t.Logf("input: subject=u-eng resource=r-conf action=read with empty policy store; reason=%q", d.Reason)

	if d.Allowed || d.Reason != model.DenyPolicyNotFound {
		t.Fatalf("expected policy_not_found, got %v/%q", d.Allowed, d.Reason)
	}
}

// TestDenyReasonsAreDistinct 三种失败原因必须互不相同，且不同于放行。
func TestDenyReasonsAreDistinct(t *testing.T) {
	eng, _, ps := newTestEngine(t)
	noPerm := eng.EvaluateRequest("u-intern", "r-conf", model.ActionRead, ps).Reason
	unknown := eng.EvaluateRequest("u-ghost", "r-conf", model.ActionRead, ps).Reason
	missing := eng.EvaluateRequest("u-eng", "r-conf", model.ActionRead, policy.NewStore()).Reason

	if noPerm == unknown || unknown == missing || noPerm == missing {
		t.Fatalf("deny reasons must be distinguishable: %q %q %q", noPerm, unknown, missing)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
