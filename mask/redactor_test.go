package mask

import (
	"fmt"
	"sync"
	"testing"

	"github.com/xingjianluo/secure-data-gateway-go/model"
)

func testResource() model.Resource {
	return model.Resource{
		ID:          "emp-1",
		Sensitivity: model.SensConfidential,
		Fields: []model.FieldSpec{
			{Name: "name", Level: model.SensPublic, RedactMode: model.RedactNone},
			{Name: "email", Level: model.SensInternal, RedactMode: model.RedactMask},
			{Name: "ssn", Level: model.SensConfidential, RedactMode: model.RedactToken},
			{Name: "salary", Level: model.SensRestricted, RedactMode: model.RedactNone},
		},
	}
}

func policyWithSecret(secret string) *model.Policy {
	return &model.Policy{Version: 1, TokenSecret: secret, DefaultEffect: "deny"}
}

// TestApplyDropInvisibleFields 超过主体级别的字段必须整体剔除，
// 输出 map 中不存在该键（而不是空值/占位符）。
func TestApplyDropInvisibleFields(t *testing.T) {
	r := New()
	sub := model.Subject{ID: "u-eng", Clearance: model.SensConfidential}
	rec := map[string]any{"name": "Alice", "email": "a@b.com", "ssn": "123", "salary": 9999}

	out, outcomes, dropped := r.Apply(rec, testResource(), sub, policyWithSecret("k"))

	t.Logf("input=%v subject clearance=confidential; output=%v dropped=%v outcomes=%+v",
		rec, out, dropped, outcomes)

	if _, present := out["salary"]; present {
		t.Fatal("restricted field must be removed entirely, not zeroed or placeheld")
	}
	if len(dropped) != 1 || dropped[0] != "salary" {
		t.Fatalf("dropped = %v, want [salary]", dropped)
	}
	if out["name"] != "Alice" {
		t.Fatal("public field should be returned verbatim")
	}
	if out["email"] != "a******" {
		t.Fatalf("email should be masked, got %v", out["email"])
	}
	if ssn, _ := out["ssn"].(string); len(ssn) == 0 || ssn == "123" || ssn[:4] != "tok_" {
		t.Fatalf("ssn should be tokenized, got %v", out["ssn"])
	}
}

// TestTokenDeterministic 同一主体/字段/值重复令牌化必须得到相同结果。
func TestTokenDeterministic(t *testing.T) {
	r := New()
	first := r.Token("secret", "u-eng", "ssn", "123-45-6789")
	for i := 0; i < 10; i++ {
		if got := r.Token("secret", "u-eng", "ssn", "123-45-6789"); got != first {
			t.Fatalf("token not deterministic at iteration %d: %q != %q", i, got, first)
		}
	}
	t.Logf("input=(u-eng, ssn, 123-45-6789) stable token=%s", first)

	// 不同主体、不同字段、不同值必须产生不同令牌。
	if r.Token("secret", "u-other", "ssn", "123-45-6789") == first {
		t.Fatal("tokens for different subjects must differ")
	}
	if r.Token("secret", "u-eng", "email", "123-45-6789") == first {
		t.Fatal("tokens for different fields must differ")
	}
	if r.Token("secret", "u-eng", "ssn", "999-99-9999") == first {
		t.Fatal("tokens for different values must differ")
	}
}

// TestTokenStableAcrossSecretAndReload 相同密钥下"状态重载"（新建 Redactor/Policy）
// 后令牌必须保持一致；不同密钥（旧策略密钥）下产生不同令牌，但自身仍稳定。
func TestTokenStableAcrossReloadAndSecret(t *testing.T) {
	r1, r2 := New(), New()
	sub := model.Subject{ID: "u-eng", Clearance: model.SensConfidential}
	rec := map[string]any{"ssn": "123-45-6789"}
	res := model.Resource{Fields: []model.FieldSpec{
		{Name: "ssn", Level: model.SensConfidential, RedactMode: model.RedactToken},
	}}

	// 模拟进程重启/状态重载：重建全部对象，密钥相同。
	out1, _, _ := r1.Apply(rec, res, sub, policyWithSecret("stable-key"))
	out2, _, _ := r2.Apply(rec, res, sub, policyWithSecret("stable-key"))
	if out1["ssn"] != out2["ssn"] {
		t.Fatalf("tokens must survive state reload: %v vs %v", out1["ssn"], out2["ssn"])
	}

	// 旧策略使用不同密钥：结论可区分，但各自确定性，且不可还原为明文。
	outOld, _, _ := r1.Apply(rec, res, sub, policyWithSecret("old-key"))
	if outOld["ssn"] == out1["ssn"] {
		t.Fatal("tokens under different policy secrets must differ")
	}
	if fmt.Sprint(out1["ssn"]) == "123-45-6789" || fmt.Sprint(outOld["ssn"]) == "123-45-6789" {
		t.Fatal("token must not reveal plaintext")
	}
	t.Logf("current-policy token=%s old-policy token=%s (both irreversible)",
		out1["ssn"], outOld["ssn"])
}

// TestTokenConcurrentConsistency 并发访问下输出必须完全一致。
func TestTokenConcurrentConsistency(t *testing.T) {
	r := New()
	const n = 200
	var wg sync.WaitGroup
	results := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = r.Token("secret", "u-eng", "ssn", "123-45-6789")
		}(i)
	}
	wg.Wait()
	for i := 1; i < n; i++ {
		if results[i] != results[0] {
			t.Fatalf("concurrent tokens differ: %q vs %q", results[i], results[0])
		}
	}
	t.Logf("%d concurrent calls produced identical token %s", n, results[0])
}

// TestApplyDoesNotMutateInput 脱敏不得修改库内明文记录。
func TestApplyDoesNotMutateInput(t *testing.T) {
	r := New()
	sub := model.Subject{ID: "u-intern", Clearance: model.SensInternal}
	rec := map[string]any{"name": "Alice", "email": "a@b.com", "salary": 1}
	_, _, _ = r.Apply(rec, testResource(), sub, policyWithSecret("k"))
	if rec["name"] != "Alice" || rec["email"] != "a@b.com" || rec["salary"] != 1 {
		t.Fatalf("input record mutated: %v", rec)
	}
}

// TestDefaultSecretStable 空密钥使用内置固定密钥，跨实例仍稳定。
func TestDefaultSecretStable(t *testing.T) {
	if New().Token("", "s", "f", "v") != New().Token("", "s", "f", "v") {
		t.Fatal("default-secret tokens must be stable across instances")
	}
}
