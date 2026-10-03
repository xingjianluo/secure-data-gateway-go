package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// ---- 旧版本定义文件：字段缺失（min_supported、field_modes、description）必须容忍 ----

func TestLoadLegacyPolicyFile(t *testing.T) {
	p, err := LoadPolicyFile(filepath.Join("testdata", "policy-legacy.json"))
	if err != nil {
		t.Fatalf("旧版定义文件应可加载: %v", err)
	}
	if p.Version != "1.0.0" || len(p.Rules) != 1 {
		t.Fatalf("旧版解析异常: %+v", p)
	}
	if p.Rules[0].Actions[0] != ActionRead || p.Rules[0].MinLevel != LevelInternal {
		t.Fatalf("规则字段解析异常: %+v", p.Rules[0])
	}
}

// ---- 端到端热更新：ReloadPolicy 后新规则生效，令牌化模式按新文件执行 ----

func TestReloadPolicyEndToEnd(t *testing.T) {
	gw, _ := newFixture(t)
	carolReq := readReq("carol", "cust-1", LevelInternal)

	// v1 下 carol 无策略 -> 拒绝。
	if _, d, err := gw.AccessRecord(carolReq, customerData()); err == nil || d.Reason != DenyNoRuleMatch {
		t.Fatalf("v1 下 carol 应 no_rule_match, got %+v %v", d, err)
	}

	// 热更新 v2。
	if err := gw.ReloadPolicy(filepath.Join("testdata", "policy-v2.json")); err != nil {
		t.Fatalf("v2 热更新失败: %v", err)
	}
	if v := gw.PolicyStore().Snapshot().Version; v != "2.0.0" {
		t.Fatalf("生效版本应为 2.0.0, got %s", v)
	}

	// v2 下 carol 放行；alice 的 email 仍为确定性令牌，phone 仍打码。
	out, d, err := gw.AccessRecord(carolReq, customerData())
	if err != nil || !d.Allowed {
		t.Fatalf("v2 下 carol 应放行: %+v %v", d, err)
	}
	t.Logf("热更新后输入 subject=carol; 判定依据=%v; 输出=%v", d.MatchedRules, out)
	if d.PolicyVersion != "2.0.0" || d.PolicyID != "legal-read" {
		t.Fatalf("应命中 v2 新规则, got %+v", d)
	}

	aliceReq := readReq("alice", "cust-1", LevelInternal)
	aout, ad, _ := gw.AccessRecord(aliceReq, customerData())
	if ad.PolicyVersion != "2.0.0" {
		t.Fatalf("alice 判定应标注新版本, got %s", ad.PolicyVersion)
	}
	if aout["phone"] != "1****8" {
		t.Fatalf("phone 仍应打码, got %v", aout["phone"])
	}
	if tok, _ := aout["email"].(string); len(tok) < 5 || tok[:4] != "tok_" {
		t.Fatalf("email 仍应令牌化, got %v", aout["email"])
	}
}

// ---- 不兼容文件热更新必须失败并保持 v1 继续可用，不部分生效 ----

func TestReloadIncompatibleFileKeepsOldPolicy(t *testing.T) {
	gw, _ := newFixture(t)
	before := gw.PolicyStore().Snapshot()

	err := gw.ReloadPolicy(filepath.Join("testdata", "policy-incompatible.json"))
	if !errors.Is(err, ErrIncompatiblePolicy) {
		t.Fatalf("不兼容文件应被拒绝, got %v", err)
	}
	after := gw.PolicyStore().Snapshot()
	if after != before || after.Version != "1.0.0" || len(after.Rules) != 3 {
		t.Fatalf("拒绝后策略必须原样可用, got version=%s rules=%d", after.Version, len(after.Rules))
	}
	// carol 依旧无任何规则覆盖，证明没有部分生效。
	_, d, err := gw.AccessRecord(readReq("carol", "cust-1", LevelInternal), customerData())
	if d.Reason != DenyNoRuleMatch {
		t.Fatalf("旧策略必须保持判定行为, got %q", d.Reason)
	}
}

// ---- 非法 JSON / 非法枚举：拒绝加载且不影响在用策略 ----

func TestReloadMalformedFile(t *testing.T) {
	gw, _ := newFixture(t)
	dir := t.TempDir()

	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := gw.ReloadPolicy(badJSON); err == nil {
		t.Fatal("损坏的 JSON 必须报错")
	}

	badEnum := filepath.Join(dir, "enum.json")
	os.WriteFile(badEnum, []byte(`{
	  "version": "2.1.0", "min_supported": "1.0.0",
	  "rules": [{"id": "r", "actions": ["execute"]}],
	  "field_modes": {"1": {"read": "redact"}}}
	`), 0o600)
	if err := gw.ReloadPolicy(badEnum); err == nil {
		t.Fatal("非法操作/模式枚举必须报错")
	}
	if v := gw.PolicyStore().Snapshot().Version; v != "1.0.0" {
		t.Fatalf("非法文件不得影响在用策略, got %s", v)
	}
}
