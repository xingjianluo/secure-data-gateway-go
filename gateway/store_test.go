package gateway

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// ---- 兼容加载：新版本必须被接受并原子生效 ----

func TestCompatibleUpdateAccepted(t *testing.T) {
	s := NewStore(testPolicyV1())
	v2 := &Policy{
		Version:      "2.0.0",
		MinSupported: "1.0.0", // 仍兼容 1.0.0
		Rules: []Rule{
			{ID: "eng-read", Departments: []string{"engineering"}, Actions: []Action{ActionRead}, MinLevel: LevelInternal},
			// 新增规则：legal 也可读（旧版本定义向后兼容，新能力叠加）
			{ID: "legal-read", Departments: []string{"legal"}, Actions: []Action{ActionRead}, MinLevel: LevelInternal},
		},
		FieldModes: map[Level]map[Action]FieldMode{
			LevelConfidential: {ActionRead: FieldMask}, // 由令牌化放宽为打码，仍属同结构
		},
	}
	if err := s.Update(v2); err != nil {
		t.Fatalf("向后兼容的 2.0.0 应加载成功: %v", err)
	}
	if got := s.Snapshot().Version; got != "2.0.0" {
		t.Fatalf("期望快照版本 2.0.0, got %s", got)
	}
	e := NewEngine()
	carol := Subject{ID: "carol", Department: "legal", Role: "counsel", Clearance: LevelConfidential}
	req := readReq("carol", "cust-1", LevelInternal)
	if d := e.Evaluate(s.Snapshot(), carol, req); !d.Allowed || d.PolicyVersion != "2.0.0" {
		t.Fatalf("v2 下 carol 应被放行: %+v", d)
	}
}

// ---- 不兼容加载：明确拒绝且保持原有版本继续可用，不部分生效 ----

func TestIncompatibleUpdateRejectedAndStaysUsable(t *testing.T) {
	s := NewStore(testPolicyV1())
	bad := &Policy{
		Version:      "3.0.0",
		MinSupported: "2.0.0", // 当前是 1.0.0，超出兼容范围
		Rules:        []Rule{{ID: "only-new", Departments: []string{"engineering"}, Actions: []Action{ActionRead}, MinLevel: LevelInternal}},
	}
	err := s.Update(bad)
	if !errors.Is(err, ErrIncompatiblePolicy) {
		t.Fatalf("应返回 ErrIncompatiblePolicy, got %v", err)
	}
	t.Logf("不兼容加载被拒绝, 输入版本=3.0.0 min_supported=2.0.0 当前=1.0.0, 错误: %v", err)

	cur := s.Snapshot()
	if cur.Version != "1.0.0" || len(cur.Rules) != 3 {
		t.Fatalf("拒绝加载后必须保持原策略完整可用, got version=%s rules=%d", cur.Version, len(cur.Rules))
	}

	// 版本回退也必须拒绝。
	downgrade := &Policy{Version: "0.9.0", Rules: []Rule{{ID: "r", Actions: []Action{ActionRead}}}}
	if err := s.Update(downgrade); !errors.Is(err, ErrIncompatiblePolicy) {
		t.Fatalf("降级加载应被拒绝, got %v", err)
	}

	// 非法策略（空规则）拒绝且不影响在用版本。
	invalid := &Policy{Version: "1.1.0", Rules: nil}
	if err := s.Update(invalid); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("非法策略应被拒绝, got %v", err)
	}
	if s.Snapshot().Version != "1.0.0" {
		t.Fatal("非法加载后原策略必须仍可用")
	}
}

// ---- 并发热更新：进行中的判定不得读到半更新状态 ----

func TestConcurrentUpdateAndEvaluate(t *testing.T) {
	s := NewStore(testPolicyV1())
	e := NewEngine()
	alice := Subject{ID: "alice", Department: "engineering", Role: "engineer", Clearance: LevelConfidential}
	req := readReq("alice", "cust-1", LevelInternal)

	versions := []string{"1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"}
	var updWg, evalWg sync.WaitGroup
	stop := make(chan struct{})

	// 更新方：顺序发布若干向后兼容版本（版本号只允许递增，乱序降级应被拒绝），
	// 发布期间判定方持续并发读取，验证任何时刻读到的都是完整版本。
	updWg.Add(1)
	go func() {
		defer updWg.Done()
		for _, ver := range versions {
			np := &Policy{
				Version:      ver,
				MinSupported: "1.0.0",
				Rules:        append([]Rule(nil), testPolicyV1().Rules...),
			}
			if err := s.Update(np); err != nil {
				t.Errorf("更新 %s 失败: %v", ver, err)
			}
		}
	}()

	// 判定方：高并发下每次取快照再判定，结论必须自洽——
	// 判定记录的策略版本必须与所用快照一致，且规则结构始终完整（非半更新）。
	for i := 0; i < 8; i++ {
		evalWg.Add(1)
		go func() {
			defer evalWg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				p := s.Snapshot()
				d := e.Evaluate(p, alice, req)
				if p == nil || d.PolicyVersion != p.Version {
					t.Errorf("读到不一致快照: snap=%s decision=%s", safeVer(p), d.PolicyVersion)
					return
				}
				if len(p.Rules) == 0 {
					t.Errorf("读到半更新/空规则状态")
					return
				}
			}
		}()
	}

	updWg.Wait() // 先等所有更新发布完成
	close(stop)  // 再通知判定方退出
	evalWg.Wait()

	if got := s.Snapshot().Version; got != "1.5.0" {
		t.Fatalf("最终版本应为 1.5.0, got %s", got)
	}
}

// ---- 旧版本策略下的历史判定结论可复现 ----

func TestHistoricalDecisionReproducible(t *testing.T) {
	e := NewEngine()
	alice := Subject{ID: "alice", Department: "engineering", Role: "engineer", Clearance: LevelConfidential}
	carol := Subject{ID: "carol", Department: "legal", Role: "counsel", Clearance: LevelConfidential}
	reqCarol := readReq("carol", "cust-1", LevelInternal)

	v1 := testPolicyV1()
	// 保存旧版本上的历史结论（即便旧策略已不在 Store 中）。
	history := e.Evaluate(v1, carol, reqCarol)
	t.Logf("历史判定输入: subject=carol(legal) policy=1.0.0; 依据=%v; 结论 allowed=%t reason=%q",
		history.MatchedRules, history.Allowed, history.Reason)
	if history.Allowed || history.Reason != DenyNoRuleMatch || history.PolicyVersion != "1.0.0" {
		t.Fatalf("v1 历史结论应为 no_rule_match, got %+v", history)
	}

	// 热更新到 v2：legal 部门获得读权限。
	v2 := &Policy{
		Version:      "2.0.0",
		MinSupported: "1.0.0",
		Rules: []Rule{
			{ID: "eng-read", Departments: []string{"engineering"}, Actions: []Action{ActionRead}, MinLevel: LevelInternal},
			{ID: "legal-read", Departments: []string{"legal"}, Actions: []Action{ActionRead}, MinLevel: LevelInternal},
		},
	}
	s := NewStore(v1)
	if err := s.Update(v2); err != nil {
		t.Fatal(err)
	}
	now := e.Evaluate(s.Snapshot(), carol, reqCarol)
	if !now.Allowed || now.PolicyVersion != "2.0.0" {
		t.Fatalf("v2 下 carol 应放行, got %+v", now)
	}

	// 用保存的旧策略快照重放，必须复现历史结论，而不是受新版本影响。
	replayed := e.Evaluate(v1, carol, reqCarol)
	if replayed.Allowed != history.Allowed ||
		replayed.Reason != history.Reason ||
		replayed.PolicyVersion != history.PolicyVersion ||
		fmt.Sprint(replayed.MatchedRules) != fmt.Sprint(history.MatchedRules) {
		t.Fatalf("旧版本历史结论不可复现:\nhist=%+v\nreplay=%+v", history, replayed)
	}
	t.Logf("复现成功: policy=1.0.0 仍为 reason=%q; 当前 policy=2.0.0 为 allowed=%t",
		replayed.Reason, now.Allowed)

	// alice 的同输入在两个版本下结论也应各自稳定。
	reqAlice := readReq("alice", "cust-1", LevelInternal)
	if d := e.Evaluate(v1, alice, reqAlice); !d.Allowed {
		t.Fatal("alice v1 应放行")
	}
	if d := e.Evaluate(v2, alice, reqAlice); !d.Allowed {
		t.Fatal("alice v2 应放行")
	}
}

func safeVer(p *Policy) string {
	if p == nil {
		return "<nil>"
	}
	return p.Version
}
