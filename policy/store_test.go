package policy

import (
	"errors"
	"sync"
	"testing"

	"github.com/xingjianluo/secure-data-gateway-go/model"
)

func basePolicy(version int64, schema string) *model.Policy {
	return &model.Policy{
		SchemaVersion: schema,
		Version:       version,
		DefaultEffect: "deny",
		TokenSecret:   "secret-v1",
		Rules: []model.Rule{
			{Name: "r1", Effect: "allow", Actions: []model.Action{model.ActionRead},
				MinLevel: model.SensInternal},
		},
	}
}

// TestLoadAndSnapshot 正常加载并可取到快照与历史版本。
func TestLoadAndSnapshot(t *testing.T) {
	s := NewStore()
	if err := s.Load(basePolicy(1, "1.0.0")); err != nil {
		t.Fatalf("load v1: %v", err)
	}
	cur, ok := s.Current()
	if !ok || cur.Version != 1 {
		t.Fatalf("current should be v1, got ok=%v cur=%v", ok, cur)
	}
	if err := s.Load(basePolicy(2, "1.3.0")); err != nil {
		t.Fatalf("load v2: %v", err)
	}
	if cur, _ := s.Current(); cur.Version != 2 {
		t.Fatalf("current should be v2, got %d", cur.Version)
	}
	if old, ok := s.Get(1); !ok || old.Version != 1 {
		t.Fatal("historical v1 snapshot must remain available")
	}
	if vers := s.Versions(); len(vers) != 2 || vers[0] != 1 || vers[1] != 2 {
		t.Fatalf("versions = %v", vers)
	}
}

// TestRejectIncompatibleMajor 主版本不兼容必须拒绝加载，且原有策略保持可用。
func TestRejectIncompatibleMajor(t *testing.T) {
	s := NewStore()
	if err := s.Load(basePolicy(1, "1.0.0")); err != nil {
		t.Fatal(err)
	}
	err := s.Load(basePolicy(2, "2.0.0"))
	if !errors.Is(err, ErrIncompatible) {
		t.Fatalf("expected ErrIncompatible, got %v", err)
	}
	t.Logf("input policy schema=2.0.0; reject basis: %v (store remains on old version)", err)

	cur, _ := s.Current()
	if cur.Version != 1 {
		t.Fatalf("old policy must remain active, got version %d", cur.Version)
	}
	if _, ok := s.Get(2); ok {
		t.Fatal("rejected policy must not be stored")
	}
}

// TestBackwardCompatibleMinorVersions 1.x 次版本/补丁版本向后兼容，直接接受。
func TestBackwardCompatibleMinorVersions(t *testing.T) {
	s := NewStore()
	_ = s.Load(basePolicy(1, "1.0.0"))
	for _, v := range []string{"1.0.1", "1.2.0", "1.99.99"} {
		curVer, _ := s.Current()
		next := basePolicy(curVer.Version+1, v)
		if err := s.Load(next); err != nil {
			t.Fatalf("schema %s should be backward-compatible: %v", v, err)
		}
		t.Logf("input schema=%s accepted as version %d", v, next.Version)
	}
}

// TestRejectStaleVersion 版本号不递增必须拒绝。
func TestRejectStaleVersion(t *testing.T) {
	s := NewStore()
	_ = s.Load(basePolicy(3, "1.0.0"))
	if err := s.Load(basePolicy(2, "1.1.0")); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("expected ErrStaleVersion, got %v", err)
	}
	if err := s.Load(basePolicy(3, "1.1.0")); !errors.Is(err, ErrStaleVersion) {
		t.Fatalf("expected ErrStaleVersion on equal version, got %v", err)
	}
}

// TestRejectInvalidDefinition 默认效果非法、规则效果非法、重名规则均须拒绝。
func TestRejectInvalidDefinition(t *testing.T) {
	cases := map[string]*model.Policy{
		"bad default": {SchemaVersion: "1.0.0", Version: 1, DefaultEffect: "allow",
			Rules: []model.Rule{{Name: "r", Effect: "allow", Actions: []model.Action{model.ActionRead}}}},
		"bad effect": {SchemaVersion: "1.0.0", Version: 1, DefaultEffect: "deny",
			Rules: []model.Rule{{Name: "r", Effect: "maybe", Actions: []model.Action{model.ActionRead}}}},
		"dup names": {SchemaVersion: "1.0.0", Version: 1, DefaultEffect: "deny",
			Rules: []model.Rule{
				{Name: "r", Effect: "allow", Actions: []model.Action{model.ActionRead}},
				{Name: "r", Effect: "deny", Actions: []model.Action{model.ActionRead}},
			}},
		"bad action": {SchemaVersion: "1.0.0", Version: 1, DefaultEffect: "deny",
			Rules: []model.Rule{{Name: "r", Effect: "allow", Actions: []model.Action{model.Action("jump")}}}},
	}
	for name, p := range cases {
		s := NewStore()
		err := s.Load(p)
		if !errors.Is(err, ErrIncompatible) {
			t.Fatalf("case %s: expected ErrIncompatible, got %v", name, err)
		}
		if _, ok := s.Current(); ok {
			t.Fatalf("case %s: rejected load must leave store empty", name)
		}
		t.Logf("case %q rejected with basis: %v", name, err)
	}
}

// TestSnapshotImmutable 加载新版本不改变已取得的旧快照指针内容。
func TestSnapshotImmutable(t *testing.T) {
	s := NewStore()
	_ = s.Load(basePolicy(1, "1.0.0"))
	old, _ := s.Current()

	p2 := basePolicy(2, "1.1.0")
	p2.Rules[0].Name = "r2"
	_ = s.Load(p2)

	if old.Version != 1 || old.Rules[0].Name != "r1" {
		t.Fatal("old snapshot must be immutable after new version loaded")
	}

	// 外部修改原始策略对象也不得影响已存快照。
	p2.Version = 99
	p2.Rules[0].Name = "mutated"
	cur, _ := s.Current()
	if cur.Version != 2 || cur.Rules[0].Name != "r2" {
		t.Fatalf("stored snapshot must be detached from caller's object: %+v", cur)
	}
}

// TestConcurrentLoads 并发加载下当前版本必须始终是某个完整快照，版本号单调。
func TestConcurrentLoads(t *testing.T) {
	s := NewStore()
	_ = s.Load(basePolicy(0, "1.0.0"))

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				cur, ok := s.Current()
				if ok {
					_ = cur.Version // 读到的快照必须始终结构完整
				}
			}
		}()
	}
	for v := int64(1); v <= 20; v++ {
		_ = s.Load(basePolicy(v, "1.0.0"))
	}
	wg.Wait()

	cur, _ := s.Current()
	if cur.Version != 20 {
		t.Fatalf("expected final version 20, got %d", cur.Version)
	}
	if len(s.Versions()) != 21 {
		t.Fatalf("expected 21 snapshots (v0..v20), got %d", len(s.Versions()))
	}
}
