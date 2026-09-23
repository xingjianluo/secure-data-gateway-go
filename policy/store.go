package policy

import (
	"fmt"
	"sort"
	"sync"

	"github.com/xingjianluo/secure-data-gateway-go/model"
)

// Store 保存全部历史策略快照，供在线判定与历史结论复现使用。
//
// 热更新安全性：判定方先通过 Current() 取得一个 *model.Policy 快照指针，
// 之后整次判定只读取该指针指向的不可变快照。Load 仅在全部校验通过后
// 才在锁内替换指针，因此进行中的判定永远不会读到半更新状态。
type Store struct {
	mu        sync.RWMutex
	current   *model.Policy
	snapshots map[int64]*model.Policy
}

// NewStore 创建空策略存储。
func NewStore() *Store {
	return &Store{snapshots: map[int64]*model.Policy{}}
}

// Load 原子地加载一个新版本。
// 先在锁外做兼容性校验，校验失败时直接返回错误且原有状态完全不变；
// 校验通过后在写锁内保存快照并切换当前指针，替换对读者表现为原子操作。
func (s *Store) Load(p *model.Policy) error {
	s.mu.RLock()
	cur := s.current
	s.mu.RUnlock()

	if err := ValidateCompatibility(p, cur); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// 双重检查：防止拿到 RLock 与 Lock 之间已有其他更新。
	if s.current != nil && p.Version <= s.current.Version {
		return fmt.Errorf("%w: new=%d current=%d", ErrStaleVersion, p.Version, s.current.Version)
	}
	cp := clonePolicy(p)
	s.snapshots[cp.Version] = cp
	s.current = cp
	return nil
}

// Current 返回当前生效策略快照；无策略时返回 (nil, false)。
// 返回的指针指向不可变快照，调用方可在无锁状态下安全读完整次判定。
func (s *Store) Current() (*model.Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil, false
	}
	return s.current, true
}

// Get 返回指定版本的历史快照，用于旧版本结论复现。
func (s *Store) Get(version int64) (*model.Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.snapshots[version]
	return p, ok
}

// Versions 返回已保存的全部版本号（升序）。
func (s *Store) Versions() []int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]int64, 0, len(s.snapshots))
	for v := range s.snapshots {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// clonePolicy 生成策略的深拷贝，保证存入的快照在外部被修改时不受影响。
func clonePolicy(p *model.Policy) *model.Policy {
	cp := *p
	cp.Rules = make([]model.Rule, len(p.Rules))
	for i, r := range p.Rules {
		rc := r
		rc.Actions = append([]model.Action(nil), r.Actions...)
		rc.Departments = append([]string(nil), r.Departments...)
		if r.Subject != nil {
			rc.Subject = make(map[string]string, len(r.Subject))
			for k, v := range r.Subject {
				rc.Subject[k] = v
			}
		}
		cp.Rules[i] = rc
	}
	return &cp
}
