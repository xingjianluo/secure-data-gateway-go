package gateway

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// ErrIncompatiblePolicy 表示新版本策略无法向后兼容当前版本，加载被明确拒绝。
var ErrIncompatiblePolicy = errors.New("incompatible policy version")

// ErrInvalidPolicy 表示新策略内容不合法，拒绝加载且保持原策略可用。
var ErrInvalidPolicy = errors.New("invalid policy")

// ErrVersionEvicted 表示请求复现的历史版本曾经发布过、但已超出保留上限被淘汰。
// 与“从未存在过的版本”严格区分，绝不回退到当前版本顶包。
var ErrVersionEvicted = errors.New("policy version evicted from retention")

// ErrVersionNotFound 表示请求复现的版本从未发布过（不是被淘汰）。
var ErrVersionNotFound = errors.New("policy version not found")

// DefaultHistoryRetention 为历史版本默认保留上限（不含当前在用版本）。
const DefaultHistoryRetention = 8

// Store 保存当前生效策略与有限数量的历史版本，支持读多写少下的
// 原子快照替换、安全热更新与历史版本复现查询。
//
// 并发安全模型：
//   - 每个 *Policy 一经发布即视为不可变；进入历史的版本在入列时做防御性深拷贝，
//     之后任何操作都不会再改动它（只读）；
//   - Snapshot 通过原子指针读取，进行中的判定始终拿到一个完整版本，
//     不会读到“半更新”状态（新策略是整体校验后一次性替换）；
//   - Update 串行化（互斥锁），先校验兼容与合法性，再原子发布；
//   - 历史淘汰只从索引中摘除条目，已发出的 *Policy 指针不受影响，
//     因此淘汰不会打断正在进行的判定与复现。
//
// 历史保留规则：
//   - 每次成功 Update 后，被替换下来的版本进入历史（由旧到新有序）；
//   - 历史条数超过 retention 上限时，按由旧到新淘汰；上限也可在运行期
//     通过 SetRetention 调整，调低时立即按新上限淘汰；
//   - 当前在用版本永不淘汰；被淘汰的版本号会短暂留痕，
//     查询时返回 ErrVersionEvicted 而非 ErrVersionNotFound。
type Store struct {
	mu        sync.RWMutex
	current   atomic.Pointer[Policy]
	retention int
	history   []*Policy // 由旧到新；均为入列时的深拷贝，只读
	evicted   []string  // 最近被淘汰的版本号（有界），用于区分“淘汰”与“从未存在”
}

// NewStore 以初始策略创建策略存储，历史保留上限取默认值。
func NewStore(initial *Policy) *Store {
	return NewStoreWithRetention(initial, DefaultHistoryRetention)
}

// NewStoreWithRetention 以初始策略与历史保留上限创建策略存储。
// retention 为保留的旧版本条数（不含当前版本），负数按 0 处理（不保留历史）。
func NewStoreWithRetention(initial *Policy, retention int) *Store {
	if retention < 0 {
		retention = 0
	}
	s := &Store{retention: retention}
	if initial != nil {
		s.current.Store(initial)
	}
	return s
}

// SetRetention 在运行期调整历史版本保留上限（不含当前在用版本），
// 负数按 0 处理。调低时立即按新上限由旧到新淘汰多余版本，
// 被淘汰的版本号照常留痕（查询仍返回 ErrVersionEvicted）。
//
// 与 Update 一样只从索引中摘除条目：已发出的 *Policy 快照指针不受影响，
// 因此调整上限不会打断正在进行的访问判定与复核。
func (s *Store) SetRetention(n int) {
	if n < 0 {
		n = 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retention = n
	for len(s.history) > s.retention {
		old := s.history[0]
		s.history = s.history[1:]
		s.noteEvictedLocked(old.Version)
	}
}

// Snapshot 返回当前策略的只读快照。调用方不得修改返回的策略。
// 无策略时返回 nil（判定引擎据此给出 policy_not_found 拒绝）。
func (s *Store) Snapshot() *Policy {
	return s.current.Load()
}

// Update 校验新版本合法且向后兼容当前版本后，原子替换为新版本；
// 任一校验失败都返回明确错误并保持原有策略继续可用，不会部分生效。
// 替换成功后，被替换下来的旧版本深拷贝进入历史，并按上限由旧到新淘汰。
func (s *Store) Update(next *Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := validatePolicy(next); err != nil {
		return err
	}
	cur := s.current.Load()
	if cur != nil {
		if err := checkCompatible(cur, next); err != nil {
			return err
		}
	}
	if cur != nil {
		s.pushHistoryLocked(cur)
	}
	s.current.Store(next)
	return nil
}

// pushHistoryLocked 把被替换下来的版本放入历史并执行淘汰。调用方须持有写锁。
func (s *Store) pushHistoryLocked(prev *Policy) {
	s.history = append(s.history, clonePolicy(prev))
	for len(s.history) > s.retention {
		old := s.history[0]
		s.history = s.history[1:]
		s.noteEvictedLocked(old.Version)
	}
}

// noteEvictedLocked 记录被淘汰的版本号（有界队列，超界遗忘最旧记录）。
// 版本号只是短字符串，容量给得比历史保留上限宽松，
// 使“已淘汰”与“从未存在”的区分在常规使用下始终可靠。
func (s *Store) noteEvictedLocked(version string) {
	s.evicted = append(s.evicted, version)
	limit := s.retention * 4
	if limit < 64 {
		limit = 64
	}
	for len(s.evicted) > limit {
		s.evicted = s.evicted[1:]
	}
}

// Version 返回指定版本的策略只读快照，供按版本复现使用。
//
// 三种结果严格区分：
//   - 当前在用版本或仍在保留期内的历史版本：返回快照；
//   - 曾经发布但已被淘汰：返回 ErrVersionEvicted（绝不拿当前版本顶包）；
//   - 从未发布过：返回 ErrVersionNotFound。
//
// 返回的指针指向只读数据，调用方不得修改；即使随后该版本被淘汰，
// 已拿到的快照依然完整有效（淘汰只摘除索引，不打断进行中的复现）。
func (s *Store) Version(version string) (*Policy, error) {
	if cur := s.current.Load(); cur != nil && cur.Version == version {
		return cur, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.history {
		if p.Version == version {
			return p, nil
		}
	}
	for _, v := range s.evicted {
		if v == version {
			return nil, fmt.Errorf("%w: %s", ErrVersionEvicted, version)
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrVersionNotFound, version)
}

// Versions 返回当前可复现的全部版本号：历史版本由旧到新，当前版本在最后。
func (s *Store) Versions() []string {
	s.mu.RLock()
	out := make([]string, 0, len(s.history)+1)
	for _, p := range s.history {
		out = append(out, p.Version)
	}
	s.mu.RUnlock()
	if cur := s.current.Load(); cur != nil {
		out = append(out, cur.Version)
	}
	return out
}

// clonePolicy 深拷贝策略，供历史留存：入列后只读，与调用方持有的指针脱钩。
func clonePolicy(p *Policy) *Policy {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Rules = make([]Rule, len(p.Rules))
	for i, r := range p.Rules {
		cp.Rules[i] = Rule{
			ID:          r.ID,
			Departments: append([]string(nil), r.Departments...),
			Roles:       append([]string(nil), r.Roles...),
			Actions:     append([]Action(nil), r.Actions...),
			MinLevel:    r.MinLevel,
			Description: r.Description,
		}
	}
	if p.FieldModes != nil {
		cp.FieldModes = make(map[Level]map[Action]FieldMode, len(p.FieldModes))
		for lvl, byAction := range p.FieldModes {
			m := make(map[Action]FieldMode, len(byAction))
			for act, mode := range byAction {
				m[act] = mode
			}
			cp.FieldModes[lvl] = m
		}
	}
	return &cp
}

// validatePolicy 校验策略自身合法性。
func validatePolicy(p *Policy) error {
	if p == nil {
		return fmt.Errorf("%w: policy is nil", ErrInvalidPolicy)
	}
	if p.Version == "" {
		return fmt.Errorf("%w: empty version", ErrInvalidPolicy)
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("%w: version %s has no rules", ErrInvalidPolicy, p.Version)
	}
	if p.MinSupported != "" {
		if _, err := parseSemver(p.MinSupported); err != nil {
			return fmt.Errorf("%w: bad min_supported %q: %v", ErrInvalidPolicy, p.MinSupported, err)
		}
	}
	for _, r := range p.Rules {
		if r.ID == "" {
			return fmt.Errorf("%w: a rule in %s has empty id", ErrInvalidPolicy, p.Version)
		}
	}
	return nil
}

// checkCompatible 校验 next 向后兼容 cur：
//  1. 版本号不得回退（禁止降级加载旧定义）；
//  2. next 声明的兼容下界 MinSupported 不得高于 cur.Version，
//     即当前版本必须仍落在新版本支持的版本范围内。
func checkCompatible(cur, next *Policy) error {
	curV, err := parseSemver(cur.Version)
	if err != nil {
		return fmt.Errorf("%w: current version %q unparsable: %v", ErrIncompatiblePolicy, cur.Version, err)
	}
	nextV, err := parseSemver(next.Version)
	if err != nil {
		return fmt.Errorf("%w: new version %q unparsable: %v", ErrIncompatiblePolicy, next.Version, err)
	}
	if cmpSemver(nextV, curV) < 0 {
		return fmt.Errorf("%w: downgrade %s -> %s is refused", ErrIncompatiblePolicy, cur.Version, next.Version)
	}
	if next.MinSupported != "" {
		minV, err := parseSemver(next.MinSupported)
		if err != nil {
			return fmt.Errorf("%w: bad min_supported: %v", ErrIncompatiblePolicy, err)
		}
		if cmpSemver(curV, minV) < 0 {
			return fmt.Errorf("%w: current %s older than new min_supported %s",
				ErrIncompatiblePolicy, cur.Version, next.MinSupported)
		}
	}
	return nil
}

// ---- 最小语义化版本支持（major.minor.patch，缺段补 0） ----

type semver [3]int

func parseSemver(s string) (semver, error) {
	var v semver
	parts := split(s, '.')
	if len(parts) > 3 {
		return v, fmt.Errorf("too many segments")
	}
	for i, part := range parts {
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return v, fmt.Errorf("non-numeric segment %q", part)
			}
			n = n*10 + int(c-'0')
		}
		v[i] = n
	}
	return v, nil
}

func cmpSemver(a, b semver) int {
	for i := 0; i < 3; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func split(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
