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

// ErrVersionNotRetained 表示请求复现的历史版本已不在保留范围内
// （已被淘汰或从未发布过）。该错误与“判定拒绝”完全分开：
// 复现路径绝不会退回当前版本顶包，也不会当作版本不存在而静默忽略。
var ErrVersionNotRetained = errors.New("policy version not retained")

// DefaultRetention 为历史版本保留上限的缺省值（不含当前在用版本）。
const DefaultRetention = 16

// Store 保存当前生效策略与有限的历史版本，支持读多写少下的
// 原子快照替换、安全热更新与按版本复现。
//
// 并发安全模型：
//   - 每个 *Policy 一经发布即视为不可变，留存的历史版本同样只读；
//   - Snapshot 通过原子指针读取，进行中的判定始终拿到一个完整版本，
//     不会读到“半更新”状态（新策略是整体校验后一次性替换）；
//   - Update 串行化（互斥锁），先校验兼容与合法性，再原子发布，
//     随后把被替换的版本按由旧到新追加进历史并按规定上限淘汰；
//   - 历史区用独立读写锁保护：淘汰只发生在 Update 内，
//     不会阻塞或打断正在进行的判定与复现读取。
type Store struct {
	mu      sync.Mutex
	current atomic.Pointer[Policy]

	histMu    sync.RWMutex
	history   []*Policy // 由旧到新，不含当前版本
	retention int
}

// NewStore 以初始策略创建策略存储，历史保留上限取 DefaultRetention。
func NewStore(initial *Policy) *Store {
	s := &Store{retention: DefaultRetention}
	if initial != nil {
		s.current.Store(initial)
	}
	return s
}

// SetRetention 设置历史版本保留上限（不含当前在用版本）。
// 上限收紧时立即按由旧到新淘汰超出部分；当前在用版本永远不参与淘汰。
func (s *Store) SetRetention(n int) error {
	if n < 0 {
		return fmt.Errorf("%w: retention must be >= 0, got %d", ErrInvalidPolicy, n)
	}
	s.histMu.Lock()
	defer s.histMu.Unlock()
	s.retention = n
	s.evictLocked()
	return nil
}

// Retention 返回当前的历史版本保留上限。
func (s *Store) Retention() int {
	s.histMu.RLock()
	defer s.histMu.RUnlock()
	return s.retention
}

// Snapshot 返回当前策略的只读快照。调用方不得修改返回的策略。
// 无策略时返回 nil（判定引擎据此给出 policy_not_found 拒绝）。
func (s *Store) Snapshot() *Policy {
	return s.current.Load()
}

// Version 按版本号取一份已发布策略的只读快照（当前版本或留存的历史版本）。
// ok=false 表示该版本不在保留范围内（已淘汰或从未发布），
// 调用方必须显式处理，不得改用其他版本顶替。
func (s *Store) Version(version string) (p *Policy, ok bool) {
	if cur := s.current.Load(); cur != nil && cur.Version == version {
		return cur, true
	}
	s.histMu.RLock()
	defer s.histMu.RUnlock()
	for _, hp := range s.history {
		if hp.Version == version {
			return hp, true
		}
	}
	return nil, false
}

// Versions 返回当前可追溯的版本号列表（历史由旧到新，当前版本在最后）。
func (s *Store) Versions() []string {
	out := make([]string, 0, len(s.history)+1)
	s.histMu.RLock()
	for _, hp := range s.history {
		out = append(out, hp.Version)
	}
	s.histMu.RUnlock()
	if cur := s.current.Load(); cur != nil {
		out = append(out, cur.Version)
	}
	return out
}

// Update 校验新版本合法且向后兼容当前版本后，原子替换为新版本；
// 任一校验失败都返回明确错误并保持原有策略继续可用，不会部分生效。
// 被替换的旧版本进入历史区；超出保留上限时按由旧到新淘汰。
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
	s.current.Store(next)

	// 旧版本进入历史区。同版本号重发不重复留存（历史按版本号索引，
	// 重复留存会让“按版本复现”产生歧义）。
	if cur != nil && cur.Version != next.Version {
		s.histMu.Lock()
		s.history = append(s.history, cur)
		s.evictLocked()
		s.histMu.Unlock()
	}
	return nil
}

// evictLocked 按由旧到新淘汰超出保留上限的历史版本。调用方须持有 histMu 写锁。
func (s *Store) evictLocked() {
	for len(s.history) > s.retention {
		s.history = s.history[1:]
	}
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
