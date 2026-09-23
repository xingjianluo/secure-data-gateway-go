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

// Store 保存当前生效策略，支持读多写少下的原子快照替换与安全热更新。
//
// 并发安全模型：
//   - 每个 *Policy 一经发布即视为不可变；
//   - Snapshot 通过原子指针读取，进行中的判定始终拿到一个完整版本，
//     不会读到“半更新”状态（新策略是整体校验后一次性替换）；
//   - Update 串行化（互斥锁），先校验兼容与合法性，再原子发布。
type Store struct {
	mu      sync.Mutex
	current atomic.Pointer[Policy]
}

// NewStore 以初始策略创建策略存储。
func NewStore(initial *Policy) *Store {
	s := &Store{}
	if initial != nil {
		s.current.Store(initial)
	}
	return s
}

// Snapshot 返回当前策略的只读快照。调用方不得修改返回的策略。
// 无策略时返回 nil（判定引擎据此给出 policy_not_found 拒绝）。
func (s *Store) Snapshot() *Policy {
	return s.current.Load()
}

// Update 校验新版本合法且向后兼容当前版本后，原子替换为新版本；
// 任一校验失败都返回明确错误并保持原有策略继续可用，不会部分生效。
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
	return nil
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
