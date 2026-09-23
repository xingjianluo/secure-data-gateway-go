// Package policy 负责策略的版本兼容校验与多版本快照存储，
// 保证热更新期间进行中的判定只能读到完整的旧快照或完整的新快照。
package policy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/xingjianluo/secure-data-gateway-go/model"
)

// ErrIncompatible 表示新版本策略与当前支持范围不兼容，必须拒绝加载。
var ErrIncompatible = errors.New("policy schema incompatible")

// ErrStaleVersion 表示新版本号不大于当前版本。
var ErrStaleVersion = errors.New("policy version is not newer than current")

// supportedMajor 为当前引擎支持的策略 schema 主版本。
// 仅接受主版本为 1 的策略定义；主版本不同代表存在无法自动兼容的破坏性变更。
const supportedMajor = 1

// parseMajor 解析语义化版本号的主版本，如 "1.2.0" -> 1。
func parseMajor(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, errors.New("empty schema version")
	}
	parts := strings.Split(v, ".")
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, fmt.Errorf("invalid schema version %q", v)
	}
	return major, nil
}

// ValidateCompatibility 校验新策略是否可被当前引擎加载。
// 兼容范围：schema 主版本必须为 1（次版本/补丁版本向后兼容，直接接受）；
// 版本号必须严格递增；规则效果、默认效果与操作类型必须合法。
// 任一条件不满足都返回包装了 ErrIncompatible / ErrStaleVersion 的错误，
// 调用方必须拒绝加载并保持原有策略可用。
func ValidateCompatibility(p *model.Policy, current *model.Policy) error {
	if p == nil {
		return fmt.Errorf("%w: nil policy", ErrIncompatible)
	}

	major, err := parseMajor(p.SchemaVersion)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIncompatible, err)
	}
	if major != supportedMajor {
		return fmt.Errorf("%w: engine supports schema major %d only, got %d (%s)",
			ErrIncompatible, supportedMajor, major, p.SchemaVersion)
	}

	if current != nil && p.Version <= current.Version {
		return fmt.Errorf("%w: new=%d current=%d", ErrStaleVersion, p.Version, current.Version)
	}

	if p.DefaultEffect != "deny" {
		return fmt.Errorf("%w: default effect must be \"deny\", got %q", ErrIncompatible, p.DefaultEffect)
	}

	validAction := map[model.Action]bool{
		model.ActionRead: true, model.ActionWrite: true, model.ActionDelete: true,
	}
	seen := map[string]bool{}
	for i, r := range p.Rules {
		if r.Name == "" {
			return fmt.Errorf("%w: rule[%d] has empty name", ErrIncompatible, i)
		}
		if seen[r.Name] {
			return fmt.Errorf("%w: duplicate rule name %q", ErrIncompatible, r.Name)
		}
		seen[r.Name] = true
		if r.Effect != "allow" && r.Effect != "deny" {
			return fmt.Errorf("%w: rule %q has invalid effect %q", ErrIncompatible, r.Name, r.Effect)
		}
		if len(r.Actions) == 0 {
			return fmt.Errorf("%w: rule %q must declare at least one action", ErrIncompatible, r.Name)
		}
		for _, a := range r.Actions {
			if !validAction[a] {
				return fmt.Errorf("%w: rule %q has invalid action %q", ErrIncompatible, r.Name, a)
			}
		}
	}

	return nil
}
