package gateway

import (
	"strconv"
	"strings"
	"time"
)

// Engine 为无状态授权判定引擎：给定一个不可变策略快照与请求，产出判定及依据。
// 无状态保证：同一策略版本 + 同一输入，无论来自哪个入口、是否并发，结论一致且可复现。
type Engine struct{}

// NewEngine 创建判定引擎。
func NewEngine() *Engine { return &Engine{} }

// Evaluate 基于主体属性、资源敏感级别与操作类型进行判定。
//
// 拒绝原因严格区分、两两互斥：
//   - policy_not_found：系统里根本没有可用策略（未加载或策略无规则）；
//   - no_matching_rule：有可用策略，但没有任何规则的主体约束覆盖该主体；
//   - action_denied：存在匹配主体的规则，但均不允许本次操作；
//   - level_insufficient：操作被允许，但主体敏感级别低于资源要求；
//   - unknown_subject 由网关在主体目录查询阶段给出，不进入本引擎；
//   - resource_missing 由网关在取数阶段给出，同样不进入本引擎。
func (e *Engine) Evaluate(p *Policy, sub Subject, req AccessRequest) Decision {
	now := time.Now().UTC()
	base := func(reason DenyReason, rules []string) Decision {
		return Decision{
			Allowed:       false,
			Reason:        reason,
			PolicyVersion: versionOf(p),
			MatchedRules:  rules,
			EvaluatedAt:   now,
		}
	}

	if p == nil || len(p.Rules) == 0 {
		return base(DenyPolicyNotFound, nil)
	}

	var candidates, actionRules []Rule
	for _, r := range p.Rules {
		if !ruleMatchesSubject(r, sub) {
			continue
		}
		candidates = append(candidates, r)
		if ruleAllowsAction(r, req.Action) {
			actionRules = append(actionRules, r)
		}
	}

	basis := describe(candidates)

	if len(candidates) == 0 {
		// 有可用策略、但主体未被任何规则覆盖：与“根本没有可用策略”分开归属。
		return base(DenyNoMatchingRule, nil)
	}
	if len(actionRules) == 0 {
		return base(DenyActionDenied, basis)
	}

	// 所需级别取资源敏感级别与命中规则要求级别的最大值。
	required := req.Resource.Level
	for _, r := range actionRules {
		if r.MinLevel > required {
			required = r.MinLevel
		}
	}
	if sub.Clearance < required {
		d := base(DenyLevelInsufficient, describe(actionRules))
		d.MatchedRules = append(d.MatchedRules,
			"required_level>="+strconv.Itoa(int(required))+" subject_clearance="+strconv.Itoa(int(sub.Clearance)))
		return d
	}

	return Decision{
		Allowed:       true,
		Reason:        DenyNone,
		PolicyVersion: p.Version,
		PolicyID:      actionRules[0].ID,
		MatchedRules:  describe(actionRules),
		EvaluatedAt:   now,
	}
}

func versionOf(p *Policy) string {
	if p == nil {
		return ""
	}
	return p.Version
}

// ruleMatchesSubject 判断规则的主体属性约束是否容纳该主体。
// 空的部门/角色列表表示通配；列表为白名单语义。
func ruleMatchesSubject(r Rule, sub Subject) bool {
	if len(r.Departments) > 0 && !contains(r.Departments, sub.Department) {
		return false
	}
	if len(r.Roles) > 0 && !contains(r.Roles, sub.Role) {
		return false
	}
	return true
}

// ruleAllowsAction 判断规则是否允许该操作；空 Actions 表示允许全部操作。
func ruleAllowsAction(r Rule, a Action) bool {
	if len(r.Actions) == 0 {
		return true
	}
	for _, allowed := range r.Actions {
		if allowed == a {
			return true
		}
	}
	return false
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func describe(rs []Rule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		var b strings.Builder
		b.WriteString("rule=" + r.ID)
		if r.Description != "" {
			b.WriteString("(" + r.Description + ")")
		}
		b.WriteString(" min_level=" + strconv.Itoa(int(r.MinLevel)))
		out = append(out, b.String())
	}
	return out
}
