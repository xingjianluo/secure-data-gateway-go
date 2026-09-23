// Package authz 实现基于主体属性、资源敏感级别与操作类型的访问判定，
// 并完整记录每条规则的评估依据。
package authz

import (
	"fmt"
	"time"

	"github.com/xingjianluo/secure-data-gateway-go/model"
	"github.com/xingjianluo/secure-data-gateway-go/policy"
	"github.com/xingjianluo/secure-data-gateway-go/store"
)

// Engine 授权判定引擎。所有判定基于传入的策略快照，天然隔离热更新。
type Engine struct {
	dir *store.Directory
}

// New 创建授权引擎。
func New(dir *store.Directory) *Engine {
	return &Engine{dir: dir}
}

// EvaluateRequest 以当前策略快照执行一次判定。
// 三类前置失败产生互不相同的拒绝原因：
//   - 策略缺失：DenyPolicyNotFound
//   - 未知主体：DenyUnknownSubject
//   - 资源不存在：DenyResourceNotFound
func (e *Engine) EvaluateRequest(subjectID, resourceID string, action model.Action, ps *policy.Store) *model.Decision {
	base := func(reason model.DenyReason, msg string) *model.Decision {
		return &model.Decision{
			Allowed:     false,
			Reason:      reason,
			Message:     msg,
			SubjectID:   subjectID,
			ResourceID:  resourceID,
			Action:      action,
			EvaluatedAt: time.Now().UTC(),
		}
	}

	p, ok := ps.Current()
	if !ok {
		return base(model.DenyPolicyNotFound, "no policy loaded")
	}

	sub, ok := e.dir.Subject(subjectID)
	if !ok {
		d := base(model.DenyUnknownSubject, fmt.Sprintf("subject %q is not registered", subjectID))
		d.PolicyVersion = p.Version
		return d
	}

	res, ok := e.dir.Resource(resourceID)
	if !ok {
		d := base(model.DenyResourceNotFound, fmt.Sprintf("resource %q does not exist", resourceID))
		d.PolicyVersion = p.Version
		return d
	}

	return e.Evaluate(sub, res, action, p)
}

// Evaluate 基于给定主体、资源与策略快照执行判定。
// 规则按顺序评估，首个全部条件匹配的规则生效；
// 每条被评估的规则都会记录命中与否及逐条不满足的原因。
// 无规则命中时走策略默认效果（本引擎强制 deny），拒绝原因为 DenyNoPermission。
func (e *Engine) Evaluate(sub model.Subject, res model.Resource, action model.Action, p *model.Policy) *model.Decision {
	d := &model.Decision{
		Allowed:       false,
		Reason:        model.DenyNoPermission,
		SubjectID:     sub.ID,
		ResourceID:    res.ID,
		Action:        action,
		PolicyVersion: p.Version,
		Hits:          []model.RuleHit{},
		EvaluatedAt:   time.Now().UTC(),
	}

	for _, rule := range p.Rules {
		hit := model.RuleHit{RuleName: rule.Name, Effect: rule.Effect}

		actionOK := false
		for _, a := range rule.Actions {
			if a == action {
				actionOK = true
				break
			}
		}
		if !actionOK {
			hit.Reasons = append(hit.Reasons, fmt.Sprintf("action %q not covered by rule actions", action))
		}
		if sub.Clearance < rule.MinLevel {
			hit.Reasons = append(hit.Reasons, fmt.Sprintf(
				"subject clearance %s < required %s", sub.Clearance, rule.MinLevel))
		}
		if rule.MaxLevel != 0 && res.Sensitivity > rule.MaxLevel {
			hit.Reasons = append(hit.Reasons, fmt.Sprintf(
				"resource sensitivity %s > rule max %s", res.Sensitivity, rule.MaxLevel))
		}
		for k, want := range rule.Subject {
			got, present := sub.Attributes[k]
			if !present {
				hit.Reasons = append(hit.Reasons, fmt.Sprintf("subject missing attribute %q", k))
			} else if got != want {
				hit.Reasons = append(hit.Reasons, fmt.Sprintf(
					"subject attribute %q=%q does not equal %q", k, got, want))
			}
		}
		if len(rule.Departments) > 0 && !containsAny(sub.Departments, rule.Departments) {
			hit.Reasons = append(hit.Reasons, fmt.Sprintf(
				"subject departments %v not in rule departments %v", sub.Departments, rule.Departments))
		}
		if rule.OwnersOnly && sub.ID != res.OwnerID {
			hit.Reasons = append(hit.Reasons, fmt.Sprintf(
				"owners-only rule: subject %q is not owner %q", sub.ID, res.OwnerID))
		}

		hit.Matched = len(hit.Reasons) == 0
		d.Hits = append(d.Hits, hit)

		if hit.Matched {
			if rule.Effect == "allow" {
				d.Allowed = true
				d.Reason = model.DenyNone
				d.Message = fmt.Sprintf("allowed by rule %q in policy v%d", rule.Name, p.Version)
			} else {
				d.Allowed = false
				d.Message = fmt.Sprintf("explicitly denied by rule %q in policy v%d", rule.Name, p.Version)
			}
			return d
		}
	}

	d.DefaultUsed = true
	d.Message = fmt.Sprintf(
		"no rule matched; applying default effect %q of policy v%d", p.DefaultEffect, p.Version)
	return d
}

func containsAny(haystack, needles []string) bool {
	set := make(map[string]struct{}, len(haystack))
	for _, h := range haystack {
		set[h] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[n]; ok {
			return true
		}
	}
	return false
}
