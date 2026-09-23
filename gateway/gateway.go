// Package gateway 组装主体目录、数据源、策略存储、授权引擎、
// 脱敏器与审计日志，对外提供统一的数据访问入口。
// HTTP 入口与本地 SDK 入口共用本入口，保证结论一致。
package gateway

import (
	"fmt"

	"github.com/xingjianluo/secure-data-gateway-go/audit"
	"github.com/xingjianluo/secure-data-gateway-go/authz"
	"github.com/xingjianluo/secure-data-gateway-go/mask"
	"github.com/xingjianluo/secure-data-gateway-go/model"
	"github.com/xingjianluo/secure-data-gateway-go/policy"
	"github.com/xingjianluo/secure-data-gateway-go/store"
)

// Gateway 本地数据访问网关。
type Gateway struct {
	dir   *store.Directory
	data  *store.DataSource
	pol   *policy.Store
	eng   *authz.Engine
	red   *mask.Redactor
	audit *audit.Log
}

// New 组装网关。
func New(dir *store.Directory, data *store.DataSource, pol *policy.Store,
	eng *authz.Engine, red *mask.Redactor, log *audit.Log) *Gateway {
	return &Gateway{dir: dir, data: data, pol: pol, eng: eng, red: red, audit: log}
}

// Access 执行一次带脱敏的数据访问并写审计日志。
// 判定不通过时不读取业务记录、不返回任何字段（含空值/占位符）。
func (g *Gateway) Access(subjectID, resourceID string, action model.Action) (*model.AccessResult, audit.Event) {
	dec := g.eng.EvaluateRequest(subjectID, resourceID, action, g.pol)

	result := &model.AccessResult{Decision: dec}
	ev := audit.Event{
		SubjectID:  subjectID,
		ResourceID: resourceID,
		Action:     action,
		Decision:   dec,
		Input:      g.summarizeInput(subjectID, resourceID, action),
	}

	if dec.Allowed {
		// 仅在授权通过后才触碰业务明文。
		rec, ok := g.data.Get(resourceID)
		if !ok {
			rec = map[string]any{}
		}
		sub, _ := g.dir.Subject(subjectID)
		res, _ := g.dir.Resource(resourceID)
		p, _ := g.pol.Get(dec.PolicyVersion)
		out, outcomes, dropped := g.red.Apply(rec, res, sub, p)
		result.Data = out
		result.FieldOutcomes = outcomes
		result.DroppedFields = dropped
		ev.Redacted = outcomes
		ev.Dropped = dropped
	}

	stored := g.audit.Record(ev)
	result.Decision = stored.Decision
	return result, stored
}

// Replay 使用指定历史版本策略复现一次判定（不重放脱敏、不写审计）。
// 旧版本下的结论只依赖当时的策略快照，因此与历史判定一致可复现。
func (g *Gateway) Replay(subjectID, resourceID string, action model.Action, policyVersion int64) (*model.Decision, error) {
	p, ok := g.pol.Get(policyVersion)
	if !ok {
		return nil, fmt.Errorf("policy version %d not found", policyVersion)
	}
	sub, ok := g.dir.Subject(subjectID)
	if !ok {
		return &model.Decision{
			Allowed: false, Reason: model.DenyUnknownSubject,
			SubjectID: subjectID, ResourceID: resourceID, Action: action,
			PolicyVersion: policyVersion,
			Message:       fmt.Sprintf("subject %q is not registered", subjectID),
		}, nil
	}
	res, ok := g.dir.Resource(resourceID)
	if !ok {
		return &model.Decision{
			Allowed: false, Reason: model.DenyResourceNotFound,
			SubjectID: subjectID, ResourceID: resourceID, Action: action,
			PolicyVersion: policyVersion,
			Message:       fmt.Sprintf("resource %q does not exist", resourceID),
		}, nil
	}
	return g.eng.Evaluate(sub, res, action, p), nil
}

// Audit 暴露审计日志供查询。
func (g *Gateway) Audit() *audit.Log { return g.audit }

// Policies 暴露策略存储供加载/查询。
func (g *Gateway) Policies() *policy.Store { return g.pol }

// summarizeInput 生成审计输入摘要，确保单测/日志中可见输入参数。
func (g *Gateway) summarizeInput(subjectID, resourceID string, action model.Action) string {
	sub, sok := g.dir.Subject(subjectID)
	res, rok := g.dir.Resource(resourceID)
	pv := int64(0)
	if p, ok := g.pol.Current(); ok {
		pv = p.Version
	}
	switch {
	case !sok && !rok:
		return fmt.Sprintf("input={subject:%q(unknown) resource:%q(unknown) action:%s policyVersion:%d}",
			subjectID, resourceID, action, pv)
	case !sok:
		return fmt.Sprintf("input={subject:%q(unknown) resource:%q sensitivity:%s action:%s policyVersion:%d}",
			subjectID, resourceID, res.Sensitivity, action, pv)
	case !rok:
		return fmt.Sprintf("input={subject:%q clearance:%s attrs:%v resource:%q(unknown) action:%s policyVersion:%d}",
			subjectID, sub.Clearance, sub.Attributes, resourceID, action, pv)
	default:
		return fmt.Sprintf("input={subject:%q clearance:%s attrs:%v depts:%v resource:%q owner:%q sensitivity:%s action:%s policyVersion:%d}",
			subjectID, sub.Clearance, sub.Attributes, sub.Departments,
			resourceID, res.OwnerID, res.Sensitivity, action, pv)
	}
}
