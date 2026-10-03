package gateway

import (
	"errors"
	"io"
)

// 入口错误：与判定拒绝原因对应，保证调用方可以区分三类拒绝，
// 而不是拿到一个笼统的错误。
var (
	ErrUnknownSubject  = errors.New("unknown subject")
	ErrAccessDenied    = errors.New("access denied")
	ErrResourceMissing = errors.New("resource not found")
)

// Gateway 聚合主体目录、策略存储、判定引擎、脱敏器、数据源与审计。
// 两个对外入口（Access / AccessRecord）共用同一条内部路径，
// 保证不同入口下授权、脱敏与审计结论一致且可复现。
type Gateway struct {
	catalog *Catalog
	store   *Store
	engine  *Engine
	masker  *Masker
	audit   *Logger
	ds      *DataSource
}

// New 组装网关。
func New(cat *Catalog, store *Store, secret []byte, auditOut io.Writer) *Gateway {
	return &Gateway{
		catalog: cat,
		store:   store,
		engine:  NewEngine(),
		masker:  NewMasker(secret),
		audit:   NewLogger(auditOut),
	}
}

// UseDataSource 挂载本地数据源（入口一使用）。
func (g *Gateway) UseDataSource(ds *DataSource) *Gateway {
	g.ds = ds
	return g
}

// AuditLogger 暴露审计记录器，供测试与上层读取审计结论。
func (g *Gateway) Audit() *Logger { return g.audit }

// PolicyStore 暴露策略存储，供上层安全热更新。
func (g *Gateway) PolicyStore() *Store { return g.store }

// Access 入口一：按资源 ID 从本地数据源取数，执行判定、脱敏与审计。
func (g *Gateway) Access(req AccessRequest) (map[string]any, Decision, error) {
	if g.ds == nil {
		return nil, Decision{}, ErrResourceMissing
	}
	rec, ok := g.ds.Get(req.Resource.ID)
	if !ok {
		// 资源不存在也经过审计：输入与结论均可追溯。
		d := Decision{Allowed: false, Reason: DenyPolicyNotFound, EvaluatedAt: nowUTC()}
		g.audit.Log(req, nil, d, nil, nil)
		return nil, d, ErrResourceMissing
	}
	res := req.Resource
	res.Fields = rec.Levels
	req.Resource = res
	return g.AccessRecord(req, rec.Data)
}

// AccessRecord 入口二：调用方自带记录数据。
// 判定/脱敏/审计逻辑与入口一完全一致（二者汇聚到 process）。
func (g *Gateway) AccessRecord(req AccessRequest, data map[string]any) (map[string]any, Decision, error) {
	return g.process(req, data)
}

// process 为所有入口共享的处理管道。
func (g *Gateway) process(req AccessRequest, data map[string]any) (map[string]any, Decision, error) {
	// 1) 主体识别：未知主体立刻拒绝，原因与越权、策略缺失区分开。
	sub, ok := g.catalog.Get(req.SubjectID)
	if !ok {
		d := Decision{
			Allowed:     false,
			Reason:      DenyUnknownSubject,
			EvaluatedAt: nowUTC(),
		}
		g.audit.Log(req, nil, d, nil, nil)
		return nil, d, ErrUnknownSubject
	}

	// 2) 取一整份策略快照：之后无论怎样热更新，本次判定都基于同一版本。
	p := g.store.Snapshot()

	// 3) 判定（纯函数，结论可复现）。
	d := g.engine.Evaluate(p, sub, req)
	if !d.Allowed {
		g.audit.Log(req, &sub, d, nil, nil)
		return nil, d, ErrAccessDenied
	}

	// 4) 通过授权后做字段投影：无权字段整体剔除，其余按级别脱敏/令牌化。
	out, kept, dropped := g.masker.Project(p, sub, req.Action, data, req.Resource.Fields)

	// 5) 审计：输入、依据、实际输出字段与剔除字段全部留痕。
	g.audit.Log(req, &sub, d, kept, dropped)
	return out, d, nil
}

// ReloadPolicy 从本地 JSON 文件加载并安全热更新策略；
// 不兼容/非法时由 Store 拒绝并保持原策略可用，错误向上透传。
func (g *Gateway) ReloadPolicy(path string) error {
	p, err := LoadPolicyFile(path)
	if err != nil {
		return err
	}
	return g.store.Update(p)
}
