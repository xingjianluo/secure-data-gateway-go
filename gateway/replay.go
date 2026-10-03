package gateway

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrReplayNotApplicable 表示该审计记录不适用于按版本复现
// （例如判定从未进入策略评估，记录未关联策略版本）。
// 与 ErrVersionNotRetained 区分：前者是“无版本可复现”，后者是“版本已不在保留范围”。
var ErrReplayNotApplicable = errors.New("replay not applicable to this record")

// Replay 按审计记录中留存的当时生效版本，重新给出判定结论与依据，
// 并与原始记录逐项比对（是否放行、拒绝归属、命中依据、版本号、字段投影）。
//
// 复现是只读操作：不写入审计日志、不修改任何状态，
// 因此同一记录反复复现输出恒定。判定与字段处理复用与在线访问
// 完全相同的引擎与脱敏器，同一版本同一输入结论一致。
func (g *Gateway) Replay(rec AuditRecord) (ReplayResult, error) {
	return g.ReplayAt(rec, rec.Decision.PolicyVersion)
}

// ReplayAt 与 Replay 相同，但显式指定用于复现的策略版本，
// 可用于“若当时生效的是另一版本会怎样”的复核。
// 指定版本已不在保留范围时返回包裹 ErrVersionNotRetained 的错误，
// 绝不会退回当前版本顶包。
func (g *Gateway) ReplayAt(rec AuditRecord, version string) (ReplayResult, error) {
	res := g.replay(rec, version)
	return res, res.Err
}

// ReplayBatch 对一批已记录的访问做批量复现对账。
//
// 确定性保证：输入先按审计序号稳定排序再逐条复现，
// 同一批输入反复执行，输出内容与顺序完全一致；
// 每条结果与对该条单独调用 Replay 的结果一致。
// 单条失败（如版本已淘汰）不影响其他条，失败信息落在该条的 Err 上。
func (g *Gateway) ReplayBatch(recs []AuditRecord) []ReplayResult {
	sorted := make([]AuditRecord, len(recs))
	copy(sorted, recs)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Seq < sorted[j].Seq })

	out := make([]ReplayResult, len(sorted))
	for i, rec := range sorted {
		out[i] = g.replay(rec, rec.Decision.PolicyVersion)
	}
	return out
}

// replay 为单条复现主流程，错误收敛到 ReplayResult.Err。
func (g *Gateway) replay(rec AuditRecord, version string) ReplayResult {
	res := ReplayResult{Seq: rec.Seq, Version: version}

	// 判定未进入策略评估的记录（未知主体 / 资源不存在 / 当时无可用策略）：
	// 结论与策略内容无关，按记录直接复现。
	// 复现结论不加盖新时间戳（EvaluatedAt 保持零值），
	// 保证同一输入反复复现、批量与逐条复现的输出完全一致。
	switch rec.Decision.Reason {
	case DenyUnknownSubject:
		res.Decision = Decision{Allowed: false, Reason: DenyUnknownSubject}
		res.compare(rec)
		return res
	case DenyResourceNotFound:
		res.Decision = Decision{Allowed: false, Reason: DenyResourceNotFound}
		res.compare(rec)
		return res
	case DenyPolicyNotFound:
		res.Decision = Decision{Allowed: false, Reason: DenyPolicyNotFound}
		res.compare(rec)
		return res
	}

	if version == "" {
		res.Err = fmt.Errorf("%w: record seq=%d has no policy version", ErrReplayNotApplicable, rec.Seq)
		return res
	}

	// 整条复现固定在这一个完整版本快照上：版本不可变，
	// 并发热更新/淘汰不会让本次复现读到半更新状态或混入其他版本。
	p, ok := g.store.Version(version)
	if !ok {
		res.Err = fmt.Errorf("%w: version %q (record seq=%d)", ErrVersionNotRetained, version, rec.Seq)
		return res
	}

	sub := rec.Subject
	d := g.engine.Evaluate(p, sub, rec.Request)
	d.EvaluatedAt = time.Time{} // 复现结论不打新时间戳，保证输出确定
	res.Decision = d
	if d.Allowed {
		out, kept, dropped := g.masker.Project(p, sub, rec.Request.Action,
			copyData(rec.Data), rec.Request.Resource.Fields)
		res.Output = out
		res.KeptFields = kept
		res.Dropped = dropped
	}
	res.compare(rec)
	return res
}

// compare 将复现结论与原始审计记录逐项比对。
// EvaluatedAt 是复现发生时间，不参与比对；其余判定要素全部逐项核对。
func (res *ReplayResult) compare(rec AuditRecord) {
	o, n := rec.Decision, res.Decision
	var mm []string
	if n.Allowed != o.Allowed {
		mm = append(mm, fmt.Sprintf("allowed: %t -> %t", o.Allowed, n.Allowed))
	}
	if n.Reason != o.Reason {
		mm = append(mm, fmt.Sprintf("reason: %q -> %q", o.Reason, n.Reason))
	}
	if n.PolicyVersion != o.PolicyVersion {
		mm = append(mm, fmt.Sprintf("policy_version: %q -> %q", o.PolicyVersion, n.PolicyVersion))
	}
	if n.PolicyID != o.PolicyID {
		mm = append(mm, fmt.Sprintf("policy_id: %q -> %q", o.PolicyID, n.PolicyID))
	}
	if !equalStrings(n.MatchedRules, o.MatchedRules) {
		mm = append(mm, fmt.Sprintf("matched_rules: [%s] -> [%s]",
			strings.Join(o.MatchedRules, "; "), strings.Join(n.MatchedRules, "; ")))
	}
	if !equalStrings(res.KeptFields, rec.OutputFields) {
		mm = append(mm, fmt.Sprintf("output_fields: %v -> %v", rec.OutputFields, res.KeptFields))
	}
	if !equalStrings(res.Dropped, rec.DroppedFields) {
		mm = append(mm, fmt.Sprintf("dropped_fields: %v -> %v", rec.DroppedFields, res.Dropped))
	}
	res.Mismatches = mm
	res.Consistent = len(mm) == 0
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
