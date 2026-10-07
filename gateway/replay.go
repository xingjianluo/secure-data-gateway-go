package gateway

import (
	"fmt"
	"strings"
	"time"
)

// ReplayResult 为一条历史访问的复现对账结果。
type ReplayResult struct {
	Seq        int64    // 原始审计记录序号
	Version    string   // 复现实际使用的策略版本
	Original   Decision // 当初记录下的判定结论
	Replayed   Decision // 用指定版本重新判定的结论
	Match      bool     // 逐项比对是否全部一致
	Mismatches []string // 不一致项的逐项说明（Match 为 true 时为空）
}

// Replay 用指定策略版本复现一笔历史访问的判定结论，并与原始记录逐项对账。
//
// version 为空时使用原始记录中保存的判定版本（即“当时生效的版本”）。
// 版本已被淘汰时返回 ErrVersionEvicted、从未发布过时返回 ErrVersionNotFound，
// 绝不回退到当前版本顶包，也不当作不存在静默跳过。
//
// 复现与正常访问共用同一套判定引擎与判定口径：判定输入全部来自审计记录
// （请求 + 主体快照），不读取当前主体目录。
//
// 复现是纯函数：不写入审计、不改动任何可观察状态。因此同一批复核请求
// 反复执行结果完全一致，且复核本身不会污染后续对账的输入（审计记录集）。
func (g *Gateway) Replay(rec AuditRecord, version string) (ReplayResult, error) {
	if version == "" {
		version = rec.Decision.PolicyVersion
	}
	// 版本非空才查存储：网关层拒绝（未知主体/资源缺失）的记录不携带版本，
	// 其判定不依赖策略，无需取快照。
	var p *Policy
	if version != "" {
		var err error
		p, err = g.store.Version(version)
		if err != nil {
			return ReplayResult{}, err
		}
	}

	var d Decision
	if !rec.SubjectKnown {
		// 网关层拒绝（未知主体、资源缺失）不经过判定引擎、与策略版本无关，
		// 结论是确定的，按原口径重建即可。
		d = Decision{
			Allowed:     false,
			Reason:      rec.Decision.Reason,
			EvaluatedAt: nowUTC(),
		}
	} else {
		d = g.engine.Evaluate(p, rec.Subject, rec.Request)
	}

	res := ReplayResult{
		Seq:      rec.Seq,
		Version:  version,
		Original: rec.Decision,
		Replayed: d,
	}
	res.Mismatches = CompareDecisions(rec.Decision, d)
	res.Match = len(res.Mismatches) == 0
	return res, nil
}

// ReplayBatch 对一批已记录的访问逐条复现对账。
//
// 每条记录默认使用其自身记录的判定版本（可用 version 统一覆盖，为空则不覆盖）。
// 结果顺序与输入顺序一致；判定为纯函数，同一批输入反复执行，
// 输出内容与顺序必然稳定。某一条版本不可复现时，该条位置填入错误信息，
// 不影响其余记录对账。
func (g *Gateway) ReplayBatch(recs []AuditRecord, version string) []ReplayResult {
	out := make([]ReplayResult, 0, len(recs))
	for _, rec := range recs {
		res, err := g.Replay(rec, version)
		if err != nil {
			out = append(out, ReplayResult{
				Seq:        rec.Seq,
				Version:    firstNonEmpty(version, rec.Decision.PolicyVersion),
				Original:   rec.Decision,
				Match:      false,
				Mismatches: []string{fmt.Sprintf("replay_error: %v", err)},
			})
			continue
		}
		out = append(out, res)
	}
	return out
}

// CompareDecisions 逐项比对两条判定结论（忽略评估时间戳），
// 返回不一致项说明；空切片表示完全一致。
// 比对项：是否放行、拒绝归属、命中规则 ID、判定依据、策略版本。
func CompareDecisions(a, b Decision) []string {
	var diff []string
	if a.Allowed != b.Allowed {
		diff = append(diff, fmt.Sprintf("allowed: %t != %t", a.Allowed, b.Allowed))
	}
	if a.Reason != b.Reason {
		diff = append(diff, fmt.Sprintf("reason: %q != %q", a.Reason, b.Reason))
	}
	if a.PolicyID != b.PolicyID {
		diff = append(diff, fmt.Sprintf("policy_id: %q != %q", a.PolicyID, b.PolicyID))
	}
	if a.PolicyVersion != b.PolicyVersion {
		diff = append(diff, fmt.Sprintf("policy_version: %q != %q", a.PolicyVersion, b.PolicyVersion))
	}
	if strings.Join(a.MatchedRules, "\x00") != strings.Join(b.MatchedRules, "\x00") {
		diff = append(diff, fmt.Sprintf("matched_rules: %v != %v", a.MatchedRules, b.MatchedRules))
	}
	return diff
}

// RecordsInWindow 返回判定时间在 [start, end] 闭区间内的审计记录副本，
// 供按时间窗批量复现对账。零值时间表示对应端不限。
func (l *Logger) RecordsInWindow(start, end time.Time) []AuditRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []AuditRecord
	for _, r := range l.records {
		if !start.IsZero() && r.Time.Before(start) {
			continue
		}
		if !end.IsZero() && r.Time.After(end) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
