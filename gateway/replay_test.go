package gateway

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- 复现测试夹具 ----

// replayPolicy 生成指定版本的测试策略：
// v1: eng 可读 / sales 可读；v2 起追加 legal 可读；v3 起追加 eng 可写。
func replayPolicy(version string) *Policy {
	rules := []Rule{
		{ID: "eng-read", Departments: []string{"engineering"}, Actions: []Action{ActionRead}, MinLevel: LevelInternal, Description: "工程只读"},
		{ID: "sales-read", Departments: []string{"sales"}, Actions: []Action{ActionRead}, MinLevel: LevelPublic, Description: "销售只读"},
	}
	if version >= "2.0.0" {
		rules = append(rules, Rule{ID: "legal-read", Departments: []string{"legal"}, Actions: []Action{ActionRead}, MinLevel: LevelInternal, Description: "法务只读"})
	}
	if version >= "3.0.0" {
		rules = append(rules, Rule{ID: "eng-write", Departments: []string{"engineering"}, Actions: []Action{ActionWrite}, MinLevel: LevelConfidential, Description: "工程可写"})
	}
	return &Policy{
		Version:      version,
		MinSupported: "1.0.0",
		Rules:        rules,
		FieldModes: map[Level]map[Action]FieldMode{
			LevelInternal:     {ActionRead: FieldMask},
			LevelConfidential: {ActionRead: FieldTokenize},
		},
	}
}

func newReplayGateway(t *testing.T, retention int) *Gateway {
	t.Helper()
	cat := NewCatalog(
		Subject{ID: "alice", Department: "engineering", Role: "engineer", Clearance: LevelConfidential},
		Subject{ID: "bob", Department: "sales", Role: "rep", Clearance: LevelInternal},
		Subject{ID: "carol", Department: "legal", Role: "counsel", Clearance: LevelConfidential},
		Subject{ID: "dave", Department: "engineering", Role: "intern", Clearance: LevelPublic},
	)
	gw := New(cat, NewStoreWithRetention(replayPolicy("1.0.0"), retention),
		[]byte("replay-test-secret"), nil)
	ds := NewDataSource()
	ds.Put("cust-1",
		map[string]any{"name": "Alice Wang", "phone": "13812345678", "email": "a@example.com"},
		map[string]Level{"name": LevelPublic, "phone": LevelInternal, "email": LevelConfidential})
	gw.UseDataSource(ds)
	return gw
}

func replayReadReq(subject string) AccessRequest {
	return AccessRequest{
		SubjectID: subject,
		Action:    ActionRead,
		Resource:  Resource{ID: "cust-1", Level: LevelInternal},
	}
}

// accessAndRecord 执行一次访问并返回刚写入的审计记录。
func accessAndRecord(t *testing.T, gw *Gateway, req AccessRequest) AuditRecord {
	t.Helper()
	before := gw.Audit().Len()
	_, d, _ := gw.Access(req)
	recs := gw.Audit().Records()
	if len(recs) != before+1 {
		t.Fatalf("审计记录数异常: before=%d after=%d", before, len(recs))
	}
	rec := recs[len(recs)-1]
	t.Logf("记录 seq=%d 输入 subject=%q action=%s resource=%q -> 版本=%s allowed=%t reason=%q 依据=%v",
		rec.Seq, req.SubjectID, req.Action, req.Resource.ID,
		d.PolicyVersion, d.Allowed, d.Reason, d.MatchedRules)
	return rec
}

// ---- 按版本复现与原始结论一致 ----

func TestReplayMatchesOriginalDecision(t *testing.T) {
	gw := newReplayGateway(t, 4)

	// v1 时期：放行、操作拒绝、策略缺失、级别不足、未知主体各一笔。
	recAllow := accessAndRecord(t, gw, replayReadReq("alice"))
	recAction := accessAndRecord(t, gw, AccessRequest{SubjectID: "alice", Action: ActionWrite,
		Resource: Resource{ID: "cust-1", Level: LevelInternal}})
	recNoPolicy := accessAndRecord(t, gw, replayReadReq("carol"))
	recLevel := accessAndRecord(t, gw, replayReadReq("dave"))
	recUnknown := accessAndRecord(t, gw, replayReadReq("ghost"))

	// 热更新到 v2（legal 获得读权限），carol 同样的输入结论翻转。
	if err := gw.PolicyStore().Update(replayPolicy("2.0.0")); err != nil {
		t.Fatal(err)
	}
	recCarolV2 := accessAndRecord(t, gw, replayReadReq("carol"))
	if !recCarolV2.Decision.Allowed {
		t.Fatal("v2 下 carol 应放行")
	}

	// 用当时生效的版本逐笔复现，结论与依据必须逐项一致。
	for _, rec := range []AuditRecord{recAllow, recAction, recNoPolicy, recLevel, recUnknown, recCarolV2} {
		res, err := gw.Replay(rec, "")
		if err != nil {
			t.Fatalf("seq=%d 复现失败: %v", rec.Seq, err)
		}
		t.Logf("复现 seq=%d 版本=%s -> allowed=%t reason=%q 依据=%v match=%t",
			rec.Seq, res.Version, res.Replayed.Allowed, res.Replayed.Reason,
			res.Replayed.MatchedRules, res.Match)
		if !res.Match {
			t.Fatalf("seq=%d 复现与原始结论不一致: %v", rec.Seq, res.Mismatches)
		}
		if res.Replayed.PolicyVersion != rec.Decision.PolicyVersion {
			t.Fatalf("seq=%d 复现版本 %q != 原始版本 %q", rec.Seq,
				res.Replayed.PolicyVersion, rec.Decision.PolicyVersion)
		}
	}

	// 显式指定版本：carol 的 v1 记录用 v1 复现仍是 policy_not_found，
	// 用 v2 复现则放行且对账能指出版本差异（不允许混用版本）。
	res, err := gw.Replay(recNoPolicy, "1.0.0")
	if err != nil || !res.Match || res.Replayed.Reason != DenyPolicyNotFound {
		t.Fatalf("v1 复现 carol 应为 policy_not_found 且一致: %+v err=%v", res, err)
	}
	res, err = gw.Replay(recNoPolicy, "2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.Match || res.Replayed.Allowed != true {
		t.Fatalf("v2 复现 carol 的 v1 记录应放行且对账不一致: %+v", res)
	}
	t.Logf("跨版本复现(预期不一致): %v", res.Mismatches)
}

// ---- 批量复现与逐条复现一致，且反复执行输出稳定 ----

func TestReplayBatchConsistentAndDeterministic(t *testing.T) {
	gw := newReplayGateway(t, 8)

	if err := gw.PolicyStore().Update(replayPolicy("2.0.0")); err != nil {
		t.Fatal(err)
	}
	// 一批混合版本、混合结论的访问。
	var batch []AuditRecord
	for _, sub := range []string{"alice", "bob", "carol", "dave", "ghost"} {
		batch = append(batch, accessAndRecord(t, gw, replayReadReq(sub)))
	}
	if err := gw.PolicyStore().Update(replayPolicy("3.0.0")); err != nil {
		t.Fatal(err)
	}
	batch = append(batch, accessAndRecord(t, gw, replayReadReq("alice")))

	single := make([]ReplayResult, 0, len(batch))
	for _, rec := range batch {
		res, err := gw.Replay(rec, "")
		if err != nil {
			t.Fatalf("seq=%d 复现失败: %v", rec.Seq, err)
		}
		single = append(single, res)
	}

	runBatch := func() []ReplayResult { return gw.ReplayBatch(batch, "") }
	b1 := runBatch()
	b2 := runBatch()

	if len(b1) != len(batch) {
		t.Fatalf("批量结果条数 %d != 输入 %d", len(b1), len(batch))
	}
	for i := range b1 {
		// 批量与逐条一致。
		if !sameReplayResult(b1[i], single[i]) {
			t.Fatalf("第 %d 条批量与逐条不一致:\nbatch=%+v\nsingle=%+v", i, b1[i], single[i])
		}
		// 反复执行输出内容与顺序稳定。
		if !sameReplayResult(b1[i], b2[i]) {
			t.Fatalf("第 %d 条两次批量执行不稳定:\nrun1=%+v\nrun2=%+v", i, b1[i], b2[i])
		}
		if b1[i].Seq != batch[i].Seq {
			t.Fatalf("第 %d 条顺序错位: got seq=%d want seq=%d", i, b1[i].Seq, batch[i].Seq)
		}
		if !b1[i].Match {
			t.Fatalf("第 %d 条(seq=%d)对账不一致: %v", i, b1[i].Seq, b1[i].Mismatches)
		}
	}
	t.Logf("批量复现 %d 条全部一致，两次执行输出稳定", len(b1))
}

// sameReplayResult 比较两条复现结果（忽略评估时间戳）。
func sameReplayResult(a, b ReplayResult) bool {
	if a.Seq != b.Seq || a.Version != b.Version || a.Match != b.Match {
		return false
	}
	if strings.Join(a.Mismatches, "|") != strings.Join(b.Mismatches, "|") {
		return false
	}
	return len(CompareDecisions(a.Replayed, b.Replayed)) == 0
}

// ---- 版本被淘汰后的明确反馈 ----

func TestReplayEvictedVersionReported(t *testing.T) {
	gw := newReplayGateway(t, 1) // 只保留 1 个历史版本

	recV1 := accessAndRecord(t, gw, replayReadReq("alice"))
	if err := gw.PolicyStore().Update(replayPolicy("2.0.0")); err != nil {
		t.Fatal(err)
	}
	recV2 := accessAndRecord(t, gw, replayReadReq("carol"))
	if err := gw.PolicyStore().Update(replayPolicy("3.0.0")); err != nil {
		t.Fatal(err)
	}
	// 此时历史=[2.0.0]，1.0.0 已被淘汰，当前=3.0.0。

	// 被淘汰版本：明确的 ErrVersionEvicted，可区分，绝不拿当前版本顶包。
	_, err := gw.Replay(recV1, "")
	if !errors.Is(err, ErrVersionEvicted) {
		t.Fatalf("淘汰版本复现应返回 ErrVersionEvicted, got %v", err)
	}
	if errors.Is(err, ErrVersionNotFound) {
		t.Fatal("淘汰版本不得误报为从未存在")
	}
	t.Logf("淘汰版本复现反馈: %v", err)

	// 从未发布过的版本：ErrVersionNotFound，与淘汰可区分。
	_, err = gw.Replay(recV1, "9.9.9")
	if !errors.Is(err, ErrVersionNotFound) || errors.Is(err, ErrVersionEvicted) {
		t.Fatalf("未知版本应返回 ErrVersionNotFound, got %v", err)
	}

	// 保留期内的历史版本与当前版本始终可复现。
	if _, err = gw.Replay(recV2, ""); err != nil {
		t.Fatalf("保留期内版本复现失败: %v", err)
	}
	cur := accessAndRecord(t, gw, replayReadReq("alice"))
	res, err := gw.Replay(cur, "")
	if err != nil || !res.Match {
		t.Fatalf("当前版本复现失败: %+v err=%v", res, err)
	}

	// 批量路径同样明确反馈，且不影响其他记录对账。
	results := gw.ReplayBatch([]AuditRecord{recV1, recV2}, "")
	if len(results) != 2 {
		t.Fatalf("批量结果条数异常: %d", len(results))
	}
	if results[0].Match || len(results[0].Mismatches) == 0 ||
		!strings.Contains(results[0].Mismatches[0], ErrVersionEvicted.Error()) {
		t.Fatalf("批量中淘汰版本应有明确错误项: %+v", results[0])
	}
	if !results[1].Match {
		t.Fatalf("批量中保留版本应一致: %+v", results[1])
	}
	t.Logf("批量对淘汰版本的反馈: %v", results[0].Mismatches)
}

// ---- 当前版本永远不会被淘汰 ----

func TestCurrentVersionNeverEvicted(t *testing.T) {
	gw := newReplayGateway(t, 0) // 不保留任何历史版本

	for _, v := range []string{"2.0.0", "3.0.0", "3.1.0", "3.2.0"} {
		if err := gw.PolicyStore().Update(replayPolicy(v)); err != nil {
			t.Fatal(err)
		}
	}
	rec := accessAndRecord(t, gw, replayReadReq("alice"))
	res, err := gw.Replay(rec, "")
	if err != nil || !res.Match {
		t.Fatalf("retention=0 时当前版本必须可复现: %+v err=%v", res, err)
	}
	// 旧版本全部明确落在“已淘汰”而非“不存在”。
	if _, err := gw.PolicyStore().Version("1.0.0"); !errors.Is(err, ErrVersionEvicted) {
		t.Fatalf("旧版本应为已淘汰: %v", err)
	}
	if got := gw.PolicyStore().Versions(); len(got) != 1 || got[0] != "3.2.0" {
		t.Fatalf("可复现版本应只剩当前版本, got %v", got)
	}
}

// ---- 并发更新与并发复现叠加时结果自洽 ----

func TestConcurrentUpdateAndReplay(t *testing.T) {
	gw := newReplayGateway(t, 3)

	rec := accessAndRecord(t, gw, replayReadReq("alice"))
	cur := accessAndRecord(t, gw, replayReadReq("carol")) // v1 下 carol 被拒

	var updWg, repWg sync.WaitGroup
	stop := make(chan struct{})

	// 更新方：顺序发布兼容版本（2.0.0..2.0.9），触发历史淘汰。
	updWg.Add(1)
	go func() {
		defer updWg.Done()
		for i := 0; i < 10; i++ {
			p := replayPolicy("2.0.0")
			p.Version = fmt.Sprintf("2.0.%d", i)
			if err := gw.PolicyStore().Update(p); err != nil {
				t.Errorf("更新失败: %v", err)
				return
			}
		}
	}()

	// 复现方：持续复现历史记录。结果只允许两种：
	// 复现成功且与原始结论一致；或版本已被淘汰（明确错误）。
	// 绝不出现结论错乱、半更新状态或错误顶包。
	for i := 0; i < 8; i++ {
		repWg.Add(1)
		go func(rec AuditRecord) {
			defer repWg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				res, err := gw.Replay(rec, "")
				if err != nil {
					if !errors.Is(err, ErrVersionEvicted) {
						t.Errorf("seq=%d 复现出现非淘汰类错误: %v", rec.Seq, err)
						return
					}
					continue
				}
				if !res.Match {
					t.Errorf("seq=%d 并发复现结论不一致: %v", rec.Seq, res.Mismatches)
					return
				}
			}
		}(rec)
	}
	// 另一组：每次先取当前版本快照再复现——任何时刻当前版本都必须完整可用，
	// 复现结论必须整体落在该版本上（alice 的读请求在所有版本下都放行，
	// 命中规则不变，可借此校验结论不混杂新旧版本）。
	for i := 0; i < 4; i++ {
		repWg.Add(1)
		go func() {
			defer repWg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				v := gw.PolicyStore().Snapshot().Version
				res, err := gw.Replay(rec, v)
				if err != nil {
					t.Errorf("当前版本 %s 复现失败: %v", v, err)
					return
				}
				if !res.Replayed.Allowed || res.Replayed.Reason != DenyNone ||
					res.Replayed.PolicyVersion != v || res.Replayed.PolicyID != "eng-read" {
					t.Errorf("复现未整体落在版本 %s 上: %+v", v, res.Replayed)
					return
				}
			}
		}()
	}

	updWg.Wait()
	close(stop)
	repWg.Wait()
	_ = cur
	t.Logf("并发更新与复现完成，最终可复现版本: %v", gw.PolicyStore().Versions())
}

// ---- 复现结果中拒绝归属可区分 ----

func TestReplayDenyReasonsDistinguishable(t *testing.T) {
	gw := newReplayGateway(t, 4)

	recs := map[DenyReason]AuditRecord{
		DenyUnknownSubject:    accessAndRecord(t, gw, replayReadReq("ghost")),
		DenyPolicyNotFound:    accessAndRecord(t, gw, replayReadReq("carol")),
		DenyActionDenied:      accessAndRecord(t, gw, AccessRequest{SubjectID: "alice", Action: ActionDelete, Resource: Resource{ID: "cust-1", Level: LevelInternal}}),
		DenyLevelInsufficient: accessAndRecord(t, gw, replayReadReq("dave")),
	}

	seen := map[DenyReason]bool{}
	for want, rec := range recs {
		res, err := gw.Replay(rec, "")
		if err != nil {
			t.Fatalf("seq=%d 复现失败: %v", rec.Seq, err)
		}
		got := res.Replayed.Reason
		t.Logf("复现 seq=%d 输入 subject=%q action=%s -> 版本=%s reason=%q 依据=%v",
			rec.Seq, rec.Request.SubjectID, rec.Request.Action,
			res.Version, got, res.Replayed.MatchedRules)
		if got != want || !res.Match {
			t.Fatalf("拒绝归属复现异常: want=%q got=%q match=%t diff=%v",
				want, got, res.Match, res.Mismatches)
		}
		seen[got] = true
	}
	// 四类拒绝两两可区分，不得互相混淆。
	if len(seen) != 4 {
		t.Fatalf("四类拒绝归属应全部出现且互不相同, got %v", seen)
	}
}

// ---- 按时间窗批量复现 ----

func TestReplayWindow(t *testing.T) {
	gw := newReplayGateway(t, 8)

	before := time.Now()
	first := accessAndRecord(t, gw, replayReadReq("alice"))
	mid := time.Now()
	second := accessAndRecord(t, gw, replayReadReq("bob"))
	after := time.Now()

	window := gw.Audit().RecordsInWindow(mid, after)
	if len(window) != 1 || window[0].Seq != second.Seq {
		t.Fatalf("时间窗过滤异常: got %d 条", len(window))
	}
	window = gw.Audit().RecordsInWindow(before, after)
	if len(window) != 2 || window[0].Seq != first.Seq || window[1].Seq != second.Seq {
		t.Fatalf("全窗过滤异常: got %d 条", len(window))
	}

	results := gw.ReplayBatch(window, "")
	for _, r := range results {
		if !r.Match {
			t.Fatalf("窗内 seq=%d 复现不一致: %v", r.Seq, r.Mismatches)
		}
	}
	t.Logf("时间窗 [%s, %s] 内 %d 条记录复现全部一致",
		before.Format(time.RFC3339), after.Format(time.RFC3339), len(results))
}
