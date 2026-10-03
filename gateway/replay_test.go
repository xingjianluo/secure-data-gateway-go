package gateway

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

// ---- 复现测试夹具 ----

// testPolicyV2 在 v1 基础上新增 legal 部门读权限（向后兼容）。
func testPolicyV2() *Policy {
	p := testPolicyV1()
	p.Version = "2.0.0"
	p.Rules = append(append([]Rule(nil), p.Rules...),
		Rule{ID: "legal-read", Departments: []string{"legal"}, Actions: []Action{ActionRead}, MinLevel: LevelInternal, Description: "法务只读"})
	return p
}

// testPolicyV3 继续向后兼容的第三版。
func testPolicyV3() *Policy {
	p := testPolicyV2()
	p.Version = "3.0.0"
	return p
}

// collectV1Records 在 v1 下通过两个入口产生一批覆盖放行与各类拒绝的访问，
// 返回审计记录（随后热更新，用于按当时版本复现）。
func collectV1Records(t *testing.T, gw *Gateway) []AuditRecord {
	t.Helper()

	// 入口一：按资源取数。
	if _, _, err := gw.Access(readReq("alice", "cust-1", LevelInternal)); err != nil {
		t.Fatalf("alice 读应放行: %v", err)
	}
	// 入口二：调用方自带数据。
	if _, _, err := gw.AccessRecord(readReq("bob", "cust-1", LevelInternal), customerData()); err != nil {
		t.Fatalf("bob 读应放行: %v", err)
	}
	// 各类拒绝 + 未知主体 + 资源不存在。
	gw.AccessRecord(AccessRequest{SubjectID: "alice", Action: ActionWrite,
		Resource: Resource{ID: "cust-1", Level: LevelInternal, Fields: customerLevels()}}, customerData())
	gw.Access(readReq("alice", "cust-secret", LevelSecret))
	gw.AccessRecord(readReq("carol", "cust-1", LevelInternal), customerData())
	gw.AccessRecord(readReq("ghost", "cust-1", LevelInternal), customerData())
	gw.Access(readReq("alice", "cust-missing", LevelInternal))

	recs := gw.Audit().Records()
	if len(recs) != 7 {
		t.Fatalf("应产生 7 条审计记录, got %d", len(recs))
	}
	return recs
}

// ---- 按版本复现：结论与依据必须和原始记录逐项一致 ----

func TestReplayMatchesOriginalDecision(t *testing.T) {
	gw, _ := newFixture(t)
	recs := collectV1Records(t, gw)

	// 热更新到 v2 再复现：复现必须落在记录当时生效的 v1 上。
	if err := gw.PolicyStore().Update(testPolicyV2()); err != nil {
		t.Fatal(err)
	}

	for _, rec := range recs {
		res, err := gw.Replay(rec)
		t.Logf("复现输入: seq=%d subject=%q action=%s resource=%q 版本=%s",
			rec.Seq, rec.Request.SubjectID, rec.Request.Action, rec.Request.Resource.ID,
			rec.Decision.PolicyVersion)
		t.Logf("  原始: allowed=%t reason=%q version=%q basis=%v kept=%v dropped=%v",
			rec.Decision.Allowed, rec.Decision.Reason, rec.Decision.PolicyVersion,
			rec.Decision.MatchedRules, rec.OutputFields, rec.DroppedFields)
		if err != nil {
			t.Fatalf("seq=%d 复现失败: %v", rec.Seq, err)
		}
		t.Logf("  复现: allowed=%t reason=%q version=%q basis=%v kept=%v dropped=%v",
			res.Decision.Allowed, res.Decision.Reason, res.Decision.PolicyVersion,
			res.Decision.MatchedRules, res.KeptFields, res.Dropped)

		if !res.Consistent {
			t.Fatalf("seq=%d 复现与原始记录不一致: %v", rec.Seq, res.Mismatches)
		}
		// 逐项显式核对：是否放行、拒绝归属、命中依据、版本号。
		if res.Decision.Allowed != rec.Decision.Allowed ||
			res.Decision.Reason != rec.Decision.Reason ||
			res.Decision.PolicyVersion != rec.Decision.PolicyVersion ||
			res.Decision.PolicyID != rec.Decision.PolicyID ||
			!reflect.DeepEqual(res.Decision.MatchedRules, rec.Decision.MatchedRules) {
			t.Fatalf("seq=%d 判定要素不一致:\n原始=%+v\n复现=%+v", rec.Seq, rec.Decision, res.Decision)
		}
		// 复现必须钉在记录当时的版本上，而不是当前 v2。
		if rec.Decision.PolicyVersion != "" && res.Version != "1.0.0" {
			t.Fatalf("seq=%d 复现应使用 v1, got %s", rec.Seq, res.Version)
		}
	}

	// 对照：同一输入在当前 v2 下结论可能不同（carol 放行），
	// 证明复现确实用的是历史版本而非当前版本。
	now, _, err := gw.AccessRecord(readReq("carol", "cust-1", LevelInternal), customerData())
	_ = now
	if err != nil {
		t.Fatalf("v2 下 carol 应放行: %v", err)
	}
}

// ---- 批量复现：与逐条一致，且反复执行输出内容与顺序稳定 ----

func TestReplayBatchMatchesIndividualAndStable(t *testing.T) {
	gw, _ := newFixture(t)
	recs := collectV1Records(t, gw)
	if err := gw.PolicyStore().Update(testPolicyV2()); err != nil {
		t.Fatal(err)
	}

	// 乱序输入也应得到按审计序号排序的稳定输出。
	shuffled := []AuditRecord{recs[5], recs[1], recs[6], recs[0], recs[4], recs[2], recs[3]}
	batch := gw.ReplayBatch(shuffled)
	if len(batch) != len(recs) {
		t.Fatalf("批量结果条数=%d, 期望 %d", len(batch), len(recs))
	}
	for i, res := range batch {
		if res.Seq != recs[i].Seq {
			t.Fatalf("批量输出顺序应按审计序号升序: 位置 %d 期望 seq=%d, got %d", i, recs[i].Seq, res.Seq)
		}
	}

	// 批量与逐条必须完全一致。
	for i, rec := range recs {
		single, err := gw.Replay(rec)
		if err != nil {
			t.Fatalf("seq=%d 逐条复现失败: %v", rec.Seq, err)
		}
		if !reflect.DeepEqual(batch[i], single) {
			t.Fatalf("seq=%d 批量与逐条不一致:\n批量=%+v\n逐条=%+v", rec.Seq, batch[i], single)
		}
		t.Logf("seq=%d 批量=逐条: version=%s allowed=%t reason=%q consistent=%t",
			rec.Seq, single.Version, single.Decision.Allowed, single.Decision.Reason, single.Consistent)
	}

	// 同一批输入反复执行，输出内容与顺序逐字节稳定。
	again := gw.ReplayBatch(shuffled)
	if !reflect.DeepEqual(batch, again) {
		t.Fatal("同一批输入重复批量复现，输出必须完全一致")
	}
}

// ---- 版本被淘汰：必须给出可区分的明确反馈，绝不拿当前版本顶包 ----

func TestReplayEvictedVersionReportsDistinctly(t *testing.T) {
	gw, _ := newFixture(t)
	store := gw.PolicyStore()
	if err := store.SetRetention(1); err != nil {
		t.Fatal(err)
	}

	recs := collectV1Records(t, gw) // 全部落在 v1
	allowed := recs[0]

	// 连续热更新：v1 -> v2 -> v3，保留上限 1，v1 应按由旧到新先被淘汰。
	if err := store.Update(testPolicyV2()); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(testPolicyV3()); err != nil {
		t.Fatal(err)
	}
	t.Logf("当前可追溯版本: %v (保留上限=1)", store.Versions())

	res, err := gw.Replay(allowed)
	if !errors.Is(err, ErrVersionNotRetained) {
		t.Fatalf("已淘汰版本必须返回 ErrVersionNotRetained, got %v", err)
	}
	if !errors.Is(res.Err, ErrVersionNotRetained) {
		t.Fatalf("结果上也应携带同一错误, got %v", res.Err)
	}
	t.Logf("淘汰反馈: seq=%d version=%q err=%v", res.Seq, allowed.Decision.PolicyVersion, err)

	// 绝不能顺手拿当前版本算个结论顶上。
	if res.Decision.PolicyVersion != "" || res.Consistent {
		t.Fatalf("已淘汰版本不得产出任何判定结论: %+v", res.Decision)
	}

	// 从未发布过的版本同样明确反馈，且可与淘汰共用同一哨兵区分于其他错误。
	if _, err := gw.ReplayAt(allowed, "9.9.9"); !errors.Is(err, ErrVersionNotRetained) {
		t.Fatalf("未发布版本应返回 ErrVersionNotRetained, got %v", err)
	}

	// 仍在保留范围内的 v2 与当前版本 v3 必须可正常复现。
	if _, ok := store.Version("2.0.0"); !ok {
		t.Fatal("v2 应在保留范围内")
	}
	if _, ok := store.Version("3.0.0"); !ok {
		t.Fatal("当前版本永远不被淘汰")
	}
	res2, err := gw.ReplayAt(allowed, "2.0.0")
	if err != nil {
		t.Fatalf("v2 复现应成功: %v", err)
	}
	if res2.Decision.PolicyVersion != "2.0.0" {
		t.Fatalf("复现必须整体落在指定版本上, got %s", res2.Decision.PolicyVersion)
	}
	// v2 与 v1 对 alice 的判定内容相同，仅版本号不同：
	// 比对应如实报告版本差异，其余要素一致。
	if res2.Consistent {
		t.Fatal("跨版本复现应报告版本号差异")
	}
	if len(res2.Mismatches) != 1 ||
		res2.Mismatches[0] != `policy_version: "1.0.0" -> "2.0.0"` {
		t.Fatalf("跨版本复现仅应报告版本差异, got %v", res2.Mismatches)
	}
	if res2.Decision.Allowed != allowed.Decision.Allowed ||
		res2.Decision.Reason != allowed.Decision.Reason {
		t.Fatalf("判定要素应与原始一致: %+v", res2.Decision)
	}
}

// ---- 历史版本保留：由旧到新淘汰，当前版本永不淘汰，留存版本只读 ----

func TestHistoryRetentionEvictsOldestFirst(t *testing.T) {
	store := NewStore(testPolicyV1())
	if err := store.SetRetention(1); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(testPolicyV2()); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(testPolicyV3()); err != nil {
		t.Fatal(err)
	}

	// 保留上限 1（不含当前版本）：v1 先被淘汰，v2 留存，v3 为当前版本。
	got := store.Versions()
	want := []string{"2.0.0", "3.0.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("可追溯版本期望 %v, got %v", want, got)
	}
	if _, ok := store.Version("1.0.0"); ok {
		t.Fatal("v1 应已被淘汰")
	}

	// 收紧上限立即按由旧到新淘汰；当前版本不受影响。
	if err := store.SetRetention(0); err != nil {
		t.Fatal(err)
	}
	if got := store.Versions(); !reflect.DeepEqual(got, []string{"3.0.0"}) {
		t.Fatalf("收紧上限后应只剩当前版本, got %v", got)
	}
	if _, ok := store.Version("3.0.0"); !ok {
		t.Fatal("当前版本永不淘汰")
	}

	// 非法上限被拒绝。
	if err := store.SetRetention(-1); err == nil {
		t.Fatal("负数保留上限应被拒绝")
	}

	// 留存的历史版本只读：通过 Store 拿到的历史快照与当前快照互不干扰，
	// 历史版本内容不受后续更新影响。
	store2 := NewStore(testPolicyV1())
	v1snap := store2.Snapshot()
	if err := store2.Update(testPolicyV2()); err != nil {
		t.Fatal(err)
	}
	hist, ok := store2.Version("1.0.0")
	if !ok {
		t.Fatal("v1 应留存在历史区")
	}
	if hist != v1snap || hist.Version != "1.0.0" || len(hist.Rules) != 3 {
		t.Fatalf("历史版本必须保持发布时原样, got %+v", hist)
	}
}

// ---- 并发热更新 + 并发复现：每条复现整体落在一个完整版本上 ----

func TestConcurrentUpdateAndReplay(t *testing.T) {
	gw, _ := newFixture(t)
	store := gw.PolicyStore()
	recs := collectV1Records(t, gw) // v1 记录，保留上限默认 16，全程可复现

	var updWg, repWg sync.WaitGroup
	stop := make(chan struct{})

	// 更新方：顺序发布若干向后兼容版本。
	updWg.Add(1)
	go func() {
		defer updWg.Done()
		for _, ver := range []string{"1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"} {
			np := testPolicyV1()
			np.Version = ver
			if err := store.Update(np); err != nil {
				t.Errorf("更新 %s 失败: %v", ver, err)
				return
			}
		}
	}()

	// 复现方：并发对 v1 记录逐条/批量复现。
	// 自洽性要求：结果要么明确报告版本不可用，要么判定版本与请求版本一致、
	// 且与原始记录逐项一致——不得新旧混用、不得读到半更新状态。
	for i := 0; i < 8; i++ {
		repWg.Add(1)
		go func(i int) {
			defer repWg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rec := recs[i%len(recs)]
				res, err := gw.Replay(rec)
				if err != nil {
					if !errors.Is(err, ErrVersionNotRetained) {
						t.Errorf("复现出现非淘汰类错误: %v", err)
						return
					}
					continue
				}
				if rec.Decision.PolicyVersion != "" && res.Decision.PolicyVersion != rec.Decision.PolicyVersion {
					t.Errorf("复现版本混用: 请求=%s 实得=%s",
						rec.Decision.PolicyVersion, res.Decision.PolicyVersion)
					return
				}
				if !res.Consistent {
					t.Errorf("并发下复现与原始记录不一致: seq=%d %v", rec.Seq, res.Mismatches)
					return
				}
				if batch := gw.ReplayBatch(recs); len(batch) != len(recs) {
					t.Errorf("批量复现条数异常: %d", len(batch))
					return
				}
			}
		}(i)
	}

	updWg.Wait()
	close(stop)
	repWg.Wait()

	if got := store.Snapshot().Version; got != "1.5.0" {
		t.Fatalf("最终版本应为 1.5.0, got %s", got)
	}
	// 并发结束后 v1 记录复现仍必须一致（保留上限内）。
	for _, rec := range recs {
		res, err := gw.Replay(rec)
		if err != nil || !res.Consistent {
			t.Fatalf("并发结束后 seq=%d 复现应一致: err=%v mismatches=%v", rec.Seq, err, res.Mismatches)
		}
	}
	t.Logf("并发复现自洽: %d 条 v1 记录在 5 次热更新后仍逐项一致", len(recs))
}

// ---- 复核结果中的拒绝归属必须彼此可区分 ----

func TestReplayDenyReasonsStayDistinct(t *testing.T) {
	gw, _ := newFixture(t)
	recs := collectV1Records(t, gw)

	seen := map[DenyReason]bool{}
	for _, rec := range recs {
		res, err := gw.Replay(rec)
		if err != nil {
			t.Fatalf("seq=%d 复现失败: %v", rec.Seq, err)
		}
		if res.Decision.Reason != rec.Decision.Reason {
			t.Fatalf("seq=%d 拒绝归属在复现后改变: %q -> %q",
				rec.Seq, rec.Decision.Reason, res.Decision.Reason)
		}
		seen[res.Decision.Reason] = true
		t.Logf("seq=%d 拒绝归属=%q (allowed=%t)", rec.Seq, res.Decision.Reason, res.Decision.Allowed)
	}
	// 一批记录中必须能一眼区分：操作不允许 / 级别不足 / 无规则覆盖 / 未知主体 / 资源不存在。
	for _, want := range []DenyReason{
		DenyActionDenied, DenyLevelInsufficient, DenyNoRuleMatch, DenyUnknownSubject, DenyResourceNotFound,
	} {
		if !seen[want] {
			t.Fatalf("复现结果中缺少拒绝归属 %q", want)
		}
	}

	// “当前没有任何可用策略”单独一类：无策略网关产生的记录也可复现且归属不混。
	emptyGW := New(NewCatalog(testSubjects()...), NewStore(nil), []byte("k"), nil)
	if _, d, err := emptyGW.AccessRecord(readReq("alice", "cust-1", LevelInternal), customerData()); err == nil ||
		d.Reason != DenyPolicyNotFound {
		t.Fatalf("无策略应 policy_not_found, got %q %v", d.Reason, err)
	}
	rec := emptyGW.Audit().Records()[0]
	res, err := emptyGW.Replay(rec)
	if err != nil {
		t.Fatalf("无策略记录复现失败: %v", err)
	}
	if res.Decision.Reason != DenyPolicyNotFound || !res.Consistent {
		t.Fatalf("无策略归属复现后必须保持, got %q consistent=%t", res.Decision.Reason, res.Consistent)
	}
	if DenyPolicyNotFound == DenyNoRuleMatch {
		t.Fatal("无可用策略与无规则覆盖必须是两类")
	}
	t.Logf("无可用策略记录复现: reason=%q consistent=%t", res.Decision.Reason, res.Consistent)
}
