// 本地策略版本复查命令：加载一段历史策略版本与一份审计记录导出，
// 按记录当时生效的版本（或指定版本）重新判定并逐项对账。
//
// 用法（在项目根目录）：
//
//	go run ./cmd/demo            # 先生成 audit-demo.json
//	go run ./cmd/replay -audit audit-demo.json \
//	  -policies gateway/testdata/policy-v1.json,gateway/testdata/policy-v2.json
//
// 可选：-version 2.0.0 统一指定复现版本；-seq 3 只复查某条记录。
// 全部一致时退出码 0；任何一条对不上或版本不可复现时退出码 1。
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/xingjianluo/secure-data-gateway-go/gateway"
)

func main() {
	auditPath := flag.String("audit", "", "审计记录 JSON 文件（由网关 SaveJSON 导出）")
	policyList := flag.String("policies", "", "逗号分隔的策略 JSON 文件列表（按版本自动排序发布）")
	version := flag.String("version", "", "统一指定复现版本；缺省用每条记录当时生效的版本")
	seq := flag.Int64("seq", 0, "只复查指定序号的记录；0 表示全部")
	flag.Parse()

	if *auditPath == "" || *policyList == "" {
		fmt.Fprintln(os.Stderr, "必须提供 -audit 与 -policies 参数")
		flag.Usage()
		os.Exit(2)
	}

	// 1) 按版本顺序把整段历史发布进 Store，形成与线上一致的版本沿革。
	policies, err := gateway.LoadPolicyFilesSorted(strings.Split(*policyList, ","))
	if err != nil {
		fmt.Fprintln(os.Stderr, "加载策略文件失败:", err)
		os.Exit(2)
	}
	store := gateway.NewStoreWithRetention(policies[0], len(policies))
	for _, p := range policies[1:] {
		if err := store.Update(p); err != nil {
			fmt.Fprintln(os.Stderr, "发布版本", p.Version, "失败:", err)
			os.Exit(2)
		}
	}
	fmt.Printf("已加载版本沿革: %s\n", strings.Join(store.Versions(), " -> "))

	// 2) 读取审计记录。复现判定输入全部来自记录本身，无需主体目录。
	f, err := os.Open(*auditPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "打开审计文件失败:", err)
		os.Exit(2)
	}
	defer f.Close()
	recs, err := gateway.LoadRecordsJSON(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "解析审计文件失败:", err)
		os.Exit(2)
	}
	if *seq != 0 {
		var picked []gateway.AuditRecord
		for _, r := range recs {
			if r.Seq == *seq {
				picked = append(picked, r)
			}
		}
		if len(picked) == 0 {
			fmt.Fprintln(os.Stderr, "未找到序号为", *seq, "的记录")
			os.Exit(2)
		}
		recs = picked
	}

	// 3) 批量复现对账：与线上共用同一套判定引擎与审计口径。
	gw := gateway.New(gateway.NewCatalog(), store, []byte("replay"), nil)
	results := gw.ReplayBatch(recs, *version)

	mismatch := 0
	for i, res := range results {
		status := "OK   "
		if !res.Match {
			status = "DIFF "
			mismatch++
		}
		fmt.Printf("%s seq=%d subject=%q action=%s version=%s -> allowed=%t reason=%q rule=%q basis=%v\n",
			status, res.Seq, recs[i].Request.SubjectID,
			recs[i].Request.Action, res.Version,
			res.Replayed.Allowed, string(res.Replayed.Reason),
			res.Replayed.PolicyID, res.Replayed.MatchedRules)
		for _, m := range res.Mismatches {
			fmt.Printf("       └─ %s\n", m)
		}
	}
	fmt.Printf("共 %d 条，一致 %d 条，不一致 %d 条\n", len(results), len(results)-mismatch, mismatch)
	if mismatch > 0 {
		os.Exit(1)
	}
}
