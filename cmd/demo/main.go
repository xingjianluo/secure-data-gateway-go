// 本地数据访问网关演示：同一套判定-脱敏-审计路径覆盖不同入口，
// 并演示策略热更新前后结论变化。运行：go run ./cmd/demo
package main

import (
	"fmt"
	"os"

	"github.com/xingjianluo/secure-data-gateway-go/gateway"
)

func main() {
	cat := gateway.NewCatalog(
		gateway.Subject{ID: "alice", Department: "engineering", Role: "engineer", Clearance: gateway.LevelConfidential},
		gateway.Subject{ID: "bob", Department: "sales", Role: "rep", Clearance: gateway.LevelInternal},
		gateway.Subject{ID: "carol", Department: "legal", Role: "counsel", Clearance: gateway.LevelConfidential},
	)
	p, err := gateway.LoadPolicyFile("gateway/testdata/policy-v1.json")
	if err != nil {
		fmt.Println("加载初始策略失败:", err)
		os.Exit(1)
	}
	gw := gateway.New(cat, gateway.NewStore(p), []byte("demo-token-secret"), os.Stdout)
	ds := gateway.NewDataSource()
	levels := map[string]gateway.Level{
		"name": gateway.LevelPublic, "phone": gateway.LevelInternal,
		"email": gateway.LevelConfidential, "ssn": gateway.LevelSecret,
	}
	data := map[string]any{"name": "Alice Wang", "phone": "13812345678",
		"email": "alice@example.com", "ssn": "110101199001011234"}
	ds.Put("cust-1", data, levels)
	gw.UseDataSource(ds)

	try := func(label, subject string, act gateway.Action) {
		fmt.Printf("\n===== %s =====\n", label)
		req := gateway.AccessRequest{
			SubjectID: subject, Action: act,
			Resource: gateway.Resource{ID: "cust-1", Level: gateway.LevelInternal, Fields: levels},
		}
		out, d, err := gw.Access(req)
		fmt.Printf("结果: err=%v output=%v\n", err, out)
		if err == nil {
			fmt.Printf("判定: version=%s rule=%s\n", d.PolicyVersion, d.PolicyID)
		}
	}

	try("正常访问(alice读, 脱敏+令牌化+剔除)", "alice", gateway.ActionRead)
	try("操作越权(alice写)", "alice", gateway.ActionWrite)
	try("无规则覆盖(carol, 有策略但无规则匹配其部门)", "carol", gateway.ActionRead)
	try("未知主体(ghost)", "ghost", gateway.ActionRead)

	fmt.Println("\n===== 在 v1 上尝试加载不兼容的 v3（min_supported=2.0.0，应拒绝并保持原状） =====")
	if err := gw.ReloadPolicy("gateway/testdata/policy-incompatible.json"); err != nil {
		fmt.Println("已拒绝，原策略继续可用:", err)
	}
	if v := gw.PolicyStore().Snapshot().Version; v != "1.0.0" {
		fmt.Println("异常：在用版本被改变为", v)
	}

	fmt.Println("\n===== 热更新到 testdata/policy-v2.json（新增 legal-read） =====")
	if err := gw.ReloadPolicy("gateway/testdata/policy-v2.json"); err != nil {
		fmt.Println("热更新被拒绝:", err)
	} else {
		try("热更新后 carol 再读", "carol", gateway.ActionRead)
	}

	fmt.Printf("\n审计记录总数: %d\n", gw.Audit().Len())

	// 导出审计记录，供 cmd/replay 按版本复查对账。
	const auditPath = "audit-demo.json"
	f, err := os.Create(auditPath)
	if err != nil {
		fmt.Println("导出审计记录失败:", err)
		return
	}
	defer f.Close()
	if err := gw.Audit().SaveJSON(f); err != nil {
		fmt.Println("导出审计记录失败:", err)
		return
	}
	fmt.Printf("审计记录已导出: %s（复查: go run ./cmd/replay -audit %s "+
		"-policies gateway/testdata/policy-v1.json,gateway/testdata/policy-v2.json）\n",
		auditPath, auditPath)
}
