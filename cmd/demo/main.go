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
	p := &gateway.Policy{
		Version:      "1.0.0",
		MinSupported: "1.0.0",
		Rules: []gateway.Rule{
			{ID: "eng-read", Departments: []string{"engineering"}, Actions: []gateway.Action{gateway.ActionRead}, MinLevel: gateway.LevelInternal},
			{ID: "sales-read", Departments: []string{"sales"}, Actions: []gateway.Action{gateway.ActionRead}, MinLevel: gateway.LevelPublic},
		},
		FieldModes: map[gateway.Level]map[gateway.Action]gateway.FieldMode{
			gateway.LevelInternal:     {gateway.ActionRead: gateway.FieldMask},
			gateway.LevelConfidential: {gateway.ActionRead: gateway.FieldTokenize},
			gateway.LevelSecret:       {gateway.ActionRead: gateway.FieldDrop},
		},
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
	try("策略缺失(carol)", "carol", gateway.ActionRead)
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
}
