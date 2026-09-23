// Command demo 启动一个内置演示数据的本地数据访问网关。
package main

import (
	"log"
	"net/http"
	"time"

	"github.com/xingjianluo/secure-data-gateway-go/audit"
	"github.com/xingjianluo/secure-data-gateway-go/authz"
	"github.com/xingjianluo/secure-data-gateway-go/gateway"
	"github.com/xingjianluo/secure-data-gateway-go/mask"
	"github.com/xingjianluo/secure-data-gateway-go/model"
	"github.com/xingjianluo/secure-data-gateway-go/policy"
	"github.com/xingjianluo/secure-data-gateway-go/server"
	"github.com/xingjianluo/secure-data-gateway-go/store"
)

func main() {
	dir := store.NewDirectory()
	data := store.NewDataSource()
	pols := policy.NewStore()
	gw := gateway.New(dir, data, pols, authz.New(dir), mask.New(), audit.NewLog())

	seed(dir, data, pols)

	addr := ":8080"
	log.Printf("secure-data-gateway listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, server.New(gw).Routes()))
}

func seed(dir *store.Directory, data *store.DataSource, pols *policy.Store) {
	// 主体：实习生(internal)、工程师(confidential)、安全员(restricted)。
	dir.AddSubject(model.Subject{
		ID: "u-intern", Clearance: model.SensInternal,
		Attributes:  map[string]string{"role": "intern"},
		Departments: []string{"engineering"},
	})
	dir.AddSubject(model.Subject{
		ID: "u-eng", Clearance: model.SensConfidential,
		Attributes:  map[string]string{"role": "engineer"},
		Departments: []string{"engineering"},
	})
	dir.AddSubject(model.Subject{
		ID: "u-sec", Clearance: model.SensRestricted,
		Attributes:  map[string]string{"role": "security"},
		Departments: []string{"security"},
	})

	// 资源：员工档案（机密），含不同敏感级别的字段。
	dir.AddResource(model.Resource{
		ID: "emp-1", OwnerID: "u-eng", Sensitivity: model.SensConfidential,
		Fields: []model.FieldSpec{
			{Name: "name", Level: model.SensPublic, RedactMode: model.RedactNone},
			{Name: "email", Level: model.SensInternal, RedactMode: model.RedactMask},
			{Name: "salary", Level: model.SensRestricted, RedactMode: model.RedactNone},
			{Name: "ssn", Level: model.SensConfidential, RedactMode: model.RedactToken},
		},
	})
	data.Put("emp-1", map[string]any{
		"name": "Alice", "email": "alice@example.com",
		"salary": 200000, "ssn": "123-45-6789",
	})

	// 策略 v1。
	pols.Load(&model.Policy{
		SchemaVersion: "1.0.0", Version: 1, CreatedAt: time.Now().UTC(),
		TokenSecret:   "demo-secret-v1",
		DefaultEffect: "deny",
		Rules: []model.Rule{
			{Name: "security-read-all", Effect: "allow", Actions: []model.Action{model.ActionRead},
				MinLevel: model.SensRestricted, Subject: map[string]string{"role": "security"}},
			{Name: "eng-read-confidential", Effect: "allow", Actions: []model.Action{model.ActionRead},
				MinLevel: model.SensConfidential, MaxLevel: model.SensConfidential,
				Departments: []string{"engineering"}},
			{Name: "intern-read-public", Effect: "allow", Actions: []model.Action{model.ActionRead},
				MinLevel: model.SensInternal, MaxLevel: model.SensInternal,
				Subject: map[string]string{"role": "intern"}},
		},
	})
}
