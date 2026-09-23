package server_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/xingjianluo/secure-data-gateway-go/audit"
	"github.com/xingjianluo/secure-data-gateway-go/authz"
	"github.com/xingjianluo/secure-data-gateway-go/gateway"
	"github.com/xingjianluo/secure-data-gateway-go/mask"
	"github.com/xingjianluo/secure-data-gateway-go/model"
	"github.com/xingjianluo/secure-data-gateway-go/policy"
	"github.com/xingjianluo/secure-data-gateway-go/server"
	"github.com/xingjianluo/secure-data-gateway-go/store"
)

func newSrv(t *testing.T) (*httptest.Server, *policy.Store) {
	t.Helper()
	dir := store.NewDirectory()
	data := store.NewDataSource()
	pols := policy.NewStore()
	dir.AddSubject(model.Subject{ID: "u1", Clearance: model.SensInternal,
		Attributes: map[string]string{"role": "member"}, Departments: []string{"eng"}})
	dir.AddResource(model.Resource{ID: "doc", Sensitivity: model.SensInternal})
	data.Put("doc", map[string]any{"title": "hello"})
	_ = pols.Load(&model.Policy{
		SchemaVersion: "1.0.0", Version: 1, DefaultEffect: "deny",
		Rules: []model.Rule{{Name: "read", Effect: "allow", Actions: []model.Action{model.ActionRead},
			MinLevel: model.SensInternal, MaxLevel: model.SensInternal}},
	})
	gw := gateway.New(dir, data, pols, authz.New(dir), mask.New(), audit.NewLog())
	return httptest.NewServer(server.New(gw).Routes()), pols
}

// TestHTTPLoadRejectsIncompatible 不兼容策略经 HTTP 被拒（400），旧版本仍可服务。
func TestHTTPLoadRejectsIncompatible(t *testing.T) {
	srv, pols := newSrv(t)
	defer srv.Close()

	body := `{"policy":{"schema_version":"2.0.0","version":2,"default_effect":"deny",` +
		`"rules":[{"name":"r","effect":"allow","actions":["read"]}]}}`
	resp, err := http.Post(srv.URL+"/policies", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for incompatible schema, got %d", resp.StatusCode)
	}
	if cur, _ := pols.Current(); cur.Version != 1 {
		t.Fatalf("v1 must remain active, got %d", cur.Version)
	}
	t.Logf("input schema=2.0.0 rejected over HTTP, policy stays on v1")
}

// TestHTTPReplay 经 HTTP 按历史版本复现判定。
func TestHTTPReplay(t *testing.T) {
	srv, pols := newSrv(t)
	defer srv.Close()

	_ = pols.Load(&model.Policy{
		SchemaVersion: "1.1.0", Version: 2, DefaultEffect: "deny",
		Rules: []model.Rule{{Name: "read-all", Effect: "allow", Actions: []model.Action{model.ActionRead},
			MinLevel: model.SensPublic}},
	})

	body := `{"subject_id":"u1","resource_id":"doc","action":"read","policy_version":1}`
	resp, err := http.Post(srv.URL+"/replay", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var d model.Decision
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatal(err)
	}
	if !d.Allowed || d.PolicyVersion != 1 || len(d.Hits) != 1 {
		t.Fatalf("replay v1 mismatch: %+v", d)
	}
	t.Logf("replayed v1 over HTTP: allowed=%v basis=%+v", d.Allowed, d.Hits)

	// 查询审计事件端点存在且返回数组。
	ar, err := http.Get(srv.URL + "/audit")
	if err != nil {
		t.Fatal(err)
	}
	defer ar.Body.Close()
	var auditBody struct {
		Events []audit.Event `json:"events"`
	}
	if err := json.NewDecoder(ar.Body).Decode(&auditBody); err != nil {
		t.Fatal(err)
	}
	t.Logf("audit endpoint returned %d events", len(auditBody.Events))
}

// TestHTTPLoadValidSnakeCase 蛇形命名的合法策略可经 HTTP 加载并立即生效。
func TestHTTPLoadValidSnakeCase(t *testing.T) {
	srv, _ := newSrv(t)
	defer srv.Close()

	body := `{"policy":{"schema_version":"1.1.0","version":2,"default_effect":"deny",
"rules":[{"name":"read-all","effect":"allow","actions":["read"],"min_level":0}]}}`
	resp, err := http.Post(srv.URL+"/policies", "application/json", bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	vers, err := http.Get(srv.URL + "/policies")
	if err != nil {
		t.Fatal(err)
	}
	defer vers.Body.Close()
	var v struct {
		Versions []int64 `json:"versions"`
	}
	if err := json.NewDecoder(vers.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if len(v.Versions) != 2 || v.Versions[1] != 2 {
		t.Fatalf("versions after valid load = %v", v.Versions)
	}
	t.Logf("valid snake_case policy loaded; versions=%v", v.Versions)
}
