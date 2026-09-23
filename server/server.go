// Package server 提供网关的 HTTP 入口，与直接调用 Gateway 的
// SDK 入口共享同一套判定/脱敏/审计逻辑，结论完全一致。
package server

import (
	"encoding/json"
	"net/http"

	"github.com/xingjianluo/secure-data-gateway-go/gateway"
	"github.com/xingjianluo/secure-data-gateway-go/model"
)

// Handler HTTP 处理器集合。
type Handler struct {
	gw *gateway.Gateway
}

// New 创建 HTTP Handler。
func New(gw *gateway.Gateway) *Handler { return &Handler{gw: gw} }

// Routes 注册路由：
//
//	GET  /data     数据访问（subject_id, resource_id, action）
//	POST /policies 热更新策略（body 为 model.Policy JSON）
//	GET  /policies 列出已保存策略版本
//	GET  /audit    查询全部审计事件
//	POST /replay   按指定策略版本复现判定
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /data", h.handleData)
	mux.HandleFunc("POST /policies", h.handleLoadPolicy)
	mux.HandleFunc("GET /policies", h.handleListPolicies)
	mux.HandleFunc("GET /audit", h.handleAudit)
	mux.HandleFunc("POST /replay", h.handleReplay)
	return mux
}

// statusFor 把可区分的拒绝原因映射到合适的 HTTP 状态码。
func statusFor(reason model.DenyReason) int {
	switch reason {
	case model.DenyUnknownSubject:
		return http.StatusForbidden
	case model.DenyResourceNotFound:
		return http.StatusNotFound
	case model.DenyPolicyNotFound:
		return http.StatusServiceUnavailable
	case model.DenyNoPermission:
		return http.StatusForbidden
	default:
		return http.StatusOK
	}
}

func (h *Handler) handleData(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	result, _ := h.gw.Access(q.Get("subject_id"), q.Get("resource_id"),
		model.Action(q.Get("action")))

	resp := map[string]any{
		"allowed":        result.Decision.Allowed,
		"reason":         string(result.Decision.Reason),
		"message":        result.Decision.Message,
		"policy_version": result.Decision.PolicyVersion,
		"hits":           result.Decision.Hits,
		"default_used":   result.Decision.DefaultUsed,
		"dropped_fields": result.DroppedFields,
	}
	if result.Decision.Allowed {
		resp["data"] = result.Data
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusFor(result.Decision.Reason))
	_ = json.NewEncoder(w).Encode(resp)
}

type loadPolicyRequest struct {
	Policy model.Policy `json:"policy"`
}

func (h *Handler) handleLoadPolicy(w http.ResponseWriter, r *http.Request) {
	var req loadPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := h.gw.Policies().Load(&req.Policy); err != nil {
		// 加载被拒绝：原有策略保持可用。
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"loaded": true, "version": req.Policy.Version})
}

func (h *Handler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"versions": h.gw.Policies().Versions()})
}

func (h *Handler) handleAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": h.gw.Audit().All()})
}

type replayRequest struct {
	SubjectID     string       `json:"subject_id"`
	ResourceID    string       `json:"resource_id"`
	Action        model.Action `json:"action"`
	PolicyVersion int64        `json:"policy_version"`
}

func (h *Handler) handleReplay(w http.ResponseWriter, r *http.Request) {
	var req replayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	dec, err := h.gw.Replay(req.SubjectID, req.ResourceID, req.Action, req.PolicyVersion)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	status := http.StatusOK
	if !dec.Allowed {
		status = statusFor(dec.Reason)
	}
	writeJSON(w, status, dec)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
