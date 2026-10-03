package gateway

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Logger 为本地审计记录器：全部留存于内存，并在每次记录时向 out 输出一行
// 结构化日志（输入 + 判定依据），便于单测中直接观察。
// 全部方法并发安全。
type Logger struct {
	mu      sync.Mutex
	seq     int64
	records []AuditRecord
	out     io.Writer
}

// NewLogger 创建审计记录器；out 为 nil 时只做内存留存。
func NewLogger(out io.Writer) *Logger { return &Logger{out: out} }

// Log 记录一次包含输入与判定依据的审计结论，并返回落库记录。
// sub/known 为判定时解析到的主体快照，data 为当时参与字段处理的数据
// （均深拷贝留存），使事后仅凭该记录即可按当时版本完整复现。
func (l *Logger) Log(req AccessRequest, sub Subject, known bool, data map[string]any, d Decision, outputFields, droppedFields []string) AuditRecord {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	rec := AuditRecord{
		Seq:           l.seq,
		Time:          time.Now().UTC(),
		Request:       cloneRequest(req),
		Subject:       sub,
		SubjectKnown:  known,
		Data:          copyData(data),
		Decision:      d,
		OutputFields:  append([]string(nil), outputFields...),
		DroppedFields: append([]string(nil), droppedFields...),
	}
	l.records = append(l.records, rec)
	l.write(rec)
	return rec
}

// Records 返回全部审计记录的副本快照。
func (l *Logger) Records() []AuditRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]AuditRecord, len(l.records))
	copy(out, l.records)
	return out
}

// Len 返回已记录条数。
func (l *Logger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.records)
}

// write 打印输入与判定依据；判定依据包含命中规则、策略版本、拒绝原因。
func (l *Logger) write(r AuditRecord) {
	if l.out == nil {
		return
	}
	res := r.Request.Resource
	fmt.Fprintf(l.out,
		"[AUDIT] seq=%d time=%s\n"+
			"  INPUT    subject_id=%q action=%s resource=%q level=%d\n"+
			"  RESOURCE fields=%v\n"+
			"  DECISION allowed=%t reason=%q policy=%s rule=%q basis=[%s]\n"+
			"  OUTPUT   kept=%v dropped=%v\n",
		r.Seq, r.Time.Format(time.RFC3339Nano),
		r.Request.SubjectID, r.Request.Action, res.ID, res.Level,
		fieldLevelList(res.Fields),
		r.Decision.Allowed, string(r.Decision.Reason),
		r.Decision.PolicyVersion, r.Decision.PolicyID,
		strings.Join(r.Decision.MatchedRules, "; "),
		r.OutputFields, r.DroppedFields,
	)
}

func fieldLevelList(fields map[string]Level) []string {
	out := make([]string, 0, len(fields))
	for name, lv := range fields {
		out = append(out, fmt.Sprintf("%s:L%d", name, lv))
	}
	sort.Strings(out)
	return out
}

// cloneRequest 深拷贝请求中引用类型字段，避免调用方后续修改污染审计记录。
func cloneRequest(req AccessRequest) AccessRequest {
	cp := req
	if req.Resource.Fields != nil {
		fields := make(map[string]Level, len(req.Resource.Fields))
		for k, v := range req.Resource.Fields {
			fields[k] = v
		}
		cp.Resource.Fields = fields
	}
	return cp
}
