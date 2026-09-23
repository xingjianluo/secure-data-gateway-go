// Package audit 记录每次访问的输入、判定结论与判定依据，
// 支持按资源/主体回溯，并作为跨入口结论一致性的凭证。
package audit

import (
	"sync"
	"time"

	"github.com/xingjianluo/secure-data-gateway-go/model"
)

// Event 一条审计事件。
type Event struct {
	ID         int64
	Time       string // RFC3339
	SubjectID  string
	ResourceID string
	Action     model.Action
	Input      string // 输入摘要（主体属性、资源级别等）
	Decision   *model.Decision
	Redacted   []model.FieldOutcome
	Dropped    []string
}

// Log 内存审计日志，并发安全。
type Log struct {
	mu     sync.Mutex
	events []Event
}

// NewLog 创建空审计日志。
func NewLog() *Log { return &Log{} }

// Record 追加一条审计事件（对切片字段做防御性拷贝），返回写入后的副本。
func (l *Log) Record(e Event) Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	e.ID = int64(len(l.events)) + 1
	if e.Time == "" {
		e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.Decision != nil {
		dc := *e.Decision
		if e.Decision.Hits != nil {
			dc.Hits = append([]model.RuleHit(nil), e.Decision.Hits...)
		}
		e.Decision = &dc
	}
	if e.Redacted != nil {
		e.Redacted = append([]model.FieldOutcome(nil), e.Redacted...)
	}
	if e.Dropped != nil {
		e.Dropped = append([]string(nil), e.Dropped...)
	}
	l.events = append(l.events, e)
	return e
}

// All 返回全部审计事件的副本。
func (l *Log) All() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out
}

// ByResource 返回指定资源的审计事件。
func (l *Log) ByResource(resourceID string) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, e := range l.events {
		if e.ResourceID == resourceID {
			out = append(out, e)
		}
	}
	return out
}
