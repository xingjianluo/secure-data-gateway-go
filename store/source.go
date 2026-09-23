package store

import "sync"

// DataSource 保存资源原始记录（字段明文），模拟业务数据库，并发安全。
type DataSource struct {
	mu      sync.RWMutex
	records map[string]map[string]any
}

// NewDataSource 创建空数据源。
func NewDataSource() *DataSource {
	return &DataSource{records: map[string]map[string]any{}}
}

// Put 写入/覆盖一条资源记录（做防御性拷贝）。
func (ds *DataSource) Put(resourceID string, record map[string]any) {
	cp := make(map[string]any, len(record))
	for k, v := range record {
		cp[k] = v
	}
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.records[resourceID] = cp
}

// Get 读取一条资源原始记录（返回拷贝，脱敏过程不影响库内明文）。
func (ds *DataSource) Get(resourceID string) (map[string]any, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	rec, ok := ds.records[resourceID]
	if !ok {
		return nil, false
	}
	cp := make(map[string]any, len(rec))
	for k, v := range rec {
		cp[k] = v
	}
	return cp, true
}
