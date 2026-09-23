package gateway

import "sync"

// Record 为数据源中的一条记录：业务数据 + 字段敏感级别标注。
type Record struct {
	ID     string
	Data   map[string]any
	Levels map[string]Level
}

// DataSource 为本地内存数据源，模拟资源记录存储。并发安全。
type DataSource struct {
	mu      sync.RWMutex
	records map[string]Record
}

// NewDataSource 创建本地数据源。
func NewDataSource() *DataSource {
	return &DataSource{records: make(map[string]Record)}
}

// Put 写入一条记录（内部保存深拷贝）。
func (d *DataSource) Put(id string, data map[string]any, levels map[string]Level) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.records[id] = Record{
		ID:     id,
		Data:   copyData(data),
		Levels: copyLevels(levels),
	}
}

// Get 读取一条记录，返回深拷贝；不存在时 ok=false。
func (d *DataSource) Get(id string) (Record, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.records[id]
	if !ok {
		return Record{}, false
	}
	return Record{ID: r.ID, Data: copyData(r.Data), Levels: copyLevels(r.Levels)}, true
}

func copyData(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyLevels(in map[string]Level) map[string]Level {
	if in == nil {
		return nil
	}
	out := make(map[string]Level, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
