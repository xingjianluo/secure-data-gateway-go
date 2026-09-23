package gateway

import "fmt"

// Catalog 为本地内存主体目录，模拟主体属性数据源。
type Catalog struct {
	subjects map[string]Subject
}

// NewCatalog 创建主体目录并登记给定主体。
func NewCatalog(subjects ...Subject) *Catalog {
	m := make(map[string]Subject, len(subjects))
	for _, s := range subjects {
		m[s.ID] = s
	}
	return &Catalog{subjects: m}
}

// Get 按 ID 查询主体；不存在时 ok=false（对应“未知主体”拒绝）。
func (c *Catalog) Get(id string) (sub Subject, ok bool) {
	s, found := c.subjects[id]
	return s, found
}

// String 便于日志打印主体输入。
func (s Subject) String() string {
	return fmt.Sprintf("Subject{id=%q dept=%q role=%q clearance=%d}",
		s.ID, s.Department, s.Role, s.Clearance)
}
