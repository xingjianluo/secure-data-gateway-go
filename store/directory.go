// Package store 用本地内存结构模拟主体目录、资源目录与数据源。
package store

import "sync"

import "github.com/xingjianluo/secure-data-gateway-go/model"

// Directory 主体与资源的本地目录（模拟外部数据源），并发安全。
type Directory struct {
	mu        sync.RWMutex
	subjects  map[string]model.Subject
	resources map[string]model.Resource
}

// NewDirectory 创建空目录。
func NewDirectory() *Directory {
	return &Directory{
		subjects:  map[string]model.Subject{},
		resources: map[string]model.Resource{},
	}
}

// AddSubject 注册主体；重复 ID 覆盖。属性切片做防御性拷贝。
func (d *Directory) AddSubject(s model.Subject) {
	s.Attributes = cloneAttrs(s.Attributes)
	s.Departments = append([]string(nil), s.Departments...)

	d.mu.Lock()
	defer d.mu.Unlock()
	d.subjects[s.ID] = s
}

// Subject 按 ID 查找主体；返回值为拷贝，调用方可安全使用。
func (d *Directory) Subject(id string) (model.Subject, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	s, ok := d.subjects[id]
	if !ok {
		return model.Subject{}, false
	}
	s.Attributes = cloneAttrs(s.Attributes)
	s.Departments = append([]string(nil), s.Departments...)
	return s, true
}

// AddResource 注册资源元数据；重复 ID 覆盖。
func (d *Directory) AddResource(r model.Resource) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resources[r.ID] = r
}

// Resource 按 ID 查找资源元数据。
func (d *Directory) Resource(id string) (model.Resource, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	r, ok := d.resources[id]
	return r, ok
}

func cloneAttrs(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
