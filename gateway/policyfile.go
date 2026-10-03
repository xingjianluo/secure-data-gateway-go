package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ruleDTO / policyDTO 为本地 JSON 策略文件的传输结构。
// 使用字符串枚举以保持文件可读，字段缺失即旧版定义，加载时按缺省容忍。
type ruleDTO struct {
	ID          string   `json:"id"`
	Departments []string `json:"departments"`
	Roles       []string `json:"roles"`
	Actions     []string `json:"actions"`
	MinLevel    int      `json:"min_level"`
	Description string   `json:"description"`
}

type policyDTO struct {
	Version      string                       `json:"version"`
	MinSupported string                       `json:"min_supported"`
	Rules        []ruleDTO                    `json:"rules"`
	FieldModes   map[string]map[string]string `json:"field_modes"`
}

// LoadPolicyFile 从本地 JSON 文件读取并解析为 *Policy（不发布到 Store；
// 发布由 Store.Update 做兼容校验与原子替换，从而加载失败不影响在用策略）。
func LoadPolicyFile(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %q: %w", path, err)
	}
	var dto policyDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		return nil, fmt.Errorf("parse policy file %q: %w", path, err)
	}

	p := &Policy{
		Version:      dto.Version,
		MinSupported: dto.MinSupported,
		FieldModes:   make(map[Level]map[Action]FieldMode, len(dto.FieldModes)),
	}
	for _, r := range dto.Rules {
		acts, err := parseActions(r.Actions)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.ID, err)
		}
		p.Rules = append(p.Rules, Rule{
			ID:          r.ID,
			Departments: r.Departments,
			Roles:       r.Roles,
			Actions:     acts,
			MinLevel:    Level(r.MinLevel),
			Description: r.Description,
		})
	}
	for lvlKey, byAction := range dto.FieldModes {
		lvl, err := parseLevelKey(lvlKey)
		if err != nil {
			return nil, fmt.Errorf("field_modes: %w", err)
		}
		m := make(map[Action]FieldMode, len(byAction))
		for actKey, modeStr := range byAction {
			act := Action(actKey)
			if !validAction(act) {
				return nil, fmt.Errorf("field_modes[%s]: unknown action %q", lvlKey, actKey)
			}
			mode := FieldMode(modeStr)
			if !validMode(mode) {
				return nil, fmt.Errorf("field_modes[%s][%s]: unknown mode %q", lvlKey, actKey, modeStr)
			}
			m[act] = mode
		}
		p.FieldModes[lvl] = m
	}
	return p, nil
}

func parseActions(in []string) ([]Action, error) {
	out := make([]Action, 0, len(in))
	for _, a := range in {
		act := Action(a)
		if !validAction(act) {
			return nil, fmt.Errorf("unknown action %q", a)
		}
		out = append(out, act)
	}
	return out, nil
}

func validAction(a Action) bool {
	switch a {
	case ActionRead, ActionWrite, ActionDelete:
		return true
	}
	return false
}

func validMode(m FieldMode) bool {
	switch m {
	case FieldKeep, FieldMask, FieldTokenize, FieldDrop:
		return true
	}
	return false
}

// parseLevelKey 接受 "0".."3" 形式的级别键。
func parseLevelKey(s string) (Level, error) {
	n := 0
	if s == "" {
		return 0, fmt.Errorf("empty level key")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-numeric level key %q", s)
		}
		n = n*10 + int(c-'0')
	}
	if n > int(LevelSecret) {
		return 0, fmt.Errorf("level key %q out of range", s)
	}
	return Level(n), nil
}

// LoadPolicyFilesSorted 加载多个本地策略文件并按版本号由旧到新排序返回，
// 供命令行工具把一整段历史版本依次发布进 Store 以复现历史判定。
func LoadPolicyFilesSorted(paths []string) ([]*Policy, error) {
	policies := make([]*Policy, 0, len(paths))
	for _, path := range paths {
		p, err := LoadPolicyFile(path)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	sort.Slice(policies, func(i, j int) bool {
		vi, errI := parseSemver(policies[i].Version)
		vj, errJ := parseSemver(policies[j].Version)
		if errI != nil || errJ != nil {
			return policies[i].Version < policies[j].Version
		}
		return cmpSemver(vi, vj) < 0
	})
	return policies, nil
}
