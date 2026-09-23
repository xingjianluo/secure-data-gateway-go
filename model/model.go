// Package model 定义数据访问网关的核心领域模型：
// 主体、资源、策略规则、判定结论与脱敏记录。
package model

import "time"

// Action 表示对资源的操作类型。
type Action string

const (
	ActionRead   Action = "read"
	ActionWrite  Action = "write"
	ActionDelete Action = "delete"
)

// SensLevel 表示敏感级别，数值越大越敏感。
type SensLevel int

const (
	SensPublic       SensLevel = 0 // 公开
	SensInternal     SensLevel = 1 // 内部
	SensConfidential SensLevel = 2 // 机密
	SensRestricted   SensLevel = 3 // 受限（最高）
)

// String 返回敏感级别的可读名称。
func (l SensLevel) String() string {
	switch l {
	case SensPublic:
		return "public"
	case SensInternal:
		return "internal"
	case SensConfidential:
		return "confidential"
	case SensRestricted:
		return "restricted"
	default:
		return "unknown"
	}
}

// Subject 访问主体及其属性。
type Subject struct {
	ID          string            `json:"id"`
	Attributes  map[string]string `json:"attributes"`
	Clearance   SensLevel         `json:"clearance"`
	Departments []string          `json:"departments"`
}

// FieldSpec 描述单个字段的敏感级别与处理方式。
type FieldSpec struct {
	Name       string     `json:"name"`
	Level      SensLevel  `json:"level"`
	RedactMode RedactMode `json:"redact_mode"`
}

// RedactMode 字段呈现方式。
type RedactMode string

const (
	RedactNone  RedactMode = "none"  // 原值返回
	RedactMask  RedactMode = "mask"  // 掩码（外观遮蔽，非加密）
	RedactToken RedactMode = "token" // 不可逆令牌化
	RedactDrop  RedactMode = "drop"  // 标记：无权访问时整体剔除
)

// Resource 受保护资源的元数据。
type Resource struct {
	ID          string      `json:"id"`
	OwnerID     string      `json:"owner_id"`
	Sensitivity SensLevel   `json:"sensitivity"`
	Fields      []FieldSpec `json:"fields"`
}

// Rule 一条授权规则：首个全部匹配的规则生效。
type Rule struct {
	Name        string            `json:"name"`
	Effect      string            `json:"effect"` // "allow" 或 "deny"
	Actions     []Action          `json:"actions"`
	MinLevel    SensLevel         `json:"min_level"` // 主体 Clearance 需 >= MinLevel
	MaxLevel    SensLevel         `json:"max_level"` // 资源 Sensitivity 需 <= MaxLevel（0 表示不限）
	Subject     map[string]string `json:"subject_attrs"`
	Departments []string          `json:"departments"`
	OwnersOnly  bool              `json:"owners_only"`
}

// Policy 一个版本的完整策略快照。
type Policy struct {
	SchemaVersion string    `json:"schema_version"` // 语义化版本，如 "1.0.0"
	Version       int64     `json:"version"`        // 单调递增的策略版本号
	CreatedAt     time.Time `json:"created_at"`
	// TokenSecret 为令牌化派生密钥；空则使用引擎内置默认值。
	TokenSecret string `json:"token_secret"`
	Rules       []Rule `json:"rules"`
	// DefaultEffect 无规则匹配时的效果，固定应为 "deny"。
	DefaultEffect string `json:"default_effect"`
}

// RuleHit 记录命中/评估过的规则，用于可追溯的判定依据。
type RuleHit struct {
	RuleName string   `json:"rule"`
	Matched  bool     `json:"matched"`
	Reasons  []string `json:"reasons,omitempty"` // 未命中时逐条列出不满足的条件
	Effect   string   `json:"effect"`
}

// DenyReason 拒绝原因的可区分枚举。
type DenyReason string

const (
	DenyNone             DenyReason = ""
	DenyUnknownSubject   DenyReason = "unknown_subject"
	DenyResourceNotFound DenyReason = "resource_not_found"
	DenyPolicyNotFound   DenyReason = "policy_not_found"
	DenyNoPermission     DenyReason = "no_permission"
)

// Decision 一次授权判定的完整结论。
type Decision struct {
	Allowed       bool       `json:"allowed"`
	Reason        DenyReason `json:"reason"`
	Message       string     `json:"message"`
	SubjectID     string     `json:"subject_id"`
	ResourceID    string     `json:"resource_id"`
	Action        Action     `json:"action"`
	PolicyVersion int64      `json:"policy_version"`
	Hits          []RuleHit  `json:"hits,omitempty"`
	DefaultUsed   bool       `json:"default_used"`
	EvaluatedAt   time.Time  `json:"evaluated_at"`
}

// FieldOutcome 单个字段的输出处理结果。
type FieldOutcome struct {
	Field  string     `json:"field"`
	Level  SensLevel  `json:"level"`
	Kept   bool       `json:"kept"`
	Mode   RedactMode `json:"mode"`
	Output any        `json:"output,omitempty"`
}

// AccessResult 网关一次访问的最终结果。
type AccessResult struct {
	Decision      *Decision      `json:"decision"`
	Data          map[string]any `json:"data,omitempty"`
	FieldOutcomes []FieldOutcome `json:"field_outcomes,omitempty"`
	DroppedFields []string       `json:"dropped_fields,omitempty"`
}
