// Package gateway 实现本地数据访问网关的核心能力：
// 基于属性的访问判定（ABAC）、字段级脱敏/令牌化、策略热更新与审计留痕。
package gateway

import "time"

// Action 表示主体对资源尝试执行的操作类型。
type Action string

const (
	ActionRead   Action = "read"
	ActionWrite  Action = "write"
	ActionDelete Action = "delete"
)

// Level 表示资源/字段的敏感级别，数值越高越敏感。
type Level int

const (
	LevelPublic Level = iota
	LevelInternal
	LevelConfidential
	LevelSecret
)

// FieldMode 表示字段在通过授权后的数据处理方式。
type FieldMode string

const (
	// FieldKeep 原样保留。
	FieldKeep FieldMode = "keep"
	// FieldMask 部分遮蔽（可逆读语义，保留部分明文，如手机号中间四位打码）。
	FieldMask FieldMode = "mask"
	// FieldTokenize 不可逆令牌化（确定性 HMAC，重复与并发访问输出一致）。
	FieldTokenize FieldMode = "tokenize"
	// FieldDrop 无权访问的字段整体剔除，不返回空值或占位符。
	FieldDrop FieldMode = "drop"
)

// Subject 为访问主体及其属性。
type Subject struct {
	ID         string
	Department string
	Role       string
	Clearance  Level // 主体持有的敏感级别上限
}

// Resource 为被访问的资源描述。
type Resource struct {
	ID     string
	Owner  string
	Level  Level
	Fields map[string]Level // 字段名 -> 字段敏感级别
}

// AccessRequest 是一次访问请求的完整输入。
type AccessRequest struct {
	SubjectID string
	Action    Action
	Resource  Resource
}

// DenyReason 区分不同的拒绝原因，禁止静默放行或统一归类。
type DenyReason string

const (
	DenyNone              DenyReason = ""                   // 允许
	DenyUnknownSubject    DenyReason = "unknown_subject"    // 未知主体
	DenyResourceNotFound  DenyReason = "resource_not_found" // 资源不存在
	DenyPolicyNotFound    DenyReason = "policy_not_found"   // 当前没有任何可用策略
	DenyNoRuleMatch       DenyReason = "no_rule_match"      // 主体存在但没有任何规则覆盖
	DenyLevelInsufficient DenyReason = "level_insufficient" // 主体敏感级别不足
	DenyActionDenied      DenyReason = "action_denied"      // 操作类型被策略拒绝
)

// Decision 为授权判定结论及其依据。
type Decision struct {
	Allowed       bool
	Reason        DenyReason
	PolicyVersion string   // 作出判定所用的策略版本（保证历史结论可复现）
	PolicyID      string   // 命中的策略 ID
	MatchedRules  []string // 参与判定的规则描述（判定依据）
	EvaluatedAt   time.Time
}

// Rule 为单条授权规则：主体属性匹配 + 操作集合 + 所需敏感级别。
type Rule struct {
	ID          string
	Departments []string // 为空表示不限部门
	Roles       []string // 为空表示不限角色
	Actions     []Action // 允许的操作；为空表示全部允许
	MinLevel    Level    // 访问该资源所需的最低主体级别
	Description string
}

// Policy 为一个不可变版本的策略集合。
type Policy struct {
	Version      string
	MinSupported string // 语义化兼容下界（加载新版本时校验）
	Rules        []Rule
	// FieldModes: 字段级别 -> 操作 -> 处理模式（缺省 keep，无权字段 drop）。
	FieldModes map[Level]map[Action]FieldMode
}

// PolicySet 为策略存储中的一个完整快照（原子替换单位）。
type PolicySet struct {
	Policy *Policy
}

// AuditRecord 为一条可复现的审计记录，包含输入与判定依据。
// Data 留存当时参与字段处理的数据快照（深拷贝），
// 使事后仅凭该记录即可按当时版本完整复现判定与字段处理。
type AuditRecord struct {
	Seq           int64
	Time          time.Time
	Request       AccessRequest
	Subject       Subject        // 判定时解析到的主体快照（复现不依赖目录后续变更）
	SubjectKnown  bool           // 主体当时是否存在于目录中
	Data          map[string]any // 当时的数据快照（深拷贝，只读）
	Decision      Decision
	OutputFields  []string // 实际返回的字段
	DroppedFields []string // 被整体剔除的字段
}

// ReplayResult 为一次按版本复现的结论：
// 复现出的判定/字段处理结果，以及与原始审计记录的逐项比对。
type ReplayResult struct {
	Seq        int64          // 原始审计记录序号
	Version    string         // 实际用于复现的策略版本
	Decision   Decision       // 复现判定结论
	Output     map[string]any // 复现后的字段投影输出
	KeptFields []string       // 复现保留字段（字典序）
	Dropped    []string       // 复现剔除字段（字典序）
	Consistent bool           // 是否与原始记录逐项一致
	Mismatches []string       // 不一致项说明（为空即一致）
	Err        error          // 复现本身失败（如版本已淘汰）；非空时其余字段无效
}
