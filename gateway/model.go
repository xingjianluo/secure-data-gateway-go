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
// 各类归属两两互斥、可区分，且与入口、是否按版本复核无关：
// 同一输入同一版本，从任何入口或复核路径得到的归属必须一致。
type DenyReason string

const (
	DenyNone           DenyReason = ""                // 允许
	DenyUnknownSubject DenyReason = "unknown_subject" // 主体目录中不存在该主体
	// DenyPolicyNotFound 表示判定时系统里根本没有可用策略
	// （未加载任何策略，或策略内没有任何规则）。
	// 与“有策略但主体未被任何规则覆盖”严格区分。
	DenyPolicyNotFound DenyReason = "policy_not_found"
	// DenyNoMatchingRule 表示系统有可用策略，但没有任何规则的
	// 主体约束（部门/角色）覆盖到该主体。
	DenyNoMatchingRule DenyReason = "no_matching_rule"
	// DenyResourceMissing 表示被访问的资源本身不存在。
	// 属于数据归属问题，与策略无关，不得混入任何策略类归属。
	DenyResourceMissing   DenyReason = "resource_missing"
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
// Subject 快照使复现不依赖当前主体目录状态：记录即全部判定输入。
type AuditRecord struct {
	Seq           int64
	Time          time.Time
	Request       AccessRequest
	Subject       Subject // 判定时使用的主体属性快照
	SubjectKnown  bool    // false 表示未知主体（Subject 为零值）
	Decision      Decision
	OutputFields  []string // 实际返回的字段
	DroppedFields []string // 被整体剔除的字段
}
