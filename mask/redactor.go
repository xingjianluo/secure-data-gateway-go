// Package mask 按字段敏感级别执行剔除、掩码与不可逆令牌化。
// 令牌化采用"策略密钥 + 主体 + 字段 + 值"的确定性 HMAC-SHA256，
// 保证同一主体重复/并发访问结果一致，且重载状态后仍一致、不可还原。
package mask

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/xingjianluo/secure-data-gateway-go/model"
)

// defaultSecret 在策略未配置 TokenSecret 时使用的内置固定密钥。
// 固定而非随机生成，正是为了进程重启/状态重载后令牌保持稳定可复现。
const defaultSecret = "secure-data-gateway:default-token-secret:v1"

// Redactor 字段脱敏器。无内部可变状态，可被任意并发调用。
type Redactor struct{}

// New 创建脱敏器。
func New() *Redactor { return &Redactor{} }

// Apply 按资源字段规格与主体可见级别处理记录：
//   - 字段敏感级别 > 主体 Clearance：整体剔除，输出 map 中不存在该键；
//   - 级别可见但 RedactMode=mask：掩码呈现；
//   - RedactMode=token：输出确定性不可逆令牌；
//   - RedactMode=none：原值返回。
//
// 资源规格中未声明的记录字段按 public 级别原值返回。
// 该函数不修改输入 record，且无内部状态，重复与并发调用结果一致。
func (r *Redactor) Apply(record map[string]any, res model.Resource, sub model.Subject, p *model.Policy) (map[string]any, []model.FieldOutcome, []string) {
	secret := p.TokenSecret
	if secret == "" {
		secret = defaultSecret
	}

	specs := make(map[string]model.FieldSpec, len(res.Fields))
	for _, f := range res.Fields {
		specs[f.Name] = f
	}

	out := make(map[string]any, len(record))
	outcomes := make([]model.FieldOutcome, 0, len(record))
	dropped := make([]string, 0)

	// 先按资源字段规格处理已声明字段（保持规格顺序，结论稳定可复现）。
	declared := make(map[string]bool, len(res.Fields))
	for _, f := range res.Fields {
		value, present := record[f.Name]
		if !present {
			continue
		}
		declared[f.Name] = true
		oc := model.FieldOutcome{Field: f.Name, Level: f.Level}

		if f.Level > sub.Clearance {
			oc.Kept = false
			oc.Mode = model.RedactDrop
			dropped = append(dropped, f.Name)
			outcomes = append(outcomes, oc)
			continue
		}

		oc.Kept = true
		switch f.RedactMode {
		case model.RedactToken:
			oc.Mode = model.RedactToken
			oc.Output = r.Token(secret, sub.ID, f.Name, value)
		case model.RedactMask:
			oc.Mode = model.RedactMask
			oc.Output = maskValue(value)
		default:
			oc.Mode = model.RedactNone
			oc.Output = value
		}
		out[f.Name] = oc.Output
		outcomes = append(outcomes, oc)
	}

	// 未在资源规格中声明的字段按公开字段处理（确定性的兜底规则）。
	for name, value := range record {
		if declared[name] {
			continue
		}
		out[name] = value
		outcomes = append(outcomes, model.FieldOutcome{
			Field: name, Level: model.SensPublic, Kept: true, Mode: model.RedactNone, Output: value,
		})
	}

	return out, outcomes, dropped
}

// Token 对单个值做确定性令牌化。
// 令牌 = "tok_" + HMAC-SHA256(key=策略密钥, data=主体ID|字段|值规范形式) 前 16 字节的十六进制。
// 该函数为纯函数：相同输入（含重载后）恒得相同输出；HMAC 不可逆，无法由令牌还原明文。
func (r *Redactor) Token(secret, subjectID, field string, value any) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%s\x00%s\x00%v", subjectID, field, value)
	sum := mac.Sum(nil)
	return "tok_" + hex.EncodeToString(sum[:16])
}

// maskValue 生成外观掩码：字符串保留首字符，其余以 '*' 替代；
// 非字符串以固定长度 '*' 呈现，不泄露长度与内容。
func maskValue(value any) any {
	s, ok := value.(string)
	if !ok {
		return "********"
	}
	runes := []rune(s)
	if len(runes) == 0 {
		return ""
	}
	if len(runes) == 1 {
		return "*"
	}
	out := make([]rune, len(runes))
	out[0] = runes[0]
	for i := 1; i < len(runes); i++ {
		out[i] = '*'
	}
	return string(out)
}
