package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Masker 负责字段级脱敏/令牌化。
//
// 一致性保证：
//   - 令牌化 = HMAC-SHA256(secret, 字段名 + 规范值)，纯函数、无内部可变状态，
//     同一主体重复访问、并发访问、策略热更新/进程内重载后，同字段同值输出恒定；
//   - 不可逆：令牌不含明文片段，无密钥不可还原，重复调用不会回吐明文；
//   - 与字段名绑定，避免不同字段同值造成跨字段关联推断；
//   - 无权字段（字段敏感级别 > 主体持有级别，或策略显式 drop）整体剔除，
//     输出中不保留键，也不返回空值或占位符。
type Masker struct {
	secret []byte
}

// NewMasker 使用令牌化密钥创建 Masker。
func NewMasker(secret []byte) *Masker {
	return &Masker{secret: append([]byte(nil), secret...)}
}

// Project 依据策略对一条记录做字段投影。
// 返回：投影后的记录、保留字段名（字典序）、剔除字段名（字典序）。
func (m *Masker) Project(
	p *Policy,
	sub Subject,
	act Action,
	data map[string]any,
	levels map[string]Level,
) (map[string]any, []string, []string) {
	out := make(map[string]any, len(data))
	var kept, dropped []string

	// 排序保证审计中字段列表稳定可复现。
	names := make([]string, 0, len(data))
	for name := range data {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		level := levels[name] // 未标注级别视为 public(0)
		if level > sub.Clearance {
			dropped = append(dropped, name)
			continue
		}
		mode := fieldMode(p, level, act)
		if mode == FieldDrop {
			dropped = append(dropped, name)
			continue
		}
		switch mode {
		case FieldMask:
			out[name] = maskValue(data[name])
		case FieldTokenize:
			out[name] = m.tokenize(name, data[name])
		default: // FieldKeep 或未知值
			out[name] = data[name]
		}
		kept = append(kept, name)
	}
	return out, kept, dropped
}

// fieldMode 查询某敏感级别在某操作下的处理模式；缺省原样保留。
func fieldMode(p *Policy, level Level, act Action) FieldMode {
	if p == nil || p.FieldModes == nil {
		return FieldKeep
	}
	if byAction, ok := p.FieldModes[level]; ok {
		if mode, ok := byAction[act]; ok {
			return mode
		}
	}
	return FieldKeep
}

// maskValue 为可逆读语义的部分遮蔽：保留首尾，其余打码；非字符串整体遮蔽。
func maskValue(v any) any {
	s, ok := v.(string)
	if !ok {
		return "***"
	}
	r := []rune(s)
	switch {
	case len(r) == 0:
		return s
	case len(r) <= 2:
		return strings.Repeat("*", len(r))
	case len(r) <= 4:
		return string(r[0]) + strings.Repeat("*", len(r)-2) + string(r[len(r)-1])
	default:
		return string(r[0]) + "****" + string(r[len(r)-1])
	}
}

// tokenize 输出不可逆确定性令牌：tok_ + 十六进制 HMAC-SHA256。
func (m *Masker) tokenize(field string, v any) string {
	mac := hmac.New(sha256.New, m.secret)
	fmt.Fprintf(mac, "v1\x00field=%s\x00value=%s", field, canonical(v))
	return "tok_" + hex.EncodeToString(mac.Sum(nil))
}

// canonical 给出基本类型值的稳定规范表示，供令牌化使用。
func canonical(v any) string {
	if s, ok := v.(string); ok {
		return "s:" + s
	}
	return fmt.Sprintf("%T:%v", v, v)
}
