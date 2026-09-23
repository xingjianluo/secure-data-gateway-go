# Secure Data Gateway（本地数据访问网关，Go）

用**本地存储与内存状态**模拟数据源、主体目录、策略与审计记录的数据访问网关。
所有授权、脱敏、审计结论都来自同一套确定性逻辑，HTTP 入口与本地 SDK 入口共用
同一个 `gateway.Gateway`，因此不同入口、重复调用、并发调用、进程重载后的结论
均一致且可复现。

## 1. 目录结构

| 包 | 职责 |
|---|---|
| `model` | 主体、资源、字段、规则、策略、判定结论等领域模型 |
| `store` | 本地内存版主体/资源目录（`Directory`）与业务数据源（`DataSource`） |
| `policy` | 策略版本兼容校验（`compat.go`）与不可变多版本快照存储（`store.go`） |
| `authz` | 基于主体属性 / 资源敏感级别 / 操作类型的判定引擎，记录逐条判定依据 |
| `mask` | 按字段敏感级别的剔除、掩码、不可逆令牌化 |
| `audit` | 内存审计日志（输入 + 结论 + 依据 + 字段处理结果） |
| `gateway` | 组装以上组件的统一访问入口，并支持按历史版本复现 |
| `server` | HTTP 入口（与 SDK 入口逻辑完全相同） |
| `cmd/demo` | 内置演示数据的可启动服务 |

## 2. 授权规则

### 2.1 敏感级别

`public(0) < internal(1) < confidential(2) < restricted(3)`。

主体拥有 `Clearance`（可见级别上限）；资源拥有 `Sensitivity`（资源级别）；
每个字段单独拥有 `Level`。

### 2.2 判定流程

1. 取得**当前策略快照指针**后，整次判定只读该快照（热更新不影响在途判定）。
2. 前置检查，三类失败产生**可区分**的拒绝原因，绝不静默放行：
   - `policy_not_found`：尚未加载任何策略；
   - `unknown_subject`：主体未在目录注册；
   - `resource_not_found`：资源不存在。
3. 规则按顺序评估，**首个全部条件匹配的规则生效**（allow/deny）。每条规则都会
   记录命中与否，以及逐条不满足的原因（操作不匹配、级别不足、属性不等、
   部门不符、非所有者）。
4. 无规则匹配时走策略默认效果（强制为 `deny`），拒绝原因为 `no_permission`。

规则支持的条件：`Actions`、`MinLevel`（主体 Clearance ≥）、
`MaxLevel`（资源 Sensitivity ≤，0 表示不限）、`Subject` 属性全等匹配、
`Departments` 归属匹配、`OwnersOnly` 仅所有者。

> `no_permission` / `unknown_subject` / `resource_not_found` / `policy_not_found`
> 四类拒绝原因彼此不同，单测 `TestDenyReasonsAreDistinct` 强制保证。

## 3. 脱敏与令牌化规则

授权通过后，按资源的字段规格逐字段处理：

| 条件 / 模式 | 行为 |
|---|---|
| 字段级别 **> 主体 Clearance** | **整体剔除**：输出对象中不存在该键，不返回空值或占位符 |
| `none` | 原值返回 |
| `mask` | 掩码（字符串保留首字符，其余 `*`），仅外观遮蔽 |
| `token` | **不可逆**确定性令牌 `tok_<hex>` |

### 3.1 令牌化的确定性与不可逆性

```
token = "tok_" + HMAC-SHA256(key=策略密钥, data="主体ID|字段名|值")[0:16] 的十六进制
```

- **确定性**：纯函数，相同主体/字段/值恒得相同令牌；`Redactor` 无内部状态，
  重复调用与并发调用结果一致（`TestTokenDeterministic`、
  `TestTokenConcurrentConsistency`）。
- **重载稳定**：密钥来自策略快照（`TokenSecret`），不使用随机种子；进程重启、
  重建对象后，只要策略相同令牌就相同（`TestTokenStableAcrossReloadAndSecret`）。
- **不可逆**：HMAC 单向，令牌无法还原明文；不同主体/字段/值/策略密钥的令牌互不相同。
- 资源规格中未声明的记录字段按 `public` 原值返回（确定性兜底）。

## 4. 策略热更新与版本兼容

### 4.1 更新原子性

`policy.Store.Load` 先在锁外做兼容性校验，**校验失败直接返回错误，原状态不动**；
校验通过后在写锁内保存深拷贝快照并原子切换 `current` 指针。判定方先取快照指针，
之后只读这一不可变快照，因此在途判定读到的永远是“完整的旧版”或“完整的新版”，
不会读到半更新状态（`TestConcurrentHotUpdateInFlightConsistency`，以 `-race` 验证）。

### 4.2 兼容范围（语义化版本）

- 引擎当前支持 **schema 主版本 `1`**：接受所有 `1.x.y`（次版本/补丁视为向后兼容）。
- schema 主版本 `≠ 1` 属于存在破坏性变更、无法自动兼容，**拒绝加载**
  （返回包装了 `policy.ErrIncompatible` 的错误），并保持原策略继续可用。
- 此外以下定义非法也会被拒绝（`TestRejectInvalidDefinition`）：
  默认效果非 `deny`、规则效果非 allow/deny、非法操作、规则重名、空规则名。
- 策略 `Version` 必须**严格递增**，否则返回 `policy.ErrStaleVersion`。

### 4.3 历史结论可复现

所有历史版本快照都被保留（`Store.Get(version)`、`Versions()`）。
`Gateway.Replay(subject, resource, action, policyVersion)` 用指定版本快照复现判定，
不依赖当前策略（`TestReplayHistoricalVersion`）。

## 5. HTTP 接口

| 方法 路径 | 说明 |
|---|---|
| `GET /data?subject_id=&resource_id=&action=read` | 授权 + 脱敏访问，返回结论、判定依据、字段结果 |
| `POST /policies` | 热更新策略，body 为 `{"policy": {...model.Policy}}`；不兼容返回 400 且旧策略不变 |
| `GET /policies` | 已保存的策略版本列表 |
| `POST /replay` | 按 `policy_version` 复现判定，body：`subject_id/resource_id/action/policy_version` |
| `GET /audit` | 全部审计事件（含输入摘要、逐条依据、剔除字段） |

拒绝原因的 HTTP 状态码：`unknown_subject`/`no_permission` → 403，
`resource_not_found` → 404，`policy_not_found` → 503；响应体中 `reason`
字段仍保留可区分的机器可读原因。

## 6. 本地验证

要求 Go 1.25+（开发环境 1.26 验证通过）。

```bash
# 编译与静态检查
go build ./...
go vet ./...

# 全部单元测试（含越权 / 未知主体 / 并发热更新 / 新旧版本兼容 / 跨入口一致）
go test ./...

# 打印输入与判定依据
go test -v ./authz/ ./gateway/ ./policy/ ./mask/

# 竞态检测（热更新并发场景）
go test -race ./...
```

启动演示服务：

```bash
go run ./cmd/demo            # 监听 :8080

# 工程师（confidential）：可见 name/email(掩码)/ssn(令牌)，salary(restricted) 被整体剔除
curl -s 'http://localhost:8080/data?subject_id=u-eng&resource_id=emp-1&action=read'

# 实习生（internal）：资源级别 confidential 超出允许范围 → no_permission
curl -s 'http://localhost:8080/data?subject_id=u-intern&resource_id=emp-1&action=read'

# 未知主体 → unknown_subject（可区分）
curl -s 'http://localhost:8080/data?subject_id=u-ghost&resource_id=emp-1&action=read'

# 查看审计记录（含输入与逐条判定依据）
curl -s 'http://localhost:8080/audit'

# 用不兼容的 schema v2 热更新 → 400 被拒，v1 继续可用
curl -s -XPOST localhost:8080/policies -d '{"policy":{
  "schema_version":"2.0.0","version":2,"default_effect":"deny","rules":[]}}'
```

## 7. 关键设计取舍

- **默认拒绝**：无策略、无匹配规则一律拒绝，杜绝静默放行。
- **快照不可变 + 指针切换**：用最简单的机制获得热更新原子性与历史复现能力。
- **字段剔除而非置空**：无权字段不出现在输出中，避免通过键存在性泄露信息。
- **密钥随策略版本走**：令牌既对当前版本稳定，也能区分不同历史策略，
  且全程不可逆。
