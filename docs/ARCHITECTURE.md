# 架构说明

## 为什么需要这个护栏

AI 自主渗透测试（agent）和人类白帽子最大的区别：**它会真的执行**。

人类看到 `/sso/authLogin/sms` 会想「这是发短信接口，测了会打扰真实用户，跳过」。
Agent 会直接发 34 次，因为它只是在「验证接口是否存在」。

护栏的作用就是补上这层判断。

## 三层判定

```
请求
  │
  ├─[1] 规则层（guard.py: business_write_hit / decide）
  │      确定性的，微秒级
  │      看路径分词、HTTP 方法、请求体特征
  │      ├─ 命中危险 → BLOCK
  │      ├─ 命中注意 → ANNOTATE（放行但标记）
  │      └─ 未命中 → 继续
  │
  ├─[2] 语义层（guard.py: jev_decide）
  │      调 LLM，300-800ms
  │      把原始请求报文交给 Jev 模型
  │      问三个问题：删改？RCE？影响面？
  │      ├─ 删改 + 高置信 → BLOCK
  │      ├─ RCE + 高置信 → BLOCK
  │      └─ 否则 → ALLOW
  │
  └─[3] 交叉校验
         规则层说 read/create 时，可以否决模型的「删改」判断
         但 RCE 判断不受否决（内容语义规则层表达不了）
```

### 为什么要有交叉校验

实测案例：

```
POST /api/user/list  {"status":"deleted"}
```

模型看到 `deleted` 就报「删改」（conf 0.8+），但实际是**查询已删除的用户列表**。
规则层基于结构判断（路径末段 `list` = 读操作）更可靠，所以允许否决模型的删改意见。

但 RCE 判断不能被否决：`chmod u+s` 这种在结构上就是「新建」，
规则层会判成 create 放行，只有模型能看出这是提权。

## 关键设计决策

### 1. 为什么用 mitmproxy 而不是 iptables

iptables 只能按 IP/端口拦，看不到 HTTP 语义。
我们要判断的是「这个请求会不会改数据」，必须看方法和路径。

实际部署是**两者都有**：iptables 保证流量必须过代理，mitmproxy 做语义判断。

### 2. 为什么 Jev 挂了要 fail-closed

```python
if 写方法 and Jev 不可用:
    return False  # 拒绝
if 读方法 and Jev 不可用:
    return True   # 放行（规则层已把关）
```

写操作的风险不能交给「默认放行」。宁可误拦，不可漏放。

### 3. 为什么 403 要带结构化信息

原始实现返回纯文本 `blocked by jev guard | <原因>`。
Agent 把它当网络错误，毫秒级重试——实测 7 秒重试 34 次。

改成：

```json
{"blocked":true,"policy_block":true,"retryable":false,
 "action":"stop","error":"POLICY_BLOCKED"}
```

并加响应头 `X-Artex-Retryable: 0`，让调用方能识别「这是策略拒绝，别重试」。

### 4. 为什么要连接池

原实现每次 `build_opener()` 新建连接，TLS 握手 0.5s。
单次调用总耗时 800ms，其中 60% 是握手。

改用 urllib3 ProxyManager 复用后：

| | 优化前 | 优化后 |
|---|---|---|
| 冷启动 | 800ms | 860ms |
| 稳态 | 800ms | **320ms** |

## 已知限制

| 限制 | 说明 |
|---|---|
| 模型有误判 | 实测 30000+ 请求中约 5 条误判（dictList 被判 RCE 0.63） |
| 规则有盲区 | 非 REST 形态（GraphQL mutation、裸 SQL）结构分类器不可靠 |
| 加密请求体看不到 | 只看到密文，语义判定退化为规则层 |
| 不防数据渗出 | 只拦「改删」，读操作默认放行（授权测试需要读） |

## 观测台数据流

```
mitm_guard.py
    └─ 每条判定写 mitm-audit.log（JSONL）
            │
            v
ui/server.py
    └─ tail 日志 → 内存聚合 → SSE 推送
            │
            v
ui/index.html
    └─ EventSource 实时渲染
```

日志格式（每行一个 JSON）：

```json
{"ts":"2026-01-01T00:00:00","h":"target.example",
 "method":"POST","url":"https://target.example/api/x",
 "allow":false,"would_block":true,"enforced":true,
 "reasons":["【业务写入保护】外部触达动作 sms"],
 "jev":{"by":"jev","kind":"deletes_or_modifies_existing","conf":0.87}}
```
