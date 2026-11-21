# httpx result diff (跨轮历史比对)

本包提供**离线、流式、确定性**的两份 httpx JSONL 结果比对能力，回答「这台
机器的页面昨天和今天哪里不一样」。它不发起任何探测，也不改变单轮探测行为。

## 启用方式（默认关闭，关闭时零影响）

```
# 第一轮：普通探测，可选地写出探测参数 sidecar
httpx -l targets.txt -json -scan-meta -o run1.json

# 第二轮
httpx -l targets.txt -json -scan-meta -o run2.json

# 比对（不探测，只读两个文件）
httpx -diff -diff-baseline run1.json -diff-current run2.json -diff-output report.jsonl
```

- 不带 `-diff` 时，本包代码完全不进入执行路径，单轮输出格式与退出码不变。
- `-diff-output` 缺省输出到 stdout；给文件路径时**先写临时文件再原子 rename**，
  比对失败不会留下半截报告。

## 目标身份（跨轮稳定，硬约束二.1）

身份键按优先级取 `input` → `url` → `host` 中第一个非空字符串值
（见 `IdentityFields`）。键中不含探测时间、耗时、响应体哈希等易变材料；
`timestamp`、`time`、`trace`、本地文件路径等在 `IgnoredFields` 中显式排除。

## 比较字段清单（硬约束二.2：写在代码里，不是注释）

- `CompareFieldSpecs`：参与比较的每个顶层 JSON 字段及其所属类别。
- `SpecialCompareFields`：需要专门计算的字段（目前是 `hash`）。
- `IgnoredFields`：显式忽略的字段及原因。
- `runner/diff_contract_test.go` 用反射保证 `runner.Result` 的每个序列化字段
  都落在上述三处之一——新增字段若不做决定，测试直接失败。

### 变化类别（互斥分桶）

| 类别 | 含义 | 代表字段 |
| --- | --- | --- |
| `availability` | 可访问↔不可访问反转，或仅在一轮出现 | `failed`、presence |
| `source` | 地址/解析来源变化（不算内容变化） | `a` `aaaa` `cname` `host_ip` `sni` |
| `certificate` | 证书/TLS 变化，页面本身没变 | `tls` `jarm_hash` |
| `redirect` | 重定向链路变化（按跳数比较） | `chain` `chain_status_codes` `final_url` `scheme` `location` |
| `body` | 响应体摘要变化 | `body_preview` `body` `hash.body_*` `content_length` |
| `header` | 仅响应头变化 | `header` `raw_header` `webserver` `hash.header_*` |
| `field` | 其它标量/集合字段 | `status_code` `title` `tech` ... |

### body / header 分离（验收 2）

`hash` 对象同时含 `body_*` 与 `header_*` 摘要，不能整体比较。引擎按子键
（`compareHashField`）分别归类：`body_md5` 变化进 `body`，`header_md5` 变化
进 `header`，因此「只换响应头」绝不会被报成「内容变了」。

### 重定向按跳比较（需求一.8）

`chain` 变化时额外产出 `chain_hop_detail`：跳数不同直接给出 `hop_count` 的
before/after；跳数相同则逐跳列出 status_code/location/request-url 的差异，
而不是只比对最终落点。

## 确定性（硬约束二.3）

- 记录按 identity 排序输出，与输入顺序无关；
- 对象键经 `json.Compact` + 解码重编码（`UseNumber` 保精度）规范化，
  key 顺序不影响相等判定；
- 同两份输入比对两次，输出逐字节一致（有测试断言）。

## 异常处理

- 上一轮文件缺失：返回 `ErrMissingInput`，明确指出缺哪一份，绝不静默当
  「全部新增」。
- 探测参数不一致：读取 JSONL 旁的 `.meta.json` sidecar，对
  `follow_redirects` / `follow_host_redirects` / `max_redirects` /
  `include_chain` 逐项校验并给出可见告警（报告仍保留）。任一侧缺 sidecar
  不算错误（兼容旧结果文件）。
- 比对失败：临时输出文件被清理，不存在半截报告（有测试断言）。
- 重复身份：计数并提示，文件内以最后一条为准。

## 流式与内存（硬约束二.5）

baseline 侧读入 identity 索引的原始消息 map；current 侧逐行扫描、单行处理后
即释放，输出记录按 identity 排序后统一写出。峰值内存随 baseline 规模线性，
不随两文件之和膨胀。10k/100k 的实测数据见仓库根 `artifacts/diff-sample/`。
