# 敏感字段流式脱敏器（安全日志外发）

面向安全日志外发场景的脱敏工具。输入为 **UTF-8 纯文本** 或 **JSON Lines**，
目标是阻止秘密泄漏，同时保留可核验的处理结构与证据。

- 运行环境：Windows / Python 3.12 / 仅 CPU，**仅使用标准库**，无 Docker、无外部服务。
- 所有操作局限在项目目录内；测试使用固定随机种子，可完全重放。

## 快速开始

```bash
# 处理一个批次（cases.json 描述秘密字典与全部用例）
python -m solution --input cases.json --output result.json

# 运行全部自动化测试
python -m unittest discover -s tests -v

# 重新生成二进制/超限样例（确定性）
python tools/make_samples.py
```

CLI 还会将每个用例的脱敏结果写入 `<output去掉扩展名>_outputs/` 目录
（上例即 `result_outputs/`）。可选参数 `--chunk-size N` 强制所有用例以
固定块大小读取输入（用于验证流式一致性）。

退出码：`0` 全部用例处理成功；`1` 至少一个用例级错误（如输入文件缺失，
详见 result.json 中该用例的 `error`）；`2` 全局配置错误（cases.json 缺失、
非法 JSON、非法字段等），错误信息打印到 stderr。

## 目录结构

```
solution/            核心包
  engine.py          流式字节匹配器（跨块安全、重叠裁决）
  secretspec.py      秘密字典 -> 三种表示的展开
  ids.py             带独立盐的 HMAC 替换标识
  jsonline.py        JSON 行验证、敏感路径与行内字典匹配
  pipeline.py        批处理管线（分块、行重组、隔离、结果装配）
  cli.py / __main__.py  命令行入口
cases.json           批次配置（秘密字典 + 用例，固定种子）
samples/             样例输入（含二进制与超限行样例）
tools/make_samples.py  确定性样例生成器
tests/               unittest 验收测试
result.json / result_outputs/   运行产物（不入库）
```

## 输入 schema：`cases.json`（`redactor-cases/1`）

```json
{
  "schema": "redactor-cases/1",
  "seed": 20261117,
  "secrets": ["明文秘密", "pa\"ss\nwörd"],
  "secrets_base64": ["AAECAwQFBgc="],
  "secrets_file": "可选，相对 cases.json 的路径，每行一个秘密（UTF-8）",
  "cases": [
    {
      "name": "用例名（必填、建议唯一）",
      "format": "text | jsonl",
      "input": "samples/x.jsonl",
      "chunk_sizes": [4, 1, 3]
    },
    {"name": "inline", "format": "text", "content": "内联文本"},
    {"name": "bin", "format": "text", "content_base64": "YmluOgA="}
  ]
}
```

- `seed`：整数。批次盐 = `random.Random(seed).randbytes(16)`，同种子完全可重放；
  省略则使用 `os.urandom(16)`（不可重放）。
- 秘密来源可组合：`secrets`（字符串，按 UTF-8 编码）、`secrets_base64`
  （二进制秘密）、`secrets_file`（每行一个）。空秘密非法（`E_BAD_CONFIG`）。
- 每个用例的输入三选一：`input`（项目内文件路径，相对 cases.json 解析，
  可为文本或二进制样例）、`content`（内联字符串）、`content_base64`（内联二进制）。
- `chunk_sizes`：正整数数组，循环使用，控制读取输入的分块边界；缺省 65536。
  分块边界可落在 UTF-8 字符、JSON 转义或秘密中间，结果与一次性处理完全一致。

## 输出 schema：`result.json`（`redactor-result/1`）

```json
{
  "schema": "redactor-result/1",
  "seed": 20261117,
  "batch_salt_hex": "……32 hex……",
  "cases": [ ... ]
}
```

`batch_salt_hex` 公开批次盐：盐不是秘密，公开它使第三方可以核验
"某标识是否对应某已知秘密"（可核验结构），而无法从标识反推未知秘密。

### text 用例

```json
{
  "name": "unicode", "format": "text", "input": "samples/unicode.txt",
  "status": "ok",
  "output_file": "result_outputs/unicode.redacted.txt",
  "output_sha256": "…",
  "evidence": [
    {"record": null, "byte_start": 17, "byte_end": 23,
     "id": "[REDACTED#f6368b79c6e728d0]",
     "source": "dictionary", "representation": "raw"}
  ]
}
```

整个输入不是合法 UTF-8 时，用例状态为 `quarantined`，只记录
`error_code` / `error_position` / `input_length` / `input_sha256`。

### jsonl 用例

```json
{
  "name": "truncated", "format": "jsonl", "status": "ok",
  "output_file": "result_outputs/truncated.redacted.jsonl",
  "counts": {"published": 1, "quarantined": 1, "blank": 0},
  "records": [
    {"line": 1, "status": "published",
     "evidence": [{"record": 1, "byte_start": 10, "byte_end": 22,
                   "id": "[REDACTED#…]", "source": "json_path", "key": "password"}]},
    {"line": 2, "status": "quarantined",
     "error_code": "E_JSON_SYNTAX", "error_position": 27,
     "line_length": 31, "line_sha256": "…"}
  ]
}
```

- 行号为物理行号（1 起，空行计入）。空行（仅空白）记为 `blank`，不产出记录。
- `published`：记录完整验证通过并脱敏发布，输出文件按原顺序只包含已发布行
  （统一以 `\n` 结尾；行内非敏感字节逐字节保留）。
- `quarantined`：**隔离区只存原文哈希与错误位置**（`line_sha256`、`error_position`、
  `line_length`、`error_code`），不存任何记录内容。
- 证据索引（`evidence`）把**原始输入的绝对字节区间**映射到替换标识：
  `byte_start`/`byte_end` 为半开区间；`source` 为 `dictionary`（附
  `representation`）或 `json_path`（附 `key`）。证据不含明文秘密。

## 匹配规则

1. **秘密字典**来自外部传入的有限集合（cases.json）。每个秘密展开为三种表示：
   - `raw`：秘密原始字节（UTF-8）；
   - `json_escape` / `json_escape_ascii`：`json.dumps` 在 `ensure_ascii=False/True`
     下产生的字符串体编码（另覆盖 `\uXXXX` 大写十六进制变体）。JSON 逐字符转义，
     因此秘密的转义形式必然逐字节出现在包含它的 JSON 字符串原始字节中；
   - `base64`：标准 base64（RFC 4648，含 `=` 填充）。
   **不做递归解码**：base64 的 base64 不会被进一步展开（有测试锁定）。
2. **重叠裁决**：先比长度，长者优先；同长按匹配字节串的字典序（小者优先）；
   仍相同（同字节串不同位置）取位置靠前者。选出的匹配互不重叠，按位置序输出。
   同一模式被多个秘密/表示产生时，取字典序最小的秘密、再按表示优先级
   （raw < json_escape < json_escape_ascii < base64），与字典顺序无关。
3. **JSON 敏感路径**：成员键名（解码后、大小写不敏感）为 `password`/`token`/`secret`
   的值整体替换为带引号的标识字符串，不论其 JSON 类型（字符串/数字/容器/null）。
   标识材料为该值的规范化 JSON（`sort_keys`、紧凑分隔符），因此同值同标识。
   路径替换优先于字典匹配；被敏感路径覆盖的区间不再做字典匹配。
4. JSON 行内的字典匹配**只作用于字符串值的内容区间**（不含键、数字与结构字节），
   因此输出仍是合法 JSON，非敏感值的语义与字节完全保留。

## 流式一致性

`StreamRedactor` 持有 `max_pattern_len - 1` 字节的回退：起始位置小于
`已缓冲 - (Lmax - 1)` 的匹配，其全部候选字节均已到齐；一个胜出匹配只有在
"不可能再有未知匹配与它重叠"（未知匹配起点 ≥ 提交边界 ≥ 该匹配终点）时才提交。
因此任意分块方式（包括逐字节、切在 UTF-8 序列/转义/秘密/base64 中间）的最终
输出与证据与一次性参考实现逐字节相同。测试对短输入**穷举全部切块位置**
（全部单切点，以及短向量的全部 2^(n-1) 种切分组合）断言该性质。

JSON Lines 模式下，分块字节流先重组为完整行再逐行处理；每行独立验证，
行级结果同样与分块方式无关（有逐切点测试）。

## 标识与盐

- 标识格式：`[REDACTED#<hmac-sha256 前16 hex>]`。
- 材料：字典秘密为 `b"dict\x00" + 秘密原始字节`（同一秘密的任意表示得到同一标识）；
  敏感路径值为 `b"path\x00" + 规范化 JSON 字节`。
- 同一批次（一次 CLI 运行）同一秘密 → 同一标识；不同批次（不同种子/盐）→ 不同标识。
- 异常、日志、证据、隔离区、result.json 均不含明文秘密；`LineError` 只携带
  错误码与字节位置。

## 错误码

| 代码 | 含义 | position 含义 |
|---|---|---|
| `E_LINE_TOO_LONG` | JSON 行内容（不含 `\n`）超过 1 MiB = 1048576 字节 | 1048576 |
| `E_UTF8_INVALID` | 记录/输入不是合法 UTF-8 | 首个非法字节偏移 |
| `E_JSON_SYNTAX` | JSON 语法错误（含 `NaN`/`Infinity` 等非标准常量、截断行） | 出错位置的字节偏移 |
| `E_INPUT_NOT_FOUND` | 用例输入文件不存在（用例级，退出码 1） | — |
| `E_UNSUPPORTED_FORMAT` | `format` 非 `text`/`jsonl`（用例级） | — |
| `E_BAD_CONFIG` | 全局配置非法（退出码 2，仅 stderr） | — |

## 测试（`python -m unittest discover -s tests -v`，51 个用例）

- `test_engine.py`：重叠裁决（最长优先、同长字节序、长者胜过早者）、三种表示、
  禁止递归解码、**穷举全部切块位置**的流式==一次性、逐字节分块、输出无秘密。
- `test_jsonline.py`：敏感路径（嵌套/大小写/非字符串/容器）、字典匹配仅限字符串值、
  路径优先级、截断行、非法 UTF-8（含位置）、**恰好 1 MiB 发布 / 1 MiB+1 隔离**、
  非标准常量、空行与顺序、非敏感值语义逐字节保留、逐切点行重组。
- `test_ids.py`：标识格式、同批次一致（跨表示）、跨批次不同、同种子可重放、
  标识不含秘密材料。
- `test_cli.py`：端到端跑 `cases.json`，逐一断言各验收场景（秘密重叠、跨块 Unicode、
  JSON 转义秘密、base64 边界、截断行、超限行、二进制秘密）；**扫描全部输出文件**
  （result.json + result_outputs/*）确认三种表示的秘密均不出现；隔离区字段白名单
  校验；固定种子重放逐字节一致；不同种子标识不同；错误退出码。

所有测试断言具体结果、状态或证据；批次种子固定（20261117），可重放。

## 限制与假设（非安全性细节）

- JSON 转义匹配覆盖 `json.dumps` 两种 canonical 形式及 `\u` 大写变体；
  不覆盖非标准的十六进制转义（如 `\x41`）或多余转义（如 `\/`）。
- base64 仅标准字母表、含填充；不匹配 URL-safe 变体或去填充形式。
- 敏感键匹配为解码后键名的精确（大小写不敏感）相等，不做空白裁剪或子串匹配。
- 敏感路径值一律替换为字符串占位符（原类型不保留）；字典替换发生在字符串
  内容内部，不改变类型。
- 输出行统一以 `\n` 结尾；被隔离的行不出现在输出中，记录顺序保持。
- 单行上限 1 MiB 以不含换行符的内容计；超限行在扫描前即隔离，不占用匹配开销。
