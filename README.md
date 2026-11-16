# 本地可衰减委托授权链与祖先撤销服务

一个**纯本地**的委托授权（delegation）服务：已认证主体可把自身权限的**子集**
委托给另一主体，形成最长 8 层的授权链；链上任意节点被撤销，其整棵子树
即刻不可用。仅使用 **Windows 原生 Python 3.12 标准库 + SQLite**，只需要 CPU，
不使用 Docker、外部服务、现成权限引擎或区块链。

---

## 1. 能力与规则映射

| 题目要求 | 实现位置 |
| --- | --- |
| 根授权含租户/持有人/资源集合/动作集合/生效过期时间，管理员创建 | `service.DelegationService.create_root_grant`、`cli.py root-grant` |
| 仅当前持有人可签发子授权 | `delegate()` 中 `ERR_NOT_HOLDER` / 叶子身份一致性校验 |
| 子授权显式绑定唯一父 ID 与不可变内容摘要 | 票据字段 `parent_id` / `parent_digest`，库列 `parent_id/parent_digest` |
| 资源/动作/时间区间均为父的子集，最长 8 层 | `_check_delegation_constraints`、`_assert_child_subset`、`MAX_DEPTH` |
| 持有人须为租户有效成员，禁止跨租户/拼接/乱序改义 | `_require_active_member`、租户一致性、规范摘要、父子绑定对账 |
| 固定 HS256，明确 JSON，拒绝重复键/错类型/未知版本/其他算法 | `crypto.py`（`_RejectDuplicates`、`_validate_header`、严格类型） |
| 签名密钥仅服务端持有 | `db.load_or_create_key` 生成本地 `server.key`，从不经网络返回 |
| 使用时登录身份须等于叶子持有人 | `_load_and_check_chain(expected_holder=...)` → `ERR_HOLDER_MISMATCH` |
| 校验全链签名/父子绑定/衰减/时间/每个祖先撤销状态 | `_load_and_check_chain` 逐节点全量校验 |
| 祖先撤销后所有后代不可用，不能靠重签/改父恢复 | 撤销位实时查库（不缓存）+ 票据与库行逐字节绑定 + 摘要对账 |
| 根授权扩权用新根 ID，不改旧链含义 | 根 ID 随机生成；无任何更新授权内容的接口 |
| delegate / check / revoke / 受保护版本递增，默认拒绝 | `httpapi.py` 路由，任何异常统一 `allowed:false` |
| ≥4 个独立进程共享数据库 | `cluster.py` + `serve_worker.py`，WAL 模式共享同一 DB 文件 |
| 撤销与签发/写入的一致提交顺序 | `BEGIN IMMEDIATE` 写事务 + 事务内二次全量校验 |
| 只缓存不可变验签结果，不缓存“未撤销”结论 | `_Verifier` 仅 LRU 缓存 `parse_ticket`；撤销/时间每次查库 |
| 可控同步点构造竞争 | `barriers.py` 文件屏障（arm/wait_for/release） |

## 2. 目录结构

```
deleg_service/
  __init__.py        常量（版本、算法、8 层上限、合法动作）
  errors.py          错误类型与原因码（默认拒绝的统一出口）
  crypto.py          严格 JSON、规范摘要、固定 HS256 票据签名/验签
  db.py              SQLite 连接(WAL)、建表、服务端密钥文件
  barriers.py        跨进程文件屏障（仅测试同步点，默认关闭）
  service.py         核心领域逻辑（签发/委托/全链校验/撤销/版本递增）
  httpapi.py         ThreadingHTTPServer 实现的 HTTP 接口
  cli.py             初始化与管理命令
  cluster.py         拉起 N 个共享数据库的独立服务进程
  serve_worker.py    服务工作进程入口
tests/
  reference_model.py 独立集合/树参考实现（不 import 服务代码，第二真相源）
  helpers.py         测试夹具：真实服务与参考模型双写联动
  test_core_rules.py 核心规则与攻击场景（深度/冒用/缺节点/摘要/跨租户/过期/缓存）
  test_fuzz_tree.py  随机委托树模糊测试，全主体×资源×动作矩阵交叉验证
  test_http_flow.py  HTTP 端到端
  test_race_multiprocess.py  4 进程竞争测试（文件屏障驱动）
run_tests.py         测试入口
init_demo.bat / run_cluster.bat  Windows 一键脚本
```

## 3. Windows 运行说明

需要 Windows 原生 Python 3.12（命令行 `python --version` 可见即可），无第三方依赖。

### 3.1 初始化与管理（单条命令）

```bat
REM 初始化数据库、租户、主体、资源、根授权（演示数据）
init_demo.bat data
```

等价的手工命令（在项目根目录执行）：

```bat
python -m deleg_service.cli --db-dir data init
python -m deleg_service.cli --db-dir data tenant --id t1 --name 租户甲
python -m deleg_service.cli --db-dir data principal --id alice --name 爱丽丝
python -m deleg_service.cli --db-dir data membership --tenant t1 --principal alice
python -m deleg_service.cli --db-dir data resource --id doc-1 --name 文档1
python -m deleg_service.cli --db-dir data root-grant --tenant t1 --holder alice ^
  --resources doc-1 --actions read write --nbf 2026-01-01 --exp 2032-01-01
```

时间参数支持 epoch 秒或 ISO-8601（`2030-01-01`、`2030-01-01T08:00:00Z`）。
其它管理命令：`login` / `revoke --auth-id ...` / `grant --auth-id ...` /
`version --resource-id ...`。

### 3.2 启动 4 个共享数据库的独立服务进程

```bat
run_cluster.bat data
REM 监听 127.0.0.1:8081 / 8082 / 8083 / 8084，Ctrl+C 整组退出
```

### 3.3 HTTP 调用示例（PowerShell）

```powershell
# 登录
$login = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8081/login `
  -ContentType 'application/json' `
  -Body '{"tenant_id":"t1","principal_id":"alice"}'
$h = @{ Authorization = "Bearer $($login.token)" }

# 委托（parent_ticket 来自 root-grant 命令输出）
$body = @{ parent_ticket=$ticket; holder='bob'; resources=@('doc-1');
           actions=@('read'); nbf=1767225600; exp=1956528000 } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8081/delegate `
  -ContentType 'application/json' -Headers $h -Body $body

# 使用授权（默认拒绝，任何不满足条件都返回 allowed:false）
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8082/check `
  -ContentType 'application/json' -Headers $hBob `
  -Body '{"ticket":"...","resource_id":"doc-1","action":"read"}'

# 撤销（持有人/签发者；管理员可用 CLI revoke）
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8083/revoke `
  -ContentType 'application/json' -Headers $h -Body '{"auth_id":"g_..."}'

# 受保护写入：资源版本 +1（要求叶子授权含该资源的 write）
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8084/resource/incr `
  -ContentType 'application/json' -Headers $h `
  -Body '{"ticket":"...","resource_id":"doc-1"}'

# 读取最终资源版本（断言最终状态用）
Invoke-RestMethod -Uri 'http://127.0.0.1:8081/resource/version?resource_id=doc-1'
```

## 4. 票据结构

固定三段式 `base64url(header).base64url(payload).base64url(signature)`，
签名为对前两段的 HMAC-SHA256。

```json
header  = {"alg":"HS256","typ":"DLG-TICKET","ver":1}
payload = {
  "v": 1, "auth_id": "g_...", "tenant": "t1", "holder": "bob",
  "resources": ["doc-1"], "actions": ["read"],
  "nbf": 1767225600, "exp": 1956528000,
  "parent_id": "g_...", "parent_digest": "<sha256 hex>"   // 根授权无此两项
}
```

- 内容摘要 `content_digest = sha256(canonical_json(payload))`，集合字段先排序，
  字段顺序/集合顺序/空白差异不会改变摘要，乱序无法改变含义；
- header 必须恰好为 `alg/typ/ver` 三字段；`alg` 非 HS256、`ver` 非 1 一律拒绝；
- JSON 解析拒绝重复键；类型检查排除布尔冒充整数；集合拒绝重复成员。

## 5. 一致性模型（为什么竞争下不会留下撤销后仍有效的分支）

1. `delegate` / `resource/incr` 先在只读连接里完成全链初校；
2. 在**写事务开启前**到达可控同步点（生产环境未布防时零阻塞）；
3. 被放行后开启 `BEGIN IMMEDIATE`，SQLite 写锁使所有写操作**全局串行**；
4. 事务内**重新加载并重跑整条链**的全部校验（含实时撤销位）。

因此：撤销先提交 → 后提交的签发/写入在二次校验时必见 `revoked=1` 而拒绝；
签发先提交 → 其后的撤销仍使该新分支立即失效。`check` 使用只读快照事务，
撤销提交之后新开始的检查必然读到新状态。

## 6. 自动化测试

```bat
python -I run_tests.py
```

- 独立参考实现 `tests/reference_model.py` 不依赖服务代码，独立建模成员、
  衰减、撤销、过期与资源版本；
- 随机委托树测试在 5 轮随机生长 + 随机撤销后，对每个授权 × 每个主体 ×
  每个资源 × read/write 的完整判定矩阵做双模型比对；
- 覆盖题目点名场景：第 8/9 层边界、叶子身份冒用、缺失中间节点、父摘要被改、
  换父拼接、同名主体跨租户、过期祖先、预热缓存下撤销；
- 4 进程竞争测试用文件屏障精确构造“祖先检查完成后的撤销”和“同节点撤销与
  再委托竞争”，并断言最终资源版本与授权链状态，而非仅验票据签名。

## 7. 安全边界与说明

- 服务只监听 `127.0.0.1`；登录令牌为不透明随机串，存于服务端会话表；
- 密钥文件 `server.key` 仅位于本地数据目录，HTTP 任何接口都不返回它；
  若当前环境禁止收紧 ACL，会打印告警并保留默认权限（见 `db._restrict_to_owner`）；
- 资源是预置的有限 `resource_id` 集合，动作只有 `read`/`write`，
  无路径通配符、无策略语言；
- 默认拒绝：结构错误、验签失败、状态不满足、未知路由全部返回 `allowed:false`。
