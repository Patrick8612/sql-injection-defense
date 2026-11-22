# SQL 注入漏洞检测与防御演示系统

面向网络安全课程设计的本地教学系统。项目通过“漏洞模式”和“安全模式”的对照，展示 SQL 注入风险、检测告警与参数化查询防护。系统只使用虚构数据，并默认监听本机地址。

## 当前进度

阶段一至 3E 已完成，3F 本地验收已完成：

- Flask 应用工厂、环境配置、pytest、Git 和健康检查。
- SQLite 数据库、虚构用户与文章、响应式页面和 Docker Compose。
- 登录、退出、Flask session 和登录日志。
- user/admin 角色、`admin_required` 和访问控制。
- `/articles` 参数化文章查询，支持关键词与分类筛选。
- 管理员模式管理：可以在“安全模式”和“漏洞演示模式”之间切换。
- `/demo/sql-injection` 受控注入演示，支持正常特殊字符、错误型、联合查询和布尔盲注场景。
- 演示查询使用独立只读 SQLite 数据库、表级权限、输入限制、返回行数上限和执行超时。

当前不包含阶段四的自动检测规则和 `detection_logs` 写入功能。

阶段三本地收尾已完成：原有功能和新演示页面通过完整回归测试，本地健康检查返回 `200 {"status":"ok"}`，README、AGENTS.md 已同步并完成本地 Git 提交。当前环境无法连接 GitHub，远端推送待网络恢复后重试。当前执行环境也没有可用的 Docker CLI，因此容器配置虽已随演示数据库路径更新，仍需在安装了 Docker 的环境中重新验证容器健康状态。

阶段四 4A 已完成：新增独立规则引擎，能够识别参数长度异常、SQL 关键字、逻辑条件组合、注释或语句分隔符、异常编码和连续特殊字符。4A 只输出脱敏的规则命中结果，不包含风险评分、请求拦截、检测日志或管理面板统计。

阶段四 4B 已完成：在规则命中结果上生成可解释风险分值、低/中/高等级和允许/告警/拦截动作，包含多规则组合加分、总分封顶及边界测试。4B 仍是纯计算模块，尚未接入请求流程或写入日志。

## 目录结构

```text
sql-injection-defense/
├─ demo/          # 演示视频或展示材料
├─ deploy/        # Docker 与部署配置
├─ docs/          # 设计文档和阶段记录
├─ screenshots/   # 验收截图
├─ src/           # Flask 应用与业务模块
├─ tests/         # 自动化测试
├─ .env.example   # 本地配置模板
└─ requirements.txt
```

## 本地启动

要求 Python 3.12。

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
python -m pytest
python -m src.app
```

启动后访问：

- 首页：`http://127.0.0.1:5000/`
- 登录：`http://127.0.0.1:5000/login`
- 文章查询：`http://127.0.0.1:5000/articles`
- 受控注入演示：`http://127.0.0.1:5000/demo/sql-injection`
- 管理面板：`http://127.0.0.1:5000/admin`
- 健康检查：`http://127.0.0.1:5000/health`

演示账号：

- 普通用户：`student / Student123!`
- 管理员：`admin / Admin123!`

## 模式管理

系统默认使用安全模式。只有已登录的管理员可以通过管理面板切换模式：

- `safe`：安全模式，当前安全查询使用参数绑定。
- `vulnerable`：漏洞演示模式，用于访问隔离的本地注入实验。

`settings.security_mode` 在应用层和 SQLite 层都限制为 `safe` 或 `vulnerable`，切换时会更新 `updated_at`。普通用户执行切换请求返回 403，未登录用户跳转到登录页。

## 受控注入演示

管理员启用漏洞演示模式后，已登录用户可以访问 `/demo/sql-injection`。实验使用独立的 `instance/sql_injection_demo.db`：

- 数据库通过只读 URI 打开，并启用 `query_only`。
- SQLite authorizer 只允许读取 `demo_articles` 和白名单函数。
- 输入最长 80 个字符，结果最多展示 50 条。
- 查询有时间上限、VM 步数上限和 SQL 长度上限。
- 禁止写入、堆叠语句、系统 schema、文件操作和扩展函数。
- 数据库错误统一脱敏，不显示版本、表结构或堆栈。

安全模式下演示查询不会执行。

## 4A 基础检测规则

检测组件位于 `src/security/detection/`，不依赖 Flask 请求或数据库。当前规则编号：

- `PARAM_LENGTH`：参数长度异常。
- `SQL_KEYWORD`：SQL 关键字。
- `LOGICAL_COMBINATION`：引号、布尔逻辑和比较条件组合。
- `COMMENT_OR_SEPARATOR`：行注释、块注释或语句分隔符。
- `ENCODED_PAYLOAD`：可疑编码和重复编码。
- `SPECIAL_CHARACTER_RUN`：异常长度的连续特殊字符。

规则证据只保留长度、关键字或结构类型，不回显完整请求参数。4A 尚未接入现有页面和请求流程。

## 4B 风险评分与处置

4B 位于 `src/security/detection/scoring.py`。不同规则编号只计分一次，多个不同规则会获得有限组合加分。默认权重：

| 规则 | 分值 |
|---|---:|
| `PARAM_LENGTH` | 10 |
| `SQL_KEYWORD` | 25 |
| `LOGICAL_COMBINATION` | 30 |
| `COMMENT_OR_SEPARATOR` | 20 |
| `ENCODED_PAYLOAD` | 25 |
| `SPECIAL_CHARACTER_RUN` | 15 |

风险与动作映射：

| 总分 | 风险等级 | 处置动作 |
|---:|---|---|
| 0 | 无风险 | `allow` |
| 1–24 | 低风险 | `allow` |
| 25–59 | 中风险 | `alert` |
| 60–100 | 高风险 | `block` |

未知规则默认计 10 分，总分封顶 100。评分结果保留命中规则、分值贡献和可读原因，4C 将决定如何把动作接入请求流程以及请求频率规则。

## 测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

pytest 临时目录固定为项目内的 `.pytest-basetemp/`，避免 Windows 用户临时目录权限导致测试夹具创建失败。截至 2026-11-22，当前完整测试结果为 `49 passed`。

## 安全边界

- 仅在本机运行，不使用真实账号、业务数据或外部目标。
- 不将 `.env`、数据库文件、日志和本地虚拟环境提交到 Git。
- 注入演示只访问独立虚构数据库，始终限制为只读查询，并明确显示实验环境风险标识。
- 测试完成后应将系统切回安全模式。
