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

## 测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

pytest 临时目录固定为项目内的 `.pytest-basetemp/`，避免 Windows 用户临时目录权限导致测试夹具创建失败。截至 2026-11-22，当前完整测试结果为 `24 passed`。

## 安全边界

- 仅在本机运行，不使用真实账号、业务数据或外部目标。
- 不将 `.env`、数据库文件、日志和本地虚拟环境提交到 Git。
- 注入演示只访问独立虚构数据库，始终限制为只读查询，并明确显示实验环境风险标识。
- 测试完成后应将系统切回安全模式。
