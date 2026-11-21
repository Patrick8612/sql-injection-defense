# SQL 注入漏洞检测与防御演示系统

面向网络安全课程设计的本地教学系统。项目通过“漏洞模式”和“安全模式”的对照，展示 SQL 注入风险、检测告警与参数化查询防护。系统只使用虚构数据，并默认监听本机地址。

## 当前进度

阶段一至 3D 已完成：

- Flask 应用工厂、环境配置、pytest、Git 和健康检查。
- SQLite 数据库、虚构用户与文章、响应式页面和 Docker Compose。
- 登录、退出、Flask session 和登录日志。
- user/admin 角色、`admin_required` 和访问控制。
- `/articles` 参数化文章查询，支持关键词与分类筛选。
- 管理员模式管理：可以在“安全模式”和“漏洞演示模式”之间切换。

当前不包含 SQL 注入攻击载荷或检测规则，这些功能将在 3E 和阶段四实现。

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
- 管理面板：`http://127.0.0.1:5000/admin`
- 健康检查：`http://127.0.0.1:5000/health`

演示账号：

- 普通用户：`student / Student123!`
- 管理员：`admin / Admin123!`

## 模式管理

系统默认使用安全模式。只有已登录的管理员可以通过管理面板切换模式：

- `safe`：安全模式，当前安全查询使用参数绑定。
- `vulnerable`：漏洞演示模式，仅用于后续本地虚构数据实验。

`settings.security_mode` 在应用层和 SQLite 层都限制为 `safe` 或 `vulnerable`，切换时会更新 `updated_at`。普通用户执行切换请求返回 403，未登录用户跳转到登录页。

## 测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

pytest 临时目录固定为项目内的 `.pytest-basetemp/`，避免 Windows 用户临时目录权限导致测试夹具创建失败。当前完整测试结果为 `14 passed`。

## 安全边界

- 仅在本机运行，不使用真实账号、业务数据或外部目标。
- 不将 `.env`、数据库文件、日志和本地虚拟环境提交到 Git。
- 后续漏洞演示路径必须限制为只读查询，并明确显示实验环境风险标识。
