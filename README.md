# SQL 注入漏洞检测与防御演示系统

面向网络安全课程设计的本地教学系统。项目通过“漏洞模式”和“安全模式”的对照，展示 SQL 注入风险、检测告警与参数化查询防护。系统只使用虚构数据，并默认监听本机地址。

## 当前进度

阶段一已完成项目初始化，包含 Flask 应用骨架、环境配置、依赖清单、测试配置和 Git 基线。业务数据表、登录、查询、注入检测和日志模块将在后续阶段实现。

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

要求 Python 3.11 或更高版本。

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
- 健康检查：`http://127.0.0.1:5000/health`

## 安全边界

- 仅在本机运行，不使用真实账号、业务数据或外部目标。
- 不将 `.env`、数据库文件、日志和本地虚拟环境提交到 Git。
- 后续漏洞演示路径必须限制为只读查询，并明确显示实验环境风险标识。
