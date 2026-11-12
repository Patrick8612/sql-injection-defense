# 阶段一：项目初始化

## 目标

建立可重复使用的本地开发环境、清晰的目录边界和版本管理基线。本阶段不实现登录、查询、SQL 注入检测或日志业务。

## 已配置内容

- Python 3.11+ 虚拟环境约定和依赖清单。
- Flask 应用工厂与健康检查接口。
- 基于环境变量的本地安全配置。
- Git 忽略规则、编辑器约定和 pytest 配置。
- 第一阶段实施记录。

## 验收方式

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env
python -m pytest
python -m src.app
```

浏览器访问 `http://127.0.0.1:5000/health`，应返回：

```json
{"status": "ok"}
```

## 环境基线

- 监听地址：`127.0.0.1`
- 默认端口：`5000`
- 本地数据库文件：`instance/demo.db`
- 敏感配置：通过 `.env` 管理，不提交到 Git
