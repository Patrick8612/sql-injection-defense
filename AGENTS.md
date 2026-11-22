# SQL 注入漏洞检测与防御演示系统

## 项目边界

- 本地网络安全课程设计，只监听 `127.0.0.1`。
- 只使用虚构用户、虚构文章和本地 SQLite。
- 不连接真实业务系统、真实数据库或外部攻击目标。
- 不记录明文密码；`.env`、数据库、日志和 `.venv` 不提交 Git。
- 漏洞模式必须清晰标识，默认保持安全模式。
- 规则检测不能替代参数化查询。

## 当前进度

- 阶段一：Flask 应用工厂、环境配置、pytest、Git 和 `/health` 已完成。
- 阶段二：SQLite 初始化、演示数据、页面框架和 Docker Compose 已完成。
- 3A：登录、退出、session、`login_required` 和登录日志已完成。
- 3B：user/admin 角色、`admin_required`、`/admin` 和 403 控制已完成。
- 3C：`/articles` 参数化查询及关键词/分类筛选已完成。
- 3D：模式管理已完成。默认 `safe`，数据库限制只允许 `safe`/`vulnerable`，仅管理员可通过 `POST /admin/security-mode` 切换，所有页面显示当前模式，切换会更新 `settings.updated_at`。
- 3E：`/demo/sql-injection` 已完成。使用独立的 `instance/sql_injection_demo.db`，通过只读 URI、SQLite authorizer、单表读取、白名单函数、输入长度、返回行数、VM 步数、执行时间和 SQL 长度限制控制实验范围；支持正常特殊字符、错误型、联合查询和布尔盲注场景。
- 3F：阶段三本地收尾已完成。完整回归测试为 `24 passed`，本地 `/health` 返回 `200 {"status":"ok"}`，文档已同步并完成本地提交。GitHub 推送仍待网络恢复后重试。
- 4A：独立规则模型与基础规则已完成。`src/security/detection/` 提供参数长度、SQL 关键字、逻辑条件组合、注释/语句分隔符、异常编码和连续特殊字符规则；输出经过脱敏的规则证据，不包含评分、日志、拦截或页面集成。
- 4B：风险评分与处置映射已完成。不同规则只计分一次，多规则组合有限加分，总分封顶 100；`0–24` 为低风险放行、`25–59` 为中风险告警、`60–100` 为高风险拦截。评分输出包含等级、动作、规则贡献和可读原因。

当前完整测试结果为 `49 passed`。不要重写上述已完成功能。

Docker 配置已包含独立演示数据库路径。当前执行环境没有可用 Docker CLI，因此需要在安装 Docker 的环境中重新执行 `docker compose config`、构建、健康检查和页面验收。

运行测试：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

pytest 配置已将临时目录固定为项目内的 `.pytest-basetemp/`。

## 演示账号

- 普通用户：`student / Student123!`
- 管理员：`admin / Admin123!`

## 关键文件

- `src/app.py`：应用工厂、路由和全局模板上下文。
- `src/database.py`：SQLite 表结构、约束、初始化和种子数据。
- `src/security/auth.py`：session 与权限装饰器。
- `src/services/articles.py`：参数化文章查询。
- `src/services/settings.py`：安全模式读取、校验和持久化。
- `src/services/sql_injection_demo.py`：隔离的只读注入场景。
- `src/security/detection/`：独立的规则模型和 4A 基础规则。
- `src/security/detection/scoring.py`：4B 风险评分、等级和处置动作。
- `src/templates/`：Jinja2 页面模板。
- `src/static/css/app.css`：统一样式。
- `tests/`：pytest 自动化测试。

## 下一次工作

先通过 `git push origin main` 完成阶段三远端同步。下一步是 4C：增加请求频率检测，并决定如何把 4B 的放行、告警和拦截动作接入受控请求流程。

4B 已完成纯评分和动作映射，但仍不直接写 `detection_logs`，也不接入管理面板。阶段四始终只处理本地虚构数据和受控请求；检测规则不能替代参数化查询，漏洞演示模式默认应保持关闭。
