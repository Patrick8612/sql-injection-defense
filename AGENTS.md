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

当前完整测试结果为 `14 passed`。不要重写上述已完成功能。

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
- `src/templates/`：Jinja2 页面模板。
- `src/static/css/app.css`：统一样式。
- `tests/`：pytest 自动化测试。

## 下一次工作

下一步是 3E：受控 SQL 注入演示。只可使用本地 SQLite 虚构文章数据，只允许只读 SELECT，限制返回行数和查询复杂度，禁止写操作、堆叠危险语句、延时、文件读取和系统命令，异常信息不得泄露数据库版本、表结构或堆栈细节。

3E 之后进入 3F：完整测试、更新文档、Git 提交和推送。检测规则与 `detection_logs` 属于阶段四，不属于 3E。
