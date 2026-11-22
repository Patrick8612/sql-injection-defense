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
- 4C：请求频率与执行处置已完成。文章查询和受控演示的指定参数已接入检测；60 秒内第 5 次可疑请求增加 `REQUEST_FREQUENCY`（40 分）。正常业务路由高风险时在执行前返回 403，中风险告警后放行；受控演示在漏洞模式下将高风险降级为教学告警并允许运行，确保 3E 实验仍可用。
- 4D：载荷脱敏与检测日志已完成。命中规则的请求会写入 `detection_logs`，记录攻击类型、路由、不可还原的字符结构摘要、风险等级、分值、实际动作和时间；被拦截请求也会在 403 返回前写入。正常请求不写检测日志。
- 4E：管理面板检测视图已完成。`/admin` 从真实 `detection_logs` 展示总数、低/中/高分布、动作统计、最近检测时间和最新 15 条告警；`/admin/detections/<id>` 提供管理员脱敏详情，普通用户 403、未登录跳转登录、缺失记录 404。
- 4F：阶段四收尾已完成。完整回归为 `81 passed`，Docker Compose 配置、镜像构建、容器健康、真实日志统计和管理员详情页均完成实际验收，容器停止时保留数据卷。
- 5A：安全模式加固已完成。文章查询使用独立只读连接和列级白名单；输入改为显式长度、控制字符、密码和分类校验，不再静默截断；统一 400/500 错误页面并增加 CSP、nosniff、禁止 iframe、无来源信息和 HTML 禁止缓存等安全响应头。
- 5B：同输入安全对照已完成。管理员可在 `/admin/comparison` 执行六个固定用例，使用同一输入分别运行隔离漏洞查询和参数化安全查询，并将脱敏状态、数量、错误、风险、规则、建议动作和结论写入 `comparison_runs` / `comparison_results`。实验不修改全局模式，也不自动写 `detection_logs`。
- 5C：实验报告已完成。管理员可从真实对照实验和检测日志生成 Markdown 快照，保存到 `experiment_reports`，支持预览和下载。报告只使用脱敏记录和真实统计，后续数据变化不会改写旧报告。
- 5D：演示环境恢复已完成。`/admin/reset` 对管理员开放并要求输入 `RESET` 确认；恢复前备份两个数据库，事务恢复用户、文章、设置和演示数据，清空登录/检测/对照/报告以及频率状态，并强制退出会话。失败时尝试从新备份回滚应用数据库。

当前完整测试结果为 `123 passed`。不要重写上述已完成功能。

阶段四 Docker 验收已完成：Compose 配置校验通过，容器达到 `healthy`，`/health` 返回 `200 {"status":"ok"}`。停止容器时使用 `docker compose down`，未删除数据卷。

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
- `src/security/detection/frequency.py`：4C 内存滑动窗口和频率规则。
- `src/security/detection/policy.py`：正常业务与受控演示的执行政策。
- `src/security/detection/masking.py`：4D 不可还原载荷摘要。
- `src/services/detection_logs.py`：4D 检测日志分类和持久化。
- `src/security/validation.py`：5A 请求输入显式校验。
- `src/services/articles.py`：5A 只读文章查询连接和白名单。
- `src/services/comparison.py`：5B 固定用例、双侧执行和对照持久化。
- `src/templates/comparison.html`：5B 管理员对照实验页面。
- `src/services/reports.py`：5C 真实数据报告生成与快照。
- `src/templates/reports.html`：5C 报告列表与生成入口。
- `src/templates/report_preview.html`：5C Markdown 报告预览。
- `src/services/reset.py`：5D 数据库备份、恢复和回滚。
- `src/templates/reset.html`：5D 恢复确认页面。
- `src/templates/detection_detail.html`：4E 管理员检测详情页。
- `src/templates/404.html`：统一缺失页面。
- `src/templates/security_blocked.html`：高风险请求拦截页。
- `src/templates/`：Jinja2 页面模板。
- `src/static/css/app.css`：统一样式。
- `tests/`：pytest 自动化测试。

## 下一次工作

下一步是 5E：整合阶段五管理员入口，完成最终浏览器验收、Docker 验证、文档和提交材料准备。

5D 恢复只可处理系统自己的虚构运行数据，不能删除源码、配置、论文或截图。5C 报告只能读取真实数据并保存快照；5B 的漏洞侧不得脱离独立只读演示库，安全侧不得放弃参数绑定。阶段五始终只处理本地虚构数据，漏洞演示模式默认应保持关闭。
