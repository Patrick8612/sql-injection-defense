"""Flask application factory and local development entry point."""

from __future__ import annotations

import sqlite3

import click
from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .config import Config
from .database import get_db, init_app as init_database, init_db
from .security.auth import (
    admin_required,
    authenticate_user,
    init_app as init_auth,
    login_required,
)
from .security.detection import (
    DetectionResult,
    DispositionAction,
    RequestFrequencyTracker,
    analyze_parameters,
    assess_detection,
    build_frequency_finding,
    decide_request_action,
    mask_parameters,
)
from .services.detection_logs import record_detection
from .services.articles import list_categories, search_articles
from .services.settings import (
    SECURITY_MODES,
    get_security_mode,
    security_mode_label,
    set_security_mode,
)
from .services.sql_injection_demo import (
    MAX_DEMO_INPUT_LENGTH,
    MAX_DEMO_RESULTS,
    SCENARIO_LABELS,
    SCENARIO_SUMMARIES,
    init_demo_database,
    run_demo_query,
)

MONITORED_ENDPOINT_PARAMETERS = {
    "article_search": ("q", "category"),
    "sql_injection_demo": ("q",),
}


def create_app(config_object: type[Config] = Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_object)

    init_database(app)
    init_auth(app)
    frequency_tracker = RequestFrequencyTracker()
    app.extensions["security_frequency_tracker"] = frequency_tracker

    with app.app_context():
        init_db()
        init_demo_database()

    @app.cli.command("init-db")
    def init_db_command() -> None:
        init_db()
        click.echo("Database initialized successfully.")

    @app.context_processor
    def inject_security_mode():
        mode = get_security_mode()
        return {
            "security_mode": mode,
            "security_mode_label": security_mode_label(mode),
        }

    @app.before_request
    def monitor_detected_parameters():
        parameter_names = MONITORED_ENDPOINT_PARAMETERS.get(request.endpoint)
        if not parameter_names:
            return None

        parameters = {}
        for name in parameter_names:
            values = request.args.getlist(name)
            if values:
                parameters[name] = values[0] if len(values) == 1 else values

        detection = analyze_parameters(parameters)
        if detection.matched:
            identity = (
                f"user:{g.user['id']}"
                if g.user is not None
                else f"ip:{request.remote_addr or 'unknown'}"
            )
            frequency = frequency_tracker.record(
                f"{identity}|{request.endpoint}"
            )
            if frequency.exceeded:
                detection = DetectionResult(
                    findings=detection.findings
                    + (build_frequency_finding(frequency),),
                    parameters_checked=detection.parameters_checked,
                )

        assessment = assess_detection(detection)
        security_mode = get_security_mode()
        decision = decide_request_action(
            assessment,
            endpoint=request.endpoint,
            security_mode=security_mode,
        )

        g.security_detection = detection
        g.security_assessment = assessment
        g.security_decision = decision

        if detection.matched:
            try:
                g.security_log_id = record_detection(
                    assessment,
                    endpoint=request.path,
                    payload_masked=mask_parameters(parameters),
                    action=decision.effective_action,
                )
            except sqlite3.Error:
                app.logger.exception("Detection log write failed")

        if decision.effective_action is DispositionAction.BLOCK:
            return render_template("security_blocked.html"), 403

        return None

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user is not None:
            return redirect(url_for("index"))

        error = None
        username = ""

        if request.method == "POST":
            username = request.form.get("username", "").strip()[:80]
            password = request.form.get("password", "")
            user = authenticate_user(username, password)
            db = get_db()

            with db:
                db.execute(
                    """
                    INSERT INTO login_logs (user_id, username_attempt, source_ip, success)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        user["id"] if user else None,
                        username or "(empty)",
                        request.remote_addr or "unknown",
                        1 if user else 0,
                    ),
                )

            if user is None:
                error = "用户名或密码错误。"
            else:
                session.clear()
                session["user_id"] = user["id"]
                flash(f"欢迎，{user['display_name']}。", "success")
                return redirect(url_for("index"))

        return render_template("login.html", error=error, username=username), 401 if error else 200

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        flash("已安全退出登录。", "success")
        return redirect(url_for("login"))

    @app.get("/admin")
    @login_required
    @admin_required
    def admin_dashboard():
        db = get_db()
        user_count = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        article_count = db.execute("SELECT COUNT(*) AS count FROM articles").fetchone()["count"]
        recent_logs = db.execute(
            """
            SELECT login_logs.id, login_logs.username_attempt, login_logs.source_ip,
                   login_logs.success, login_logs.created_at, users.display_name
            FROM login_logs
            LEFT JOIN users ON users.id = login_logs.user_id
            ORDER BY login_logs.id DESC
            LIMIT 10
            """
        ).fetchall()
        return render_template(
            "admin.html",
            user_count=user_count,
            article_count=article_count,
            recent_logs=recent_logs,
        )

    @app.post("/admin/security-mode")
    @login_required
    @admin_required
    def switch_security_mode():
        mode = request.form.get("mode", "").strip()

        if mode not in SECURITY_MODES:
            flash("运行模式无效，未做任何修改。", "error")
            return redirect(url_for("admin_dashboard"))

        set_security_mode(mode)
        flash(f"已切换为{security_mode_label(mode)}。", "success")
        return redirect(url_for("admin_dashboard"))

    @app.errorhandler(403)
    def forbidden(error):
        return render_template("403.html"), 403

    @app.get("/articles")
    @login_required
    def article_search():
        keyword = request.args.get("q", "").strip()[:80]
        category = request.args.get("category", "").strip()[:40]
        articles = search_articles(keyword=keyword, category=category)
        categories = list_categories()
        return render_template(
            "articles.html",
            articles=articles,
            categories=categories,
            keyword=keyword,
            selected_category=category,
        )

    @app.get("/demo/sql-injection")
    @login_required
    def sql_injection_demo():
        scenario = request.args.get("scenario", "normal").strip()
        if scenario not in SCENARIO_LABELS:
            scenario = "normal"

        parameter = request.args.get("q", "").strip()
        submitted = bool(request.args)
        result = None
        if get_security_mode() == "vulnerable" and submitted:
            result = run_demo_query(scenario, parameter)

        return render_template(
            "sql_injection_demo.html",
            scenario=scenario,
            scenario_labels=SCENARIO_LABELS,
            scenario_summary=SCENARIO_SUMMARIES[scenario],
            parameter=parameter,
            result=result,
            submitted=submitted,
            max_input_length=MAX_DEMO_INPUT_LENGTH,
            max_results=MAX_DEMO_RESULTS,
        )

    @app.get("/")
    @login_required
    def index():
        db = get_db()
        article_count = db.execute("SELECT COUNT(*) AS count FROM articles").fetchone()["count"]
        articles = db.execute(
            """
            SELECT articles.id, articles.title, articles.content, articles.category,
                   articles.created_at, users.display_name AS author
            FROM articles
            JOIN users ON users.id = articles.author_id
            ORDER BY articles.id
            """
        ).fetchall()
        return render_template(
            "index.html",
            article_count=article_count,
            articles=articles,
        )

    @app.get("/health")
    def health():
        try:
            get_db().execute("SELECT 1").fetchone()
        except sqlite3.Error:
            app.logger.exception("Database health check failed")
            return jsonify({"status": "error"}), 503
        return jsonify({"status": "ok"})

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host=app.config["HOST"], port=app.config["PORT"], debug=app.config["DEBUG"])
