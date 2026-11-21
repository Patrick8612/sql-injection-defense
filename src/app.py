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
    authenticate_user,
    init_app as init_auth,
    login_required,
)


def create_app(config_object: type[Config] = Config) -> Flask:
    """Create and configure the Flask application."""

    app = Flask(__name__)
    app.config.from_object(config_object)

    init_database(app)
    init_auth(app)

    with app.app_context():
        init_db()

    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Initialize or repair the demonstration database."""

        init_db()
        click.echo("Database initialized successfully.")

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
                    INSERT INTO login_logs (
                        user_id,
                        username_attempt,
                        source_ip,
                        success
                    )
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

        return render_template(
            "login.html",
            error=error,
            username=username,
        ), 401 if error else 200

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        flash("已安全退出登录。", "success")
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def index():
        db = get_db()

        article_count = db.execute(
            "SELECT COUNT(*) AS count FROM articles"
        ).fetchone()["count"]

        mode_row = db.execute(
            "SELECT value FROM settings WHERE key = ?",
            ("security_mode",),
        ).fetchone()

        mode = mode_row["value"] if mode_row else "safe"
        mode_label = "安全模式" if mode == "safe" else "漏洞演示模式"

        articles = db.execute(
            """
            SELECT
                articles.id,
                articles.title,
                articles.content,
                articles.category,
                articles.created_at,
                users.display_name AS author
            FROM articles
            JOIN users ON users.id = articles.author_id
            ORDER BY articles.id
            """
        ).fetchall()

        return render_template(
            "index.html",
            article_count=article_count,
            mode_label=mode_label,
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
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"],
    )
