"""Flask application factory and local development entry point."""

from __future__ import annotations

import sqlite3

import click
from flask import Flask, jsonify,render_template

from .config import Config
from .database import get_db, init_app as init_database, init_db


def create_app(config_object: type[Config] = Config) -> Flask:
    """Create and configure the Flask application."""

    app = Flask(__name__)
    app.config.from_object(config_object)

    # 注册数据库关闭钩子。
    init_database(app)

    # 创建应用上下文，完成建表和首次种子数据写入。
    with app.app_context():
        init_db()

    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Initialize or repair the demonstration database."""

        init_db()
        click.echo("Database initialized successfully.")


    @app.get("/")
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