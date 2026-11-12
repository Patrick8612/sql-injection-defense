"""Flask application factory and local development entry point."""

from __future__ import annotations

from flask import Flask, jsonify

from .config import Config


def create_app(config_object: type[Config] = Config) -> Flask:
    """Create the web application without connecting to the database."""

    app = Flask(__name__)
    app.config.from_object(config_object)

    @app.get("/")
    def index():
        return jsonify(
            {
                "name": "SQL Injection Detection and Defense Demo",
                "status": "initialized",
                "stage": 1,
            }
        )

    @app.get("/health")
    def health():
        return jsonify({"status": "ok"})

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"],
    )
