"""Authentication helpers and request login state."""

from __future__ import annotations

from functools import wraps

from flask import Flask, abort, g, redirect, session, url_for
from werkzeug.security import check_password_hash

from ..database import get_db


def load_logged_in_user() -> None:
    """Load the current user from the session before each request."""

    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
        return

    g.user = get_db().execute(
        """
        SELECT id, username, display_name, role
        FROM users
        WHERE id = ? AND is_active = 1
        """,
        (user_id,),
    ).fetchone()


def login_required(view):
    """Redirect unauthenticated visitors to the login page."""

    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(**kwargs)

    return wrapped_view


def admin_required(view):
    """Allow only users with the administrator role."""

    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        if g.user["role"] != "admin":
            abort(403)
        return view(**kwargs)

    return wrapped_view


def authenticate_user(username: str, password: str):
    """Return the matching active user, or None for invalid credentials."""

    if not username or not password:
        return None

    user = get_db().execute(
        """
        SELECT id, username, password_hash, display_name, role
        FROM users
        WHERE username = ? AND is_active = 1
        """,
        (username,),
    ).fetchone()

    if user is None:
        return None

    if not check_password_hash(user["password_hash"], password):
        return None

    return user


def init_app(app: Flask) -> None:
    """Register authentication hooks with Flask."""

    app.before_request(load_logged_in_user)
