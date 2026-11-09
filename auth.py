"""
Sentinel Watch - Authentication Module

Roles
-----
admin    : Dashboard, History, Alerts, Reports, System Config
security : Dashboard, History, Alerts
"""

from functools import wraps
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, session, flash, g,
)
from werkzeug.security import check_password_hash, generate_password_hash
import database
import logging

logger = logging.getLogger("sentinel.auth")

auth_bp = Blueprint("auth", __name__)

VALID_ROLES = ("admin", "security")


# ── Decorators ────────────────────────────────────────────────────────────────

def login_required(f):
    """Redirect unauthenticated requests to /login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.url))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Restrict route to admin role only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("auth.login", next=request.url))
        if session.get("role") != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


# ── Request hook ──────────────────────────────────────────────────────────────

@auth_bp.before_app_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = database.find_user_by_id(user_id) if user_id else None


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Please enter both username and password.", "danger")
            return render_template("login.html")

        user = database.find_user_by_username(username)

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"]   = user["id"]
            session["username"]  = user["username"]
            session["role"]      = user["role"]
            session["full_name"] = user["full_name"] or user["username"]
            database.update_last_login(user["id"])
            logger.info(f"User '{username}' logged in successfully.")
            flash("Welcome back, " + (user["full_name"] or user["username"]) + "!", "success")
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("dashboard"))

        logger.warning(f"Failed login attempt for username: '{username}'")
        flash("Invalid username or password.", "danger")

    return render_template("login.html")


# ── Register ──────────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username         = request.form.get("username", "").strip()
        email            = request.form.get("email", "").strip()
        full_name        = request.form.get("full_name", "").strip()
        role             = request.form.get("role", "security").strip()
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        errors = []
        if not username:
            errors.append("Username is required.")
        if not email:
            errors.append("Email is required.")
        if not password:
            errors.append("Password is required.")
        if len(password) < 6:
            errors.append("Password must be at least 6 characters.")
        if password != confirm_password:
            errors.append("Passwords do not match.")
        if role not in VALID_ROLES:
            role = "security"
        if database.find_user_by_username(username):
            errors.append("Username is already taken.")
        if database.find_user_by_email(email):
            errors.append("Email address is already registered.")

        if errors:
            for err in errors:
                flash(err, "danger")
            return render_template("register.html",
                                   form_data=request.form)

        password_hash = generate_password_hash(password)
        new_id = database.add_user(
            username=username,
            email=email,
            password_hash=password_hash,
            role=role,
            full_name=full_name,
        )

        if new_id:
            logger.info(f"New user registered: '{username}' with role '{role}'")
            flash("Registration successful. You can now sign in.", "success")
            return redirect(url_for("auth.login"))
        else:
            flash("Registration failed. Please try again.", "danger")

    return render_template("register.html", form_data={})


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout")
def logout():
    username = session.get("username", "User")
    session.clear()
    logger.info(f"User '{username}' logged out.")
    flash(username + " signed out successfully.", "info")
    return redirect(url_for("auth.login"))


# ── Profile ───────────────────────────────────────────────────────────────────

@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = database.find_user_by_id(session["user_id"])
    if request.method == "POST":
        action = request.form.get("action")
        if action == "change_password":
            current = request.form.get("current_password", "")
            new_pw  = request.form.get("new_password", "")
            confirm = request.form.get("confirm_new_password", "")
            if not check_password_hash(user["password_hash"], current):
                flash("Current password is incorrect.", "danger")
            elif len(new_pw) < 6:
                flash("New password must be at least 6 characters.", "danger")
            elif new_pw != confirm:
                flash("New passwords do not match.", "danger")
            else:
                database.update_user_password(user["id"], generate_password_hash(new_pw))
                flash("Password changed successfully.", "success")
                return redirect(url_for("auth.profile"))
    return render_template("profile.html", user=user)
