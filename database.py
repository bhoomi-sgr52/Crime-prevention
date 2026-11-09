"""
Sentinel Watch - Database Module (SQLite)

Tables
------
users       : system accounts (admin / security roles)
detections  : every weapon/threat detection event
alerts      : push notifications tied to detections
system_settings : key-value runtime config (camera URL, etc.)
"""

import sqlite3
import json
import logging
from datetime import datetime, date, time as dtime
from werkzeug.security import generate_password_hash
from config import Config

logger = logging.getLogger("sentinel.database")


# ── Connection ────────────────────────────────────────────────────────────────

def get_db_connection():
    """Open a WAL-mode thread-safe connection to sentinelwatch.db."""
    conn = sqlite3.connect(str(Config.DATABASE_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def close_connection(conn):
    """Safely close a database connection."""
    if conn:
        try:
            conn.close()
        except Exception as exc:
            logger.warning("Error closing DB connection: %s", exc)


# ── Initialisation ────────────────────────────────────────────────────────────

def init_db():
    """Create all tables and seed the default admin account."""
    Config.init_directories()
    conn = get_db_connection()
    try:
        with conn:
            # USERS
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    username      TEXT    UNIQUE NOT NULL,
                    email         TEXT    UNIQUE NOT NULL,
                    password_hash TEXT    NOT NULL,
                    role          TEXT    NOT NULL DEFAULT 'security',
                    full_name     TEXT    DEFAULT '',
                    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login    TIMESTAMP
                );
            """)

            # DETECTIONS
            conn.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    date            TEXT    NOT NULL,
                    time            TEXT    NOT NULL,
                    activity        TEXT    NOT NULL,
                    detected_objects TEXT   DEFAULT '[]',
                    confidence      REAL    NOT NULL DEFAULT 0.0,
                    threat_score    INTEGER NOT NULL DEFAULT 0,
                    threat_level    TEXT    NOT NULL DEFAULT 'LOW',
                    screenshot_path TEXT    DEFAULT '',
                    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # ALERTS
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    detection_id  INTEGER REFERENCES detections(id) ON DELETE SET NULL,
                    message       TEXT    NOT NULL,
                    alert_status  TEXT    NOT NULL DEFAULT 'PENDING',
                    sms_status    TEXT    NOT NULL DEFAULT 'NOT_CONFIGURED',
                    sent_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            # Migrate existing DB: add sms_status if column does not yet exist
            try:
                conn.execute("ALTER TABLE alerts ADD COLUMN sms_status TEXT NOT NULL DEFAULT 'NOT_CONFIGURED';")
            except Exception:
                pass  # Column already exists — ignore

            # SYSTEM SETTINGS
            conn.execute("""
                CREATE TABLE IF NOT EXISTS system_settings (
                    key        TEXT PRIMARY KEY,
                    value      TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Seed default admin
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM users;")
            if cur.fetchone()[0] == 0:
                conn.execute("""
                    INSERT INTO users (username, email, password_hash, role, full_name)
                    VALUES (?, ?, ?, ?, ?);
                """, (
                    "admin",
                    "admin@sentinelwatch.local",
                    generate_password_hash("admin123"),
                    "admin",
                    "Sentinel Administrator",
                ))
                logger.info("Default admin created: admin / admin123")

            # Seed default camera URL setting
            cur.execute("SELECT COUNT(*) FROM system_settings WHERE key='camera_url';")
            if cur.fetchone()[0] == 0:
                conn.execute("""
                    INSERT INTO system_settings (key, value, description)
                    VALUES ('camera_url', ?, 'Active camera stream URL');
                """, (Config.DEFAULT_CAMERA_URL,))

        logger.info("Database initialised at %s", Config.DATABASE_PATH)
    finally:
        close_connection(conn)


# ── User operations ───────────────────────────────────────────────────────────

def add_user(username, email, password_hash, role="security", full_name=""):
    """Insert a new user. Returns the new row id, or None on conflict."""
    conn = get_db_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO users (username, email, password_hash, role, full_name)
                VALUES (?, ?, ?, ?, ?);
            """, (username.strip(), email.strip(), password_hash, role, full_name.strip()))
            return cur.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        close_connection(conn)


def find_user_by_id(user_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        return cur.fetchone()
    finally:
        close_connection(conn)


def find_user_by_username(username):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?);", (username.strip(),))
        return cur.fetchone()
    finally:
        close_connection(conn)


def find_user_by_email(email):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?);", (email.strip(),))
        return cur.fetchone()
    finally:
        close_connection(conn)


def update_last_login(user_id):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?;",
                (user_id,),
            )
    finally:
        close_connection(conn)


def update_user_password(user_id, new_password_hash):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?;",
                (new_password_hash, user_id),
            )
            return True
    finally:
        close_connection(conn)


# ── Detection operations ──────────────────────────────────────────────────────

def save_detection(activity, detected_objects, confidence, threat_score,
                   threat_level, screenshot_path=""):
    """
    Persist one detection event.
    detected_objects: list[str] or str  — serialised to JSON.
    Returns the new detection id.
    """
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")
    if isinstance(detected_objects, list):
        detected_objects = json.dumps(detected_objects)

    conn = get_db_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO detections
                    (date, time, activity, detected_objects, confidence,
                     threat_score, threat_level, screenshot_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """, (
                date_str, time_str, activity, detected_objects,
                round(float(confidence), 4), int(threat_score),
                threat_level, screenshot_path,
            ))
            det_id = cur.lastrowid
            logger.info("Detection #%d saved (%s score=%d)", det_id, threat_level, threat_score)
            return det_id
    finally:
        close_connection(conn)


def get_detection_history(limit=100, offset=0, threat_level=None, search=None):
    """Retrieve detection records, newest first."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        query = "SELECT * FROM detections WHERE 1=1"
        params = []
        if threat_level and threat_level.upper() != "ALL":
            query += " AND threat_level = ?"
            params.append(threat_level.upper())
        if search:
            query += " AND (activity LIKE ? OR detected_objects LIKE ?)"
            s = "%" + search + "%"
            params.extend([s, s])
        query += " ORDER BY id DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])
        cur.execute(query, params)
        return cur.fetchall()
    finally:
        close_connection(conn)


def get_detection_by_id(detection_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM detections WHERE id = ?;", (detection_id,))
        return cur.fetchone()
    finally:
        close_connection(conn)


def get_distinct_activities():
    """Return a list of distinct activity strings from the detections table, newest first."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT DISTINCT activity
            FROM detections
            WHERE activity IS NOT NULL AND activity != ''
            ORDER BY activity ASC;
        """)
        return [row[0] for row in cur.fetchall()]
    finally:
        close_connection(conn)


def get_detections_by_activity(activity: str, limit: int = 200):
    """
    Return all detection records matching the given activity string,
    newest first, joined with the latest alert status for each detection.
    """
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
            SELECT d.*,
                   (SELECT a.alert_status
                    FROM alerts a
                    WHERE a.detection_id = d.id
                    ORDER BY a.id DESC LIMIT 1) AS alert_status,
                   (SELECT a.sms_status
                    FROM alerts a
                    WHERE a.detection_id = d.id
                    ORDER BY a.id DESC LIMIT 1) AS sms_status
            FROM detections d
            WHERE d.activity = ?
            ORDER BY d.id DESC
            LIMIT ?;
        """, (activity, limit))
        return cur.fetchall()
    finally:
        close_connection(conn)


def get_detection_stats():
    """Summary statistics for the dashboard cards."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        stats = {}
        cur.execute("SELECT COUNT(*) FROM detections;")
        stats['total_detections'] = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM detections WHERE LOWER(activity) LIKE '%weapon%';")
        stats['total_weapon_detections'] = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM detections WHERE threat_level IN ('HIGH', 'CRITICAL');")
        stats['high_risk_events'] = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM alerts WHERE alert_status = 'SENT';")
        stats['alerts_sent'] = cur.fetchone()[0]
        
        return stats
    finally:
        close_connection(conn)


# ── Alert operations ──────────────────────────────────────────────────────────

def save_alert(detection_id, message, alert_status="PENDING", sms_status="NOT_CONFIGURED"):
    """Persist an alert notification record. Returns new alert id."""
    conn = get_db_connection()
    try:
        with conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO alerts (detection_id, message, alert_status, sms_status)
                VALUES (?, ?, ?, ?);
            """, (detection_id, message, alert_status, sms_status))
            return cur.lastrowid
    finally:
        close_connection(conn)


def get_alerts(limit=50, status=None):
    """Retrieve alert records joined with detection data, newest first."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        query = """
            SELECT a.id          AS id,
                   a.alert_status,
                   a.sms_status,
                   a.sent_at,
                   d.threat_level, d.threat_score, d.activity,
                   d.screenshot_path, d.date, d.time
            FROM alerts a
            LEFT JOIN detections d ON a.detection_id = d.id
            WHERE 1=1
        """
        params = []
        if status and status.upper() not in ("ALL", ""):
            query += " AND a.alert_status = ?"
            params.append(status.upper())
        query += " ORDER BY a.id DESC LIMIT ?;"
        params.append(limit)
        cur.execute(query, params)
        return cur.fetchall()
    finally:
        close_connection(conn)


def update_alert_status(alert_id, new_status):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "UPDATE alerts SET alert_status = ? WHERE id = ?;",
                (new_status, alert_id),
            )
            return True
    finally:
        close_connection(conn)


def acknowledge_detection(detection_id, status="acknowledged"):
    """Mark a detection as reviewed (used from alerts page)."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "UPDATE alerts SET alert_status = ? WHERE detection_id = ?;",
                (status, detection_id),
            )
            return True
    finally:
        close_connection(conn)


# ── System settings ───────────────────────────────────────────────────────────

def get_setting(key, default=None):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT value FROM system_settings WHERE key = ?;", (key,))
        row = cur.fetchone()
        return row[0] if row else default
    finally:
        close_connection(conn)


def set_setting(key, value, description=""):
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                INSERT INTO system_settings (key, value, description, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    description = COALESCE(excluded.description, system_settings.description),
                    updated_at = CURRENT_TIMESTAMP;
            """, (key, str(value), description))
            return True
    finally:
        close_connection(conn)


# ── Telemetry (kept for dashboard charts) ────────────────────────────────────

def log_detection_telemetry(person_count, weapon_count, threat_score, threat_level, fps):
    """Lightweight periodic telemetry — reuses detections table summary info."""
    pass  # Telemetry is now fully derived from the detections table


# Legacy compatibility shims (used by alerts.py process_incident)
def log_incident(activity, confidence, threat_score, threat_level,
                 screenshot_path="", details=None):
    """Shim: maps old log_incident() call to save_detection()."""
    objects = []
    if isinstance(details, dict):
        objects = details.get("contributing_factors", [])
    return save_detection(
        activity=activity,
        detected_objects=objects,
        confidence=confidence,
        threat_score=threat_score,
        threat_level=threat_level,
        screenshot_path=screenshot_path,
    )


def get_incidents(limit=50, offset=0, threat_level=None, status=None, search=None):
    """Shim: maps old get_incidents() to get_detection_history()."""
    return get_detection_history(limit=limit, offset=offset,
                                  threat_level=threat_level, search=search)


def get_incident_by_id(detection_id):
    """Shim: maps old get_incident_by_id() to get_detection_by_id()."""
    return get_detection_by_id(detection_id)


def get_incident_stats():
    """Shim: maps old get_incident_stats() to get_detection_stats()."""
    return get_detection_stats()


def update_incident_status(incident_id, status, notes=None, user=None):
    """Shim: acknowledge detection and related alerts."""
    return acknowledge_detection(incident_id, status)
