"""
Sentinel Watch - Main Flask Application and Real-Time Detection Pipeline.
Removed: object tracking, behaviour analysis, activity detection.
Focus: weapon detection, threat scoring, alerting, dashboard, reports.
"""

import os
import cv2
import time
import json
import logging
import threading
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, render_template, Response, request, jsonify,
    redirect, url_for, send_from_directory, flash, session, g,
)

from config import Config
import database
from auth import auth_bp, login_required, admin_required
from camera import CameraManager
from detect import ObjectDetector
from threat import ThreatEvaluator
from alerts import AlertManager
import reports

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(Config.LOGS_DIR / "sentinelwatch.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("sentinel.app")

# Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = Config.SECRET_KEY
app.register_blueprint(auth_bp, url_prefix="/auth")

# Core services
database.init_db()
camera_manager   = CameraManager()
detector         = ObjectDetector()
threat_evaluator = ThreatEvaluator()
alert_manager    = AlertManager()

# Thread-safe AI telemetry
ai_state = {
    "fps": 0.0,
    "total_persons": 0,
    "total_weapons": 0,
    "scene_label": "System Initializing",
    "threat": {
        "threat_score": 0,
        "threat_level": "LOW",
        "confidence": 0.0,
        "contributing_factors": ["System starting up"],
    },
    "is_custom_model_loaded": detector.is_custom_model_loaded,
    "model_warning": detector.model_warning,
    "weapons_pending": 0,
    "last_processed_time": time.time(),
}
ai_state_lock = threading.Lock()


def ai_processing_worker():
    """Background worker: detect weapons/persons, score threats, annotate, alert."""
    global ai_state
    logger.info("AI Processing Worker started.")
    last_telemetry_log = 0.0

    while True:
        try:
            frame, is_online = camera_manager.get_raw_frame()

            if not is_online or frame is None or frame.size == 0:
                with ai_state_lock:
                    ai_state.update({
                        "total_persons": 0,
                        "total_weapons": 0,
                        "scene_label": "Camera Offline - Reconnecting",
                        "threat": {
                            "threat_score": 0, "threat_level": "LOW",
                            "confidence": 0.0,
                            "contributing_factors": ["Camera stream unreachable"],
                        },
                    })
                time.sleep(0.1)
                continue

            t_start = time.time()

            # ── 1. YOLO detection + annotation (all drawing done in detect.py) ──
            detections = detector.detect(frame)
            persons          = detections["persons"]
            weapons          = detections["weapons"]           # confirmed weapons
            weapons_pending  = detections.get("weapons_pending", [])
            annotated        = detections["annotated_frame"]   # already has boxes drawn

            # ── 2. Threat scoring ──────────────────────────────────────────────
            threat = threat_evaluator.evaluate(persons, weapons)

            # ── 3. Build HUD text and pass overlay to camera manager ──────────
            #    Drawing happens inside get_stream_jpeg() on the newest raw frame.
            #    This ensures the video stream is never blocked waiting for YOLO.
            color_map = {
                "LOW":      (0, 200, 0),
                "MEDIUM":   (0, 200, 255),
                "HIGH":     (0, 100, 255),
                "CRITICAL": (0, 0, 255),
            }
            hud_color = color_map.get(threat["threat_level"], (0, 200, 0))
            banner = (
                "THREAT: " + threat["threat_level"] +
                "  SCORE: " + str(threat["threat_score"]) + "/100  |  " +
                threat["scene_label"]
            )
            camera_manager.update_overlay(
                persons=persons,
                weapons=weapons,
                weapons_pending=weapons_pending,
                banner_text=banner,
                banner_color=hud_color,
            )

            # ── 4. Alert: fire for ANY confirmed weapon (all threat levels) ────
            #    AlertManager handles the 20-second interval internally and
            #    tracks whether this is a new event or the same ongoing threat.
            if weapons:
                alert_manager.process_incident(
                    frame_to_save=annotated,
                    activity=threat["scene_label"],
                    confidence=threat["confidence"],
                    threat_score=threat["threat_score"],
                    threat_level=threat["threat_level"],
                    contributing_factors=threat["contributing_factors"],
                    weapons=weapons,
                )
            else:
                # No confirmed weapon — end any in-progress threat event so the
                # next weapon appearance starts a fresh alert cycle immediately.
                alert_manager.clear_threat()

            # ── 5. Telemetry ───────────────────────────────────────────────────
            dt       = time.time() - t_start
            inst_fps = 1.0 / max(dt, 0.001)
            with ai_state_lock:
                ai_state["fps"]                    = round(0.9 * ai_state["fps"] + 0.1 * inst_fps, 1)
                ai_state["total_persons"]           = len(persons)
                ai_state["total_weapons"]           = len(weapons)
                ai_state["weapons_pending"]         = len(weapons_pending)
                ai_state["scene_label"]             = threat["scene_label"]
                ai_state["threat"]                  = threat
                ai_state["is_custom_model_loaded"]  = detector.is_custom_model_loaded
                ai_state["model_warning"]           = detector.model_warning
                ai_state["last_processed_time"]     = time.time()

            if time.time() - last_telemetry_log > 10.0:
                database.log_detection_telemetry(
                    person_count=len(persons), weapon_count=len(weapons),
                    threat_score=threat["threat_score"],
                    threat_level=threat["threat_level"], fps=ai_state["fps"],
                )
                last_telemetry_log = time.time()

            time.sleep(0.01)

        except Exception as exc:
            logger.error("AI worker error: %s", exc, exc_info=True)
            time.sleep(0.5)



camera_manager.start()
ai_thread = threading.Thread(target=ai_processing_worker, name="AIWorker", daemon=True)
ai_thread.start()


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("auth.login"))


@app.route("/dashboard")
@login_required
def dashboard():
    stats            = database.get_incident_stats()
    recent_incidents = database.get_incidents(limit=6)
    return render_template("dashboard.html", stats=stats, recent_incidents=recent_incidents)


@app.route("/history")
@login_required
def history():
    threat_level = request.args.get("threat_level", "ALL")
    status       = request.args.get("status", "ALL")
    search       = request.args.get("search", "").strip()
    incidents    = database.get_incidents(limit=100, threat_level=threat_level,
                                          status=status, search=search)
    return render_template("history.html", incidents=incidents)


@app.route("/alerts")
@login_required
def alerts():
    status_filter = request.args.get("status", "").strip().upper()
    alert_rows = database.get_alerts(
        limit=100,
        status=status_filter if status_filter else None,
    )
    return render_template(
        "alerts.html",
        alerts=alert_rows,
        status_filter=status_filter,
    )


@app.route("/reports", methods=["GET"])
@app.route("/reports/<int:incident_id>", methods=["GET"])
@admin_required
def reports_view(incident_id=None):
    selected_incident = database.get_incident_by_id(incident_id) if incident_id else None
    # Load distinct activities from DB for the dropdown
    activities = database.get_distinct_activities()
    selected_activity = request.args.get("activity", "").strip()

    generated = []
    if Config.REPORTS_DIR.exists():
        for p in sorted(Config.REPORTS_DIR.glob("*.pdf"), key=os.path.getmtime, reverse=True):
            stat = p.stat()
            generated.append({
                "name": p.name,
                "size_kb": round(stat.st_size / 1024, 1),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
            })
    return render_template(
        "report.html",
        selected_incident=selected_incident,
        generated_reports=generated,
        activities=activities,
        selected_activity=selected_activity,
    )


@app.route("/reports/download/activity", methods=["POST"])
@admin_required
def download_activity_pdf():
    """Generate and download a PDF for all detections of a given activity."""
    activity = request.form.get("activity", "").strip()
    if not activity:
        flash("Please select an activity before downloading.", "warning")
        return redirect(url_for("reports_view"))
    try:
        user_name = session.get("full_name", session.get("username", "Security Officer"))
        pdf_path  = reports.generate_activity_pdf(activity, generated_by=user_name)
        return send_from_directory(
            Config.REPORTS_DIR,
            pdf_path.name,
            as_attachment=True,
            download_name=pdf_path.name,
        )
    except ValueError as ve:
        # No records — stay on page with a clear message
        flash(str(ve), "warning")
        return redirect(url_for("reports_view") + f"?activity={activity}")
    except Exception as exc:
        logger.error("Activity PDF generation failed for %r: %s", activity, exc)
        flash("Report generation failed: " + str(exc), "danger")
        return redirect(url_for("reports_view") + f"?activity={activity}")


@app.route("/reports/download/<int:incident_id>")
@admin_required
def download_incident_pdf(incident_id):
    try:
        user_name = session.get("full_name", session.get("username", "Security Officer"))
        pdf_path  = reports.generate_incident_pdf(incident_id, generated_by=user_name)
        return send_from_directory(Config.REPORTS_DIR, pdf_path.name,
                                   as_attachment=True, download_name=pdf_path.name)
    except Exception as exc:
        logger.error("PDF generation failed #%s: %s", incident_id, exc)
        flash("Error generating PDF report: " + str(exc), "danger")
        return redirect(url_for("reports_view", incident_id=incident_id))


@app.route("/reports/<filename>")
@admin_required
def serve_report_file(filename):
    return send_from_directory(Config.REPORTS_DIR, filename)


@app.route("/screenshots/<filename>")
@login_required
def serve_screenshot_file(filename):
    return send_from_directory(Config.SCREENSHOTS_DIR, filename)


def generate_video_stream():
    while True:
        frame_bytes = camera_manager.get_stream_jpeg()
        if frame_bytes:
            yield b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + frame_bytes + b"\r\n"
        time.sleep(0.04)


@app.route("/video_feed")
def video_feed():
    return Response(generate_video_stream(),
                    mimetype="multipart/x-mixed-replace; boundary=frame")


@app.route("/api/live_status")
def api_live_status():
    cam = camera_manager.get_telemetry()
    with ai_state_lock:
        state = dict(ai_state)
    state["camera"] = cam
    return jsonify(state)


@app.route("/api/update_camera", methods=["POST"])
@login_required
def api_update_camera():
    data    = request.get_json(silent=True) or request.form
    new_url = data.get("camera_url", "").strip()
    if not new_url:
        return jsonify({"status": "error", "message": "Camera URL cannot be empty."}), 400
    success, message = camera_manager.set_camera_url(new_url)
    return jsonify({"status": "success" if success else "error",
                    "message": message, "active_url": new_url})


@app.route("/api/reload_model", methods=["POST"])
@login_required
def api_reload_model():
    loaded, warning = detector.reload_custom_model()
    with ai_state_lock:
        ai_state["is_custom_model_loaded"] = loaded
        ai_state["model_warning"]          = warning
    if loaded:
        return jsonify({"status": "success", "message": "Custom weapon model loaded."})
    return jsonify({"status": "notice", "message": warning})


@app.route("/api/acknowledge_alert/<int:incident_id>", methods=["POST"])
@login_required
def api_acknowledge_alert(incident_id):
    status = request.form.get("status", "acknowledged")
    notes  = request.form.get("notes", "").strip()
    user   = session.get("full_name", session.get("username", "Officer"))
    database.update_incident_status(incident_id, status, notes or None, user)
    flash("Incident #" + str(incident_id) + " marked as " + status.upper() + ".", "success")
    return redirect(request.referrer or url_for("alerts"))


if __name__ == "__main__":
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG, threaded=True)
