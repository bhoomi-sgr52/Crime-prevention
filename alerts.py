"""
Sentinel Watch - Alert and Evidence Module
===========================================

Alert behaviour
---------------
* ALL confirmed weapon threats (LOW / MEDIUM / HIGH / CRITICAL) send a
  Pushbullet notification. Pushbullet is the ONLY notification channel.

* First detection of a weapon  -> immediate screenshot + Pushbullet.
* Same weapon still visible    -> one repeat every ALERT_INTERVAL_SECONDS.
* Weapon disappears            -> threat event ends; no further alerts.
* Weapon re-appears later      -> treated as a brand-new event.

Timer note
----------
The interval is checked by comparing wall-clock timestamps only. No sleep()
is used, so camera capture and YOLO inference are never blocked.

If Pushbullet is not configured (token missing) or fails, SentinelWatch
continues monitoring and recording detections normally.
"""

import cv2
import time
import os
import logging
import requests
from datetime import datetime

from config import Config
import database


logger = logging.getLogger("sentinel.alerts")


# ============================================================
# Threat level emoji
# ============================================================

_LEVEL_EMOJI = {
    "LOW":      "\U0001f7e2",
    "MEDIUM":   "\U0001f7e1",
    "HIGH":     "\U0001f7e0",
    "CRITICAL": "\U0001f534",
}


# ============================================================
# Weapon disappearance grace period
# ============================================================

WEAPON_GONE_GRACE = 3.0


class AlertManager:
    """
    Manages:

    1. Screenshot capture
    2. SQLite detection records
    3. Pushbullet notifications
    4. Pushbullet screenshot attachments
    5. Threat-event timing
    """

    def __init__(self):

        # ====================================================
        # Alert interval
        # ====================================================

        self.alert_interval: int = int(
            os.getenv("ALERT_INTERVAL_SECONDS")
            or os.getenv("ALERT_COOLDOWN_SECONDS")
            or 20
        )

        # ====================================================
        # Ongoing threat state
        # ====================================================

        self._threat_active: bool = False

        self._current_weapon_key: frozenset = frozenset()

        self._last_alert_time: float = 0.0

        # ====================================================
        # Weapon disappearance timer
        # ====================================================

        self._weapon_gone_since: float = 0.0


    # ========================================================
    # PUBLIC API
    # ========================================================

    def process_incident(
        self,
        frame_to_save,
        activity: str,
        confidence: float,
        threat_score: int,
        threat_level: str,
        contributing_factors=None,
        weapons=None,
    ):
        """
        Called by ai_processing_worker() whenever at least one
        confirmed weapon is detected.

        Sends an alert when:

        1. A new weapon event starts
        OR
        2. The alert interval has elapsed.

        Returns:
            detection_id
            or None when no new alert is fired.
        """

        now = time.time()

        # ----------------------------------------------------
        # Weapon is visible again.
        # Cancel any pending clear timer.
        # ----------------------------------------------------

        self._weapon_gone_since = 0.0

        # ----------------------------------------------------
        # Create a unique key based on detected weapon names.
        # ----------------------------------------------------

        weapon_key = self._make_weapon_key(
            weapons or []
        )

        # ----------------------------------------------------
        # Determine whether this is a new event.
        # ----------------------------------------------------

        is_new_event = (
            not self._threat_active
            or weapon_key != self._current_weapon_key
        )

        # ----------------------------------------------------
        # Check whether the alert interval has elapsed.
        # ----------------------------------------------------

        interval_elapsed = (
            now - self._last_alert_time
        ) >= self.alert_interval

        # ----------------------------------------------------
        # Existing threat + interval not reached
        # ----------------------------------------------------

        if not is_new_event and not interval_elapsed:
            return None

        # ====================================================
        # UPDATE THREAT STATE
        # ====================================================

        self._threat_active = True

        self._current_weapon_key = weapon_key

        self._last_alert_time = now

        # ====================================================
        # 1. SAVE SCREENSHOT
        # ====================================================

        screenshot_rel = self._save_screenshot(
            frame_to_save
        )

        # ====================================================
        # 2. SAVE DETECTION TO SQLITE
        # ====================================================

        det_id = self._save_detection(
            activity=activity,
            contributing_factors=contributing_factors or [],
            confidence=confidence,
            threat_score=threat_score,
            threat_level=threat_level,
            screenshot_path=screenshot_rel,
        )

        # ----------------------------------------------------
        # If database insertion failed, stop this alert cycle.
        # ----------------------------------------------------

        if det_id is None:
            return None

        # ====================================================
        # 3. BUILD PUSHBULLET MESSAGE
        # ====================================================

        ts_now = datetime.now()

        date_str = ts_now.strftime(
            "%d-%m-%Y"
        )

        time_str = ts_now.strftime(
            "%H:%M:%S"
        )

        conf_pct = int(
            round(confidence * 100)
        )

        # ----------------------------------------------------
        # Weapon names
        # ----------------------------------------------------

        weapon_names = (
            ", ".join(
                sorted(
                    set(
                        w["class"].upper()
                        for w in (weapons or [])
                    )
                )
            )
            if weapons
            else "N/A"
        )

        # ----------------------------------------------------
        # Contributing factors
        # ----------------------------------------------------

        factors_text = (
            "\n".join(
                f"  - {f}"
                for f in (contributing_factors or [])
            )
            or "  N/A"
        )

        # ----------------------------------------------------
        # Threat emoji
        # ----------------------------------------------------

        emoji = _LEVEL_EMOJI.get(
            threat_level,
            "\u26a0\ufe0f"
        )

        title = (
            f"{emoji} SENTINEL WATCH - "
            f"{threat_level} THREAT"
        )

        # ----------------------------------------------------
        # Pushbullet body
        # ----------------------------------------------------

        body = (
            "\U0001f6a8 SENTINEL WATCH SECURITY ALERT\n"
            "==============================\n\n"

            f"Threat Level:     {threat_level}\n"
            f"Threat Score:     {threat_score}/100\n\n"

            f"Activity:         {activity}\n"

            f"Detected Objects:\n"
            f"{factors_text}\n"

            f"Weapon:           {weapon_names}\n\n"

            f"Confidence:       {conf_pct}%\n\n"

            f"Date:             {date_str}\n"
            f"Time:             {time_str}\n\n"

            "Potential Security Threat Detected.\n"
            "Please check the SentinelWatch live camera."
        )

        # ====================================================
        # 4. SEND PUSHBULLET
        #    INCLUDING SCREENSHOT
        # ====================================================

        pb_status = self._send_pushbullet(
            title,
            body,
            screenshot_rel
        )

        # ====================================================
        # 5. SAVE ALERT STATUS TO DATABASE
        # ====================================================

        try:

            database.save_alert(
                det_id,
                body,
                alert_status=pb_status,
            )

        except Exception as exc:

            logger.error(
                "Failed to save alert status to DB: %s",
                exc
            )

        return det_id


    # ========================================================
    # CLEAR THREAT
    # ========================================================

    def clear_threat(self):
        """
        Called when no confirmed weapon is visible.

        The threat is not immediately cleared.

        Instead, a short grace period is used to prevent
        YOLO detection flickering from creating multiple
        unnecessary alert events.
        """

        # ----------------------------------------------------
        # No active threat
        # ----------------------------------------------------

        if not self._threat_active:

            self._weapon_gone_since = 0.0

            return

        now = time.time()

        # ----------------------------------------------------
        # Start disappearance timer
        # ----------------------------------------------------

        if self._weapon_gone_since == 0.0:

            self._weapon_gone_since = now

            return

        # ----------------------------------------------------
        # Grace period not finished
        # ----------------------------------------------------

        if (
            now - self._weapon_gone_since
        ) < WEAPON_GONE_GRACE:

            return

        # ====================================================
        # Threat event ended
        # ====================================================

        logger.info(
            "Threat event ended "
            "(weapon absent for %.1fs). "
            "Next weapon detection will start "
            "a new alert cycle.",
            WEAPON_GONE_GRACE,
        )

        self._threat_active = False

        self._current_weapon_key = frozenset()

        self._weapon_gone_since = 0.0


    # ========================================================
    # PRIVATE HELPERS
    # ========================================================

    @staticmethod
    def _make_weapon_key(
        weapons: list
    ) -> frozenset:

        return frozenset(
            w["class"].upper()
            for w in weapons
        )


    # ========================================================
    # SAVE SCREENSHOT
    # ========================================================

    @staticmethod
    def _save_screenshot(frame) -> str:
        """
        Save the incident screenshot.

        Returns:
            Relative path such as:

            screenshots/incident_2026-09-24_203015_123456.jpg
        """

        # ----------------------------------------------------
        # Validate frame
        # ----------------------------------------------------

        if (
            frame is None
            or getattr(frame, "size", 0) == 0
        ):

            logger.warning(
                "Cannot save screenshot: empty frame."
            )

            return ""

        # ----------------------------------------------------
        # Create unique timestamp.
        # ----------------------------------------------------

        file_ts = datetime.now().strftime(
            "%Y-%m-%d_%H%M%S_%f"
        )

        fname = (
            f"incident_{file_ts}.jpg"
        )

        full_path = (
            Config.SCREENSHOTS_DIR / fname
        )

        try:

            # ------------------------------------------------
            # Make sure screenshot directory exists.
            # ------------------------------------------------

            Config.SCREENSHOTS_DIR.mkdir(
                parents=True,
                exist_ok=True
            )

            # ------------------------------------------------
            # Write image
            # ------------------------------------------------

            success = cv2.imwrite(
                str(full_path),
                frame
            )

            # ------------------------------------------------
            # Verify image was actually written.
            # ------------------------------------------------

            if (
                not success
                or not full_path.exists()
            ):

                logger.error(
                    "Failed to write screenshot: %s",
                    full_path
                )

                return ""

            logger.info(
                "Evidence screenshot saved: %s",
                full_path
            )

            # ------------------------------------------------
            # Relative path stored in SQLite
            # ------------------------------------------------

            return (
                f"screenshots/{fname}"
            )

        except Exception as exc:

            logger.error(
                "Failed to save screenshot: %s",
                exc
            )

            return ""


    # ========================================================
    # SAVE DETECTION
    # ========================================================

    @staticmethod
    def _save_detection(
        activity,
        contributing_factors,
        confidence,
        threat_score,
        threat_level,
        screenshot_path,
    ) -> "int | None":

        try:

            return database.save_detection(
                activity=activity,
                detected_objects=contributing_factors,
                confidence=confidence,
                threat_score=threat_score,
                threat_level=threat_level,
                screenshot_path=screenshot_path,
            )

        except Exception as exc:

            logger.error(
                "Failed to save detection "
                "to database: %s",
                exc
            )

            return None


    # ========================================================
    # SEND PUSHBULLET
    # ========================================================

    @staticmethod
    def _send_pushbullet(
        title: str,
        body: str,
        screenshot_rel: str = "",
    ) -> str:
        """
        Send Pushbullet notification.

        If screenshot exists:

            1. Request Pushbullet upload URL
            2. Upload screenshot
            3. Send a file-type Pushbullet notification

        If screenshot does not exist:

            Send a normal text notification.

        Returns:

            SENT
            FAILED
            NOT_CONFIGURED

        The Pushbullet token is never logged.
        """

        # ====================================================
        # GET PUSHBULLET TOKEN
        # ====================================================

        token = os.getenv(
            "PUSHBULLET_ACCESS_TOKEN",
            ""
        ).strip()

        # ----------------------------------------------------
        # Token missing
        # ----------------------------------------------------

        if not token:

            logger.warning(
                "PUSHBULLET_ACCESS_TOKEN not set "
                "in .env — Pushbullet notification skipped."
            )

            return "NOT_CONFIGURED"

        # ====================================================
        # COMMON HEADERS
        # ====================================================

        headers = {
            "Access-Token": token,
        }

        # ====================================================
        # FIND SCREENSHOT FILE
        # ====================================================

        screenshot_path = None

        if screenshot_rel:

            try:

                relative_path = (
                    screenshot_rel.replace(
                        "/",
                        os.sep
                    )
                )

                candidate = (
                    Config.BASE_DIR
                    / relative_path
                )

                if candidate.is_file():

                    screenshot_path = candidate

                else:

                    logger.warning(
                        "Screenshot not found "
                        "for Pushbullet attachment: %s",
                        candidate
                    )

            except Exception as exc:

                logger.warning(
                    "Could not resolve screenshot "
                    "path '%s': %s",
                    screenshot_rel,
                    exc
                )


        try:

            # ==================================================
            # CASE 1:
            # SCREENSHOT EXISTS
            # ==================================================

            if screenshot_path is not None:

                file_type = "image/jpeg"

                # ==============================================
                # STEP 1:
                # REQUEST PUSHBULLET UPLOAD URL
                # ==============================================

                upload_request = requests.post(

                    "https://api.pushbullet.com/v2/upload-request",

                    headers={
                        **headers,
                        "Content-Type":
                            "application/json",
                    },

                    json={
                        "file_name":
                            screenshot_path.name,

                        "file_type":
                            file_type,
                    },

                    timeout=10.0,
                )

                # ------------------------------------------------
                # Check upload-request response
                # ------------------------------------------------

                if upload_request.status_code != 200:

                    logger.error(
                        "Pushbullet upload request "
                        "failed: HTTP %s — %s",

                        upload_request.status_code,

                        upload_request.text[:200],
                    )

                    return "FAILED"

                # ------------------------------------------------
                # Convert response to JSON
                # ------------------------------------------------

                upload_info = (
                    upload_request.json()
                )

                upload_url = (
                    upload_info.get(
                        "upload_url"
                    )
                )

                upload_data = (
                    upload_info.get(
                        "data"
                    )
                )

                file_url = (
                    upload_info.get(
                        "file_url"
                    )
                )

                # ------------------------------------------------
                # Make sure Pushbullet returned everything.
                # ------------------------------------------------

                if (
                    not upload_url
                    or not upload_data
                    or not file_url
                ):

                    logger.error(
                        "Pushbullet upload request "
                        "returned incomplete data."
                    )

                    return "FAILED"


                # ==============================================
                # STEP 2:
                # UPLOAD SCREENSHOT
                # ==============================================

                with screenshot_path.open(
                    "rb"
                ) as image_file:

                    upload_response = requests.post(

                        upload_url,

                        data=upload_data,

                        files={
                            "file": (
                                screenshot_path.name,
                                image_file,
                                file_type,
                            )
                        },

                        timeout=15.0,
                    )

                # ------------------------------------------------
                # IMPORTANT:
                #
                # Pushbullet returns HTTP 204 when the file
                # upload succeeds.
                #
                # Your previous code rejected 204 and treated
                # it as an error.
                # ------------------------------------------------

                if upload_response.status_code not in (
                    200,
                    201,
                    204,
                ):

                    logger.error(
                        "Pushbullet screenshot upload "
                        "failed: HTTP %s — %s",

                        upload_response.status_code,

                        upload_response.text[:200],
                    )

                    return "FAILED"

                logger.info(
                    "Pushbullet screenshot uploaded successfully."
                )


                # ==============================================
                # STEP 3:
                # SEND FILE PUSH
                # ==============================================

                response = requests.post(

                    "https://api.pushbullet.com/v2/pushes",

                    headers={
                        **headers,
                        "Content-Type":
                            "application/json",
                    },

                    json={

                        "type": "file",

                        "file_name":
                            screenshot_path.name,

                        "file_type":
                            file_type,

                        "file_url":
                            file_url,

                        "title":
                            title,

                        "body":
                            body,
                    },

                    timeout=10.0,
                )


            # ==================================================
            # CASE 2:
            # SCREENSHOT NOT AVAILABLE
            # ==================================================

            else:

                logger.warning(
                    "Screenshot unavailable. "
                    "Sending text-only Pushbullet alert."
                )

                response = requests.post(

                    "https://api.pushbullet.com/v2/pushes",

                    headers={
                        **headers,
                        "Content-Type":
                            "application/json",
                    },

                    json={
                        "type": "note",

                        "title":
                            title,

                        "body":
                            body,
                    },

                    timeout=6.0,
                )


            # ==================================================
            # CHECK FINAL PUSHBULLET RESPONSE
            # ==================================================

            if response.status_code == 200:

                # ------------------------------------------------
                # Screenshot notification
                # ------------------------------------------------

                if screenshot_path is not None:

                    logger.info(
                        "Pushbullet notification WITH "
                        "screenshot sent: %s",
                        title
                    )

                # ------------------------------------------------
                # Text fallback
                # ------------------------------------------------

                else:

                    logger.info(
                        "Pushbullet text notification sent: %s",
                        title
                    )

                return "SENT"


            # ==================================================
            # PUSHBULLET ERROR
            # ==================================================

            logger.error(
                "Pushbullet HTTP %s — "
                "notification not delivered: %s",

                response.status_code,

                response.text[:160],
            )

            return "FAILED"


        # ======================================================
        # NETWORK / OTHER ERROR
        # ======================================================

        except Exception as exc:

            logger.error(
                "Pushbullet connection/upload error: %s",
                exc
            )

            return "FAILED"