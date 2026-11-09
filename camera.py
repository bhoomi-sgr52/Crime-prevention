"""
Sentinel Watch - Camera Stream Manager
=======================================
Single Android smartphone IP camera source over HTTP/MJPEG.

Configuration
-------------
Set CAMERA_URL in .env:

    CAMERA_URL=http://172.16.1.24:8080/video

Camera URL priority:
    1. .env CAMERA_URL
    2. constructor-provided stream_url
    3. system_settings database value
    4. Config.DEFAULT_CAMERA_URL fallback

The .env value is given highest priority so that changing the
phone's IP address does not get overridden by an old value stored
in the SQLite database.

Design
------
- One background thread owns the single VideoCapture object.
- Failed reads trigger automatic reconnection with capped exponential backoff.
- Stale-frame detection marks the stream OFFLINE if no new frame arrives
  within STALE_FRAME_TIMEOUT seconds.
- The AI worker calls get_raw_frame() and updates the latest AI overlay.
- Flask /video_feed calls get_stream_jpeg() to encode the newest frame.
- If offline, a high-visibility "CAMERA OFFLINE" placeholder is returned.
"""

import os
import cv2
import time
import threading
import logging
import numpy as np

from datetime import datetime

from config import Config
import database


logger = logging.getLogger("sentinel.camera")


# ---------------------------------------------------------------------------
# Camera configuration
# ---------------------------------------------------------------------------

# Maximum seconds without a new frame before marking stream OFFLINE
STALE_FRAME_TIMEOUT = 8.0

# Reconnection backoff
INITIAL_BACKOFF = 1.0
MAX_BACKOFF = 10.0

# JPEG quality
JPEG_QUALITY = 82

# Keep only the latest frame in OpenCV buffer
FRAME_BUFFER_SIZE = 1


class CameraManager:
    """
    Manages the single Android smartphone IP camera stream.

    Only ONE instance should exist per application process.
    All public methods are thread-safe.
    """

    def __init__(self, stream_url: str = None):

        # -------------------------------------------------------------------
        # CAMERA URL PRIORITY
        #
        # 1. .env CAMERA_URL
        # 2. Constructor URL
        # 3. Database URL
        # 4. Config default
        #
        # This prevents an old IP stored in SQLite from overriding
        # the new IP specified in .env.
        # -------------------------------------------------------------------

        env_url = os.getenv("CAMERA_URL", "").strip()

        # Read database setting safely
        saved_url = None

        try:
            if Config.DATABASE_PATH.exists():
                saved_url = database.get_setting("camera_url")

                if saved_url:
                    saved_url = str(saved_url).strip()

        except Exception as exc:
            logger.warning(
                "Could not read camera URL from database: %s",
                exc
            )
            saved_url = None

        # Final URL selection
        self.stream_url: str = (
            env_url
            or (str(stream_url).strip() if stream_url else "")
            or saved_url
            or str(Config.DEFAULT_CAMERA_URL).strip()
        )

        logger.info(
            "Camera URL selected: %s",
            self.stream_url
        )

        # -------------------------------------------------------------------
        # Internal state
        # -------------------------------------------------------------------

        self._lock = threading.Lock()

        # OpenCV VideoCapture object
        self._cap = None

        # Latest raw BGR frame
        self._last_frame = None

        # Kept for API compatibility
        self._annotated_frame = None

        # Camera status
        self._is_online = False
        self._is_running = False

        # Human-readable status
        self._status_message = "Not started"

        # Time of last successful frame
        self._last_frame_time = 0.0

        # FPS calculation
        self._fps = 0.0

        # Statistics
        self._frame_count = 0
        self._reconnect_count = 0

        # Background thread
        self._thread = None

        # -------------------------------------------------------------------
        # Latest AI overlay
        # -------------------------------------------------------------------

        self._latest_overlay = {
            "persons": [],
            "weapons": [],
            "weapons_pending": [],
            "banner_text": "",
            "banner_color": (0, 200, 0),
        }

    # =======================================================================
    # Lifecycle
    # =======================================================================

    def start(self):
        """
        Start the background capture thread.
        Call this once when the application starts.
        """

        with self._lock:

            if self._is_running:

                logger.warning(
                    "CameraManager.start() called but already running."
                )

                return

            self._is_running = True

        self._thread = threading.Thread(
            target=self._capture_loop,
            name="CameraWorker",
            daemon=True,
        )

        self._thread.start()

        logger.info(
            "Camera manager started | stream: %s",
            self.stream_url
        )

    # -----------------------------------------------------------------------

    def stop(self):
        """
        Gracefully stop the camera capture thread.
        """

        with self._lock:
            self._is_running = False

        if self._thread and self._thread.is_alive():

            self._thread.join(timeout=3.0)

        self._release_capture()

        logger.info("Camera manager stopped.")

    # =======================================================================
    # Runtime URL change
    # =======================================================================

    def set_camera_url(self, new_url: str):
        """
        Update the camera URL at runtime.

        The new URL is also stored in the database.

        NOTE:
        The .env CAMERA_URL still has higher priority after a restart.
        This is intentional so the .env file remains the main source
        for changing the phone IP.
        """

        new_url = str(new_url).strip()

        if not new_url:

            return False, "Camera URL cannot be empty."

        if not (
            new_url.startswith("http://")
            or new_url.startswith("https://")
            or new_url.startswith("rtsp://")
            or new_url.isdigit()
        ):

            return (
                False,
                "URL must start with http://, https://, rtsp://, "
                "or be a webcam index."
            )

        # Update current running URL
        with self._lock:

            self.stream_url = new_url

            self._is_online = False

            self._status_message = (
                "Switching to new camera stream..."
            )

            # Drop current connection
            self._release_capture_unsafe()

        # Save to database
        try:

            database.set_setting(
                "camera_url",
                new_url,
                "User-updated camera stream URL"
            )

        except Exception as exc:

            logger.error(
                "Could not persist camera URL to database: %s",
                exc
            )

        logger.info(
            "Camera URL updated to: %s",
            new_url
        )

        return (
            True,
            "Camera URL updated. Reconnecting..."
        )

    # =======================================================================
    # Frame access
    # =======================================================================

    def get_raw_frame(self):
        """
        Return:

            (frame, is_online)

        If the camera is offline, an offline placeholder frame is returned.
        """

        with self._lock:

            stale = (
                self._last_frame_time > 0
                and (
                    time.monotonic()
                    - self._last_frame_time
                ) > STALE_FRAME_TIMEOUT
            )

            if stale and self._is_online:

                self._is_online = False

                self._status_message = (
                    "Stream stalled — reconnecting..."
                )

                logger.warning(
                    "Stale frame detected — marking camera OFFLINE."
                )

                self._release_capture_unsafe()

            if (
                self._is_online
                and self._last_frame is not None
            ):

                return (
                    self._last_frame.copy(),
                    True
                )

        return (
            self._build_offline_frame(),
            False
        )

    # -----------------------------------------------------------------------

    def update_annotated_frame(self, frame: np.ndarray):
        """
        Kept for API compatibility.

        The current architecture draws AI overlays on the newest raw frame
        inside get_stream_jpeg().
        """

        pass

    # =======================================================================
    # AI overlay
    # =======================================================================

    def update_overlay(
        self,
        persons: list,
        weapons: list,
        weapons_pending: list,
        banner_text: str,
        banner_color: tuple,
    ):
        """
        Store the latest AI detection results.

        Called by ai_processing_worker() after YOLO inference.
        """

        with self._lock:

            self._latest_overlay = {

                "persons": persons,

                "weapons": weapons,

                "weapons_pending": weapons_pending,

                "banner_text": banner_text,

                "banner_color": banner_color,
            }

    # =======================================================================
    # MJPEG stream
    # =======================================================================

    def get_stream_jpeg(self) -> bytes | None:
        """
        Encode the newest raw camera frame to JPEG.

        Latest AI detection overlays are drawn on the frame.

        If camera is offline, an offline placeholder is returned.
        """

        # ---------------------------------------------------------------
        # Get newest raw frame
        # ---------------------------------------------------------------

        with self._lock:

            if (
                self._is_online
                and self._last_frame is not None
            ):

                raw = self._last_frame.copy()

            else:

                raw = None

            overlay = dict(
                self._latest_overlay
            )

        # ---------------------------------------------------------------
        # Offline frame
        # ---------------------------------------------------------------

        if raw is None:

            raw = self._build_offline_frame()

            ok, buf = cv2.imencode(
                ".jpg",
                raw,
                [
                    int(
                        cv2.IMWRITE_JPEG_QUALITY
                    ),
                    JPEG_QUALITY
                ],
            )

            return (
                buf.tobytes()
                if ok
                else None
            )

        # ---------------------------------------------------------------
        # Draw person boxes
        # ---------------------------------------------------------------

        for det in overlay.get("persons", []):

            x1, y1, x2, y2 = det["box"]

            label = "{} {:.0f}%".format(
                "Person",
                det["confidence"] * 100
            )

            cv2.rectangle(
                raw,
                (x1, y1),
                (x2, y2),
                (0, 220, 0),
                2
            )

            cv2.putText(
                raw,
                label,
                (x1, max(y1 - 5, 14)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                (0, 220, 0),
                2,
                cv2.LINE_AA
            )

        # ---------------------------------------------------------------
        # Draw pending weapon boxes
        # ---------------------------------------------------------------

        for det in overlay.get(
            "weapons_pending",
            []
        ):

            x1, y1, x2, y2 = det["box"]

            label = "{}? {:.0f}%".format(
                det["class"],
                det["confidence"] * 100
            )

            cv2.rectangle(
                raw,
                (x1, y1),
                (x2, y2),
                (0, 200, 255),
                2
            )

            cv2.putText(
                raw,
                label,
                (x1, max(y1 - 5, 14)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                (0, 200, 255),
                2,
                cv2.LINE_AA
            )

        # ---------------------------------------------------------------
        # Draw confirmed weapon boxes
        # ---------------------------------------------------------------

        for det in overlay.get(
            "weapons",
            []
        ):

            x1, y1, x2, y2 = det["box"]

            label = "{}! {:.0f}%".format(
                det["class"],
                det["confidence"] * 100
            )

            # Red corner bracket
            L = 18
            T = 3

            for (
                px,
                py,
                dx,
                dy
            ) in [

                (x1, y1, 1, 1),

                (x2, y1, -1, 1),

                (x1, y2, 1, -1),

                (x2, y2, -1, -1),

            ]:

                cv2.line(
                    raw,
                    (px, py),
                    (
                        px + dx * L,
                        py
                    ),
                    (0, 0, 255),
                    T
                )

                cv2.line(
                    raw,
                    (px, py),
                    (
                        px,
                        py + dy * L
                    ),
                    (0, 0, 255),
                    T
                )

            cv2.putText(
                raw,
                label,
                (x1, max(y1 - 5, 14)),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                (0, 0, 255),
                2,
                cv2.LINE_AA
            )

        # ---------------------------------------------------------------
        # HUD banner
        # ---------------------------------------------------------------

        banner = overlay.get(
            "banner_text",
            ""
        )

        if banner:

            color = overlay.get(
                "banner_color",
                (0, 200, 0)
            )

            cv2.rectangle(
                raw,
                (0, 0),
                (
                    raw.shape[1],
                    26
                ),
                (12, 18, 30),
                -1
            )

            cv2.putText(
                raw,
                banner,
                (8, 18),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.50,
                color,
                2,
                cv2.LINE_AA
            )

        # ---------------------------------------------------------------
        # JPEG encoding
        # ---------------------------------------------------------------

        ok, buf = cv2.imencode(
            ".jpg",
            raw,
            [
                int(
                    cv2.IMWRITE_JPEG_QUALITY
                ),
                JPEG_QUALITY
            ],
        )

        return (
            buf.tobytes()
            if ok
            else None
        )

    # =======================================================================
    # Telemetry
    # =======================================================================

    def get_telemetry(self) -> dict:
        """
        Return thread-safe camera status information.
        """

        with self._lock:

            last_seen = (

                datetime.fromtimestamp(
                    self._last_frame_time
                ).strftime("%H:%M:%S")

                if self._last_frame_time > 0

                else "Never"
            )

            return {

                "online":
                    self._is_online,

                "url":
                    self.stream_url,

                "fps":
                    round(
                        self._fps,
                        1
                    ),

                "status_message":
                    self._status_message,

                "frames_captured":
                    self._frame_count,

                "reconnect_count":
                    self._reconnect_count,

                "last_seen":
                    last_seen,
            }

    # =======================================================================
    # Internal helpers
    # =======================================================================

    def _release_capture_unsafe(self):
        """
        Release VideoCapture without acquiring the lock.

        Caller must already hold self._lock.
        """

        if self._cap is not None:

            try:

                self._cap.release()

            except Exception as exc:

                logger.debug(
                    "VideoCapture release warning: %s",
                    exc
                )

            self._cap = None

    # -----------------------------------------------------------------------

    def _release_capture(self):
        """
        Safely release VideoCapture.
        """

        with self._lock:

            self._release_capture_unsafe()

    # -----------------------------------------------------------------------

    def _open_capture(
        self,
        target
    ) -> cv2.VideoCapture | None:
        """
        Open a new VideoCapture.

        target can be:

            HTTP URL
            RTSP URL
            webcam index
        """

        try:

            backend = (
                cv2.CAP_FFMPEG
                if isinstance(target, str)
                else cv2.CAP_ANY
            )

            cap = cv2.VideoCapture(
                target,
                backend
            )

            if cap.isOpened():

                cap.set(
                    cv2.CAP_PROP_BUFFERSIZE,
                    FRAME_BUFFER_SIZE
                )

                return cap

            cap.release()

        except Exception as exc:

            logger.error(
                "VideoCapture open error (%s): %s",
                target,
                exc
            )

        return None

    # =======================================================================
    # Background capture loop
    # =======================================================================

    def _capture_loop(self):
        """
        Dedicated background camera thread.

        State machine:

            DISCONNECTED
                  ↓
              CONNECTING
                  ↓
              CONNECTED
                  ↓
             READ FRAMES
                  ↓
          connection failure
                  ↓
             RECONNECT
        """

        backoff = INITIAL_BACKOFF

        while True:

            # ---------------------------------------------------------------
            # Check whether camera manager is still running
            # ---------------------------------------------------------------

            with self._lock:

                if not self._is_running:

                    break

                url = self.stream_url

            # ---------------------------------------------------------------
            # Resolve target
            # ---------------------------------------------------------------

            target = (
                int(url)
                if (
                    isinstance(url, str)
                    and url.isdigit()
                )
                else url
            )

            # ---------------------------------------------------------------
            # Connect
            # ---------------------------------------------------------------

            logger.info(
                "Connecting to camera stream: %s",
                target
            )

            with self._lock:

                self._status_message = (
                    "Connecting to "
                    + str(target)
                    + "..."
                )

            cap = self._open_capture(
                target
            )

            # ---------------------------------------------------------------
            # Connection failed
            # ---------------------------------------------------------------

            if cap is None:

                with self._lock:

                    self._is_online = False

                    self._reconnect_count += 1

                    self._status_message = (
                        "Connection failed ("
                        + str(
                            self._reconnect_count
                        )
                        + " attempts) — retrying in "
                        + str(
                            int(backoff)
                        )
                        + "s"
                    )

                logger.warning(
                    "Could not connect to %s. Retry in %.1fs.",
                    target,
                    backoff
                )

                time.sleep(
                    backoff
                )

                backoff = min(
                    backoff * 2,
                    MAX_BACKOFF
                )

                continue

            # ---------------------------------------------------------------
            # Connected
            # ---------------------------------------------------------------

            logger.info(
                "Connected to camera stream: %s",
                target
            )

            backoff = INITIAL_BACKOFF

            with self._lock:

                self._cap = cap

            # ---------------------------------------------------------------
            # Read frames
            # ---------------------------------------------------------------

            while True:

                with self._lock:

                    if not self._is_running:

                        self._release_capture_unsafe()

                        return

                    # -------------------------------------------------------
                    # Detect runtime URL change
                    # -------------------------------------------------------

                    url_changed = (

                        isinstance(
                            target,
                            str
                        )
                        and target != self.stream_url

                    ) or (

                        isinstance(
                            target,
                            int
                        )
                        and str(target)
                        != self.stream_url
                    )

                    if url_changed:

                        logger.info(
                            "Camera URL changed — "
                            "dropping current connection."
                        )

                        self._release_capture_unsafe()

                        break

                    local_cap = self._cap

                # -----------------------------------------------------------
                # Capture object unavailable
                # -----------------------------------------------------------

                if local_cap is None:

                    break

                # -----------------------------------------------------------
                # Read frame
                # -----------------------------------------------------------

                ret, frame = local_cap.read()

                if (
                    ret
                    and frame is not None
                    and frame.size > 0
                ):

                    mono_now = time.monotonic()

                    with self._lock:

                        prev_t = (
                            self._last_frame_time
                        )

                        dt = (
                            mono_now - prev_t
                            if prev_t > 0
                            else 0.033
                        )

                        self._fps = (
                            0.9 * self._fps
                            + 0.1 * (
                                1.0
                                / max(
                                    dt,
                                    1e-4
                                )
                            )
                        )

                        self._last_frame_time = (
                            mono_now
                        )

                        self._frame_count += 1

                        self._is_online = True

                        self._status_message = (
                            "Online"
                        )

                        self._last_frame = frame

                    # Yield CPU briefly
                    time.sleep(0.005)

                else:

                    # -------------------------------------------------------
                    # Frame read failed
                    # -------------------------------------------------------

                    logger.warning(
                        "Frame read failed on %s — reconnecting.",
                        target
                    )

                    with self._lock:

                        self._is_online = False

                        self._reconnect_count += 1

                        self._status_message = (
                            "Stream lost — reconnecting..."
                        )

                        self._release_capture_unsafe()

                    break

            # ---------------------------------------------------------------
            # Brief pause before reconnect
            # ---------------------------------------------------------------

            time.sleep(
                min(
                    backoff,
                    2.0
                )
            )

            backoff = min(
                backoff * 1.5,
                MAX_BACKOFF
            )

    # =======================================================================
    # Offline frame
    # =======================================================================

    def _build_offline_frame(
        self,
        width: int = 640,
        height: int = 480
    ) -> np.ndarray:
        """
        Build a professional CAMERA OFFLINE frame.
        """

        img = np.zeros(
            (
                height,
                width,
                3
            ),
            dtype=np.uint8
        )

        img[:] = (
            18,
            22,
            32
        )

        # ---------------------------------------------------------------
        # Background grid
        # ---------------------------------------------------------------

        for x in range(
            0,
            width,
            40
        ):

            cv2.line(
                img,
                (x, 0),
                (x, height),
                (32, 40, 52),
                1
            )

        for y in range(
            0,
            height,
            40
        ):

            cv2.line(
                img,
                (0, y),
                (width, y),
                (32, 40, 52),
                1
            )

        # ---------------------------------------------------------------
        # Warning box
        # ---------------------------------------------------------------

        cx = width // 2
        cy = height // 2

        bw = 440
        bh = 170

        x1 = cx - bw // 2
        y1 = cy - bh // 2

        x2 = cx + bw // 2
        y2 = cy + bh // 2

        cv2.rectangle(
            img,
            (x1, y1),
            (x2, y2),
            (24, 30, 44),
            -1
        )

        cv2.rectangle(
            img,
            (x1, y1),
            (x2, y2),
            (0, 0, 210),
            2
        )

        # ---------------------------------------------------------------
        # Warning icon
        # ---------------------------------------------------------------

        cv2.circle(
            img,
            (cx, cy - 55),
            22,
            (0, 0, 200),
            2
        )

        cv2.putText(
            img,
            "!",
            (cx - 6, cy - 42),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.85,
            (0, 0, 220),
            2,
            cv2.LINE_AA
        )

        # ---------------------------------------------------------------
        # Offline title
        # ---------------------------------------------------------------

        font = cv2.FONT_HERSHEY_SIMPLEX

        title = "CAMERA OFFLINE"

        tw = cv2.getTextSize(
            title,
            font,
            0.85,
            2
        )[0][0]

        cv2.putText(
            img,
            title,
            (
                cx - tw // 2,
                cy + 5
            ),
            font,
            0.85,
            (0, 60, 255),
            2,
            cv2.LINE_AA
        )

        # ---------------------------------------------------------------
        # Current target URL
        # ---------------------------------------------------------------

        url_disp = self.stream_url

        if len(url_disp) > 50:

            url_disp = (
                url_disp[:47]
                + "..."
            )

        uw = cv2.getTextSize(
            url_disp,
            font,
            0.4,
            1
        )[0][0]

        cv2.putText(
            img,
            url_disp,
            (
                cx - uw // 2,
                cy + 32
            ),
            font,
            0.4,
            (160, 160, 160),
            1,
            cv2.LINE_AA
        )

        # ---------------------------------------------------------------
        # Status
        # ---------------------------------------------------------------

        status_line = (
            "Status: Reconnecting — "
            "ensure Android IP Webcam app is running"
        )

        sw = cv2.getTextSize(
            status_line,
            font,
            0.35,
            1
        )[0][0]

        cv2.putText(
            img,
            status_line,
            (
                cx - sw // 2,
                cy + 55
            ),
            font,
            0.35,
            (120, 120, 120),
            1,
            cv2.LINE_AA
        )

        # ---------------------------------------------------------------
        # Top HUD
        # ---------------------------------------------------------------

        ts = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        cv2.rectangle(
            img,
            (0, 0),
            (width, 28),
            (12, 16, 26),
            -1
        )

        cv2.putText(
            img,
            "SENTINEL WATCH  |  STREAM OFFLINE  |  "
            + ts,
            (10, 18),
            font,
            0.4,
            (0, 140, 220),
            1,
            cv2.LINE_AA
        )

        # ---------------------------------------------------------------
        # Bottom HUD
        # ---------------------------------------------------------------

        cv2.rectangle(
            img,
            (0, height - 24),
            (width, height),
            (12, 16, 26),
            -1
        )

        cv2.putText(
            img,
            "CAMERA: OFFLINE  |  RECONNECT ATTEMPTS: "
            + str(self._reconnect_count),
            (10, height - 8),
            font,
            0.38,
            (80, 80, 80),
            1,
            cv2.LINE_AA
        )

        return img