"""
Sentinel Watch - Configuration Module
"""

import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent

env_file = BASE_DIR / ".env"

if env_file.exists():
    load_dotenv(dotenv_path=env_file)
else:
    load_dotenv()


class Config:
    """Application configuration parameters."""

    # --------------------------------------------------
    # Security
    # --------------------------------------------------
    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        "sentinel-watch-default-secret-key-2026"
    )

    # --------------------------------------------------
    # Paths
    # --------------------------------------------------
    BASE_DIR = BASE_DIR

    DATABASE_DIR = BASE_DIR / "database"
    DATABASE_PATH = DATABASE_DIR / "sentinelwatch.db"

    SCREENSHOTS_DIR = BASE_DIR / "screenshots"
    REPORTS_DIR = BASE_DIR / "reports"
    LOGS_DIR = BASE_DIR / "logs"
    UPLOADS_DIR = BASE_DIR / "uploads"

    MODELS_DIR = BASE_DIR / "models"

    CUSTOM_MODEL_PATH = MODELS_DIR / "best.pt"
    BASE_MODEL_PATH = MODELS_DIR / "yolov8n.pt"

    # --------------------------------------------------
    # Camera
    # --------------------------------------------------
    DEFAULT_CAMERA_URL = os.getenv(
        "CAMERA_URL",
        "http://172.16.1.24:8080/video"
    )

    CAMERA_RECONNECT_INTERVAL = 3.0

    CAMERA_FRAME_WIDTH = 640
    CAMERA_FRAME_HEIGHT = 480

    # --------------------------------------------------
    # YOLO Detection
    # --------------------------------------------------
    CONFIDENCE_THRESHOLD = float(
        os.getenv("CONFIDENCE_THRESHOLD", "0.50")
    )

    IOU_THRESHOLD = float(
        os.getenv("IOU_THRESHOLD", "0.45")
    )

    # --------------------------------------------------
    # Threat Scoring / Alerts
    # --------------------------------------------------
    ALERT_THREAT_THRESHOLD = int(
        os.getenv("ALERT_THREAT_THRESHOLD", "60")
    )

    ALERT_COOLDOWN_SECONDS = int(
        os.getenv("ALERT_COOLDOWN_SECONDS", "20")
    )

    ALERT_INTERVAL_SECONDS = int(
        os.getenv("ALERT_INTERVAL_SECONDS", "20")
    )

    # --------------------------------------------------
    # Threat Level Labels
    # --------------------------------------------------
    THREAT_LEVEL_LOW = "LOW"
    THREAT_LEVEL_MEDIUM = "MEDIUM"
    THREAT_LEVEL_HIGH = "HIGH"
    THREAT_LEVEL_CRITICAL = "CRITICAL"

    # --------------------------------------------------
    # Pushbullet
    # --------------------------------------------------
    PUSHBULLET_ACCESS_TOKEN = os.getenv(
        "PUSHBULLET_ACCESS_TOKEN",
        ""
    ).strip()

    # --------------------------------------------------
    # Flask
    # --------------------------------------------------
    HOST = os.getenv("HOST", "0.0.0.0")

    PORT = int(
        os.getenv("PORT", "5000")
    )

    DEBUG = os.getenv(
        "FLASK_DEBUG",
        "0"
    ) == "1"

    # --------------------------------------------------
    # Create Required Directories
    # --------------------------------------------------
    @classmethod
    def init_directories(cls):
        directories = [
            cls.DATABASE_DIR,
            cls.SCREENSHOTS_DIR,
            cls.REPORTS_DIR,
            cls.LOGS_DIR,
            cls.UPLOADS_DIR,
            cls.MODELS_DIR,
        ]

        for path in directories:
            path.mkdir(
                parents=True,
                exist_ok=True
            )


# Initialize required directories
Config.init_directories()