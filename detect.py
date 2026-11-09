"""
Sentinel Watch - AI Weapon Detection Module
============================================
Pipeline:
    Android Camera  →  OpenCV  →  YOLO Inference
    →  Weapon / Person Detection  →  Annotated Frame
    →  Threat Score  →  Alert Decision

Models
------
custom (models/best.pt) : trained weapon model — primary source for weapons.
baseline (yolov8n.pt)   : COCO model — used for person detection; also
                          detects edged weapons (knife/scissors) when
                          custom model is absent.

Class routing
-------------
Class IDs are read at load time from model.names (dict {int: str}).
No class-ID values are hard-coded in the inference path.
WEAPON_KEYWORDS is used ONCE during model load to build integer ID sets.

Temporal confirmation
---------------------
A weapon detection is only reported as "confirmed" once it has appeared
in WEAPON_CONFIRM_FRAMES consecutive frames.  This prevents single-frame
false positives from triggering alerts.  No object tracking is used —
confirmed status resets whenever the weapon disappears.

Bounding boxes
--------------
Weapon  : RED corner-marker box with class label and confidence %.
Person  : CYAN thin rectangle with confidence %.
"""

import cv2
import logging
import collections
import numpy as np
from config import Config

logger = logging.getLogger("sentinel.detect")

# ── Vocabulary used at model-load time only ───────────────────────────────────
WEAPON_KEYWORDS = frozenset({
    "gun", "pistol", "rifle", "handgun", "shotgun", "revolver",
    "firearm", "weapon", "knife", "dagger", "sword", "blade",
    "scissors",
})

# ── Temporal confirmation: N consecutive frames needed before "confirmed" ──────
WEAPON_CONFIRM_FRAMES = 2    # set to 1 to disable (every frame counts)

# ── Drawing constants ─────────────────────────────────────────────────────────
COLOR_WEAPON_CONFIRMED = (0, 0, 255)      # red  (BGR)
COLOR_WEAPON_PENDING   = (0, 100, 255)    # orange (BGR) — seen but not yet confirmed
COLOR_PERSON           = (255, 200, 0)    # cyan-yellow
CORNER_LEN             = 16              # pixels for corner-marker arms
CORNER_THICK           = 3
FONT                   = cv2.FONT_HERSHEY_SIMPLEX


# ── Utility: build integer class-ID sets from model.names ────────────────────

def _build_class_maps(yolo_model):
    """
    Return (person_class_id | None, weapon_class_ids: set[int])
    by scanning model.names with WEAPON_KEYWORDS.
    """
    names = yolo_model.model.names          # {int: str}
    person_id = None
    weapon_ids = set()
    for cls_id, cls_name in names.items():
        lower = cls_name.lower()
        if lower == "person":
            person_id = cls_id
        elif any(kw in lower for kw in WEAPON_KEYWORDS):
            weapon_ids.add(cls_id)
    logger.info(
        "Class map: person_id=%s  weapon_ids=%s  (total classes: %d)",
        person_id, weapon_ids, len(names),
    )
    return person_id, weapon_ids


# ── Drawing helpers ───────────────────────────────────────────────────────────

def _draw_label_tag(img, text, x, y, bg_color, text_color=(255, 255, 255),
                    font_scale=0.44, thickness=1):
    """Draw a filled label box above point (x, y)."""
    (tw, th), baseline = cv2.getTextSize(text, FONT, font_scale, thickness)
    pad = 3
    ty  = max(th + pad * 2, y)
    cv2.rectangle(img, (x, ty - th - pad * 2), (x + tw + pad * 2, ty), bg_color, -1)
    cv2.putText(img, text, (x + pad, ty - pad),
                FONT, font_scale, text_color, thickness, cv2.LINE_AA)


def _draw_corner_box(img, x1, y1, x2, y2, color, thickness=CORNER_THICK, arm=CORNER_LEN):
    """Draw four corner-marker brackets instead of a full rectangle."""
    pts = [
        # TL
        ((x1, y1 + arm), (x1, y1), (x1 + arm, y1)),
        # TR
        ((x2 - arm, y1), (x2, y1), (x2, y1 + arm)),
        # BL
        ((x1, y2 - arm), (x1, y2), (x1 + arm, y2)),
        # BR
        ((x2 - arm, y2), (x2, y2), (x2, y2 - arm)),
    ]
    for a, corner, b in pts:
        cv2.line(img, a, corner, color, thickness, cv2.LINE_AA)
        cv2.line(img, corner, b, color, thickness, cv2.LINE_AA)


def _draw_weapon(img, det, confirmed: bool):
    x1, y1, x2, y2 = det["box"]
    pct   = int(det["confidence"] * 100)
    label = ("⚠ " if confirmed else "? ") + det["class"].upper() + " " + str(pct) + "%"
    color = COLOR_WEAPON_CONFIRMED if confirmed else COLOR_WEAPON_PENDING

    # Semi-transparent fill when confirmed
    if confirmed:
        overlay = img.copy()
        cv2.rectangle(overlay, (x1, y1), (x2, y2), color, -1)
        cv2.addWeighted(overlay, 0.08, img, 0.92, 0, img)

    # Corner-marker box
    _draw_corner_box(img, x1, y1, x2, y2, color)

    # Label tag
    _draw_label_tag(img, label, x1, y1, color)


def _draw_person(img, det):
    x1, y1, x2, y2 = det["box"]
    pct   = int(det["confidence"] * 100)
    label = "PERSON " + str(pct) + "%"
    cv2.rectangle(img, (x1, y1), (x2, y2), COLOR_PERSON, 1)
    _draw_label_tag(img, label, x1, y1, COLOR_PERSON, text_color=(0, 0, 0))


def _draw_hud_banner(img, threat: dict):
    """Top HUD bar with threat level and score."""
    level = threat.get("threat_level", "LOW")
    score = threat.get("threat_score", 0)
    label = threat.get("scene_label", "Monitoring")
    color_map = {
        "LOW":      (0, 200, 0),
        "MEDIUM":   (0, 200, 255),
        "HIGH":     (0, 100, 255),
        "CRITICAL": (0, 0, 255),
    }
    hud_color = color_map.get(level, (0, 200, 0))
    banner = "THREAT: " + level + "  SCORE: " + str(score) + "/100  |  " + label
    cv2.rectangle(img, (0, 0), (img.shape[1], 26), (12, 18, 30), -1)
    cv2.putText(img, banner, (8, 18), FONT, 0.50, hud_color, 2, cv2.LINE_AA)


# ── Main detector class ───────────────────────────────────────────────────────

class ObjectDetector:
    """
    YOLO-based weapon and person detector with temporal confirmation.

    Two YOLO models run in sequence:
      baseline  — always loaded (yolov8n.pt / COCO).  Detects persons and
                  edged weapons from COCO classes.
      custom    — loaded when models/best.pt exists.  Primary weapon detector.
                  When loaded, baseline weapon detections are suppressed so only
                  custom-model weapons appear.

    Temporal confirmation
    ---------------------
    _weapon_streak[class_id_key] counts how many consecutive frames a weapon
    class-ID appeared.  A detection is "confirmed" once count ≥ WEAPON_CONFIRM_FRAMES.
    The streak resets to 0 when a class-ID is absent for a frame.
    No object IDs / tracking is involved.
    """

    def __init__(self):
        self.custom_model_path       = Config.CUSTOM_MODEL_PATH
        self.base_model_path         = Config.BASE_MODEL_PATH
        self.model                   = None   # custom weapon model
        self.person_model            = None   # baseline COCO model
        self.is_custom_model_loaded  = False
        self.model_warning           = ""
        # Class-ID sets built from model.names at load time
        self.person_class_id         = None
        self.weapon_class_ids        = set()   # baseline
        self.custom_person_class_id  = None
        self.custom_weapon_class_ids = set()   # custom
        # Temporal confirmation state
        self._weapon_streak: dict[str, int] = collections.defaultdict(int)
        self._load_models()

    # ── Model loading ─────────────────────────────────────────────────────────

    def _load_models(self):
        try:
            from ultralytics import YOLO
        except ImportError:
            self.model_warning = "CRITICAL: ultralytics not installed. AI pipeline unavailable."
            logger.error(self.model_warning)
            return

        # Custom weapon model
        if self.custom_model_path.exists():
            try:
                logger.info("Loading custom weapon model: %s", self.custom_model_path)
                self.model = YOLO(str(self.custom_model_path))
                self.is_custom_model_loaded = True
                self.model_warning = ""
                self.custom_person_class_id, self.custom_weapon_class_ids = (
                    _build_class_maps(self.model)
                )
                logger.info(
                    "Custom model loaded — classes: %s",
                    list(self.model.model.names.values()),
                )
            except Exception as exc:
                self.is_custom_model_loaded = False
                self.model_warning = (
                    "Error loading models/best.pt: " + str(exc) +
                    ". Falling back to baseline YOLOv8."
                )
                logger.error(self.model_warning)
        else:
            self.is_custom_model_loaded = False
            self.model_warning = (
                "NOTICE: models/best.pt not found. "
                "Place a trained weapon model there for full weapon detection. "
                "Using baseline COCO model (knife/scissors only)."
            )
            logger.warning(self.model_warning)

        # Baseline COCO model (always loaded)
        try:
            target = (
                str(self.base_model_path)
                if self.base_model_path.exists()
                else "yolov8n.pt"
            )
            logger.info("Loading baseline YOLOv8 model: %s", target)
            self.person_model = YOLO(target)
            self.person_class_id, self.weapon_class_ids = _build_class_maps(self.person_model)
            logger.info("Baseline YOLOv8 model ready.")
        except Exception as exc:
            logger.error("Failed to load baseline YOLOv8: %s", exc)

    def reload_custom_model(self):
        """Re-scan models/best.pt and reload if present. Returns (loaded, warning)."""
        self._weapon_streak.clear()
        self._load_models()
        return self.is_custom_model_loaded, self.model_warning

    # ── Inference ─────────────────────────────────────────────────────────────

    def detect(self, frame: np.ndarray) -> dict:
        """
        Run YOLO inference on a single BGR frame.

        Returns
        -------
        dict with keys:
          persons          : list[DetectionItem]
          weapons          : list[DetectionItem]   — confirmed weapons only
          weapons_pending  : list[DetectionItem]   — seen but not yet confirmed
          all_detections   : list[DetectionItem]
          annotated_frame  : np.ndarray            — frame with boxes + HUD drawn
          is_custom_model_loaded : bool
          model_warning    : str
        """
        empty = {
            "persons": [], "weapons": [], "weapons_pending": [],
            "all_detections": [],
            "annotated_frame": frame.copy() if frame is not None else None,
            "is_custom_model_loaded": self.is_custom_model_loaded,
            "model_warning": self.model_warning,
        }
        if frame is None or frame.size == 0:
            return empty

        conf_threshold = Config.CONFIDENCE_THRESHOLD
        iou_threshold  = Config.IOU_THRESHOLD

        persons:       list[dict] = []
        raw_weapons:   list[dict] = []
        all_dets:      list[dict] = []

        # ── 1. Baseline COCO model ────────────────────────────────────────────
        if self.person_model is not None:
            try:
                for res in self.person_model(
                    frame, conf=conf_threshold, iou=iou_threshold, verbose=False
                ):
                    for box in res.boxes:
                        cls_id   = int(box.cls[0])
                        cls_name = res.names[cls_id]
                        conf     = float(box.conf[0])
                        x1, y1, x2, y2 = (int(v) for v in box.xyxy[0])
                        item = {
                            "class":      cls_name,
                            "class_id":   cls_id,
                            "confidence": round(conf, 4),
                            "box":        [x1, y1, x2, y2],
                            "center":     ((x1 + x2) // 2, (y1 + y2) // 2),
                            "source":     "baseline",
                        }
                        all_dets.append(item)
                        if cls_id == self.person_class_id:
                            persons.append(item)
                        elif cls_id in self.weapon_class_ids and not self.is_custom_model_loaded:
                            # Only use baseline weapons when no custom model is loaded
                            raw_weapons.append(item)
            except Exception as exc:
                logger.error("Baseline model inference error: %s", exc, exc_info=False)

        # ── 2. Custom weapon model (primary) ──────────────────────────────────
        if self.is_custom_model_loaded and self.model is not None:
            try:
                for res in self.model(
                    frame, conf=conf_threshold, iou=iou_threshold, verbose=False
                ):
                    for box in res.boxes:
                        cls_id   = int(box.cls[0])
                        cls_name = res.names[cls_id]
                        conf     = float(box.conf[0])
                        x1, y1, x2, y2 = (int(v) for v in box.xyxy[0])
                        item = {
                            "class":      cls_name,
                            "class_id":   cls_id,
                            "confidence": round(conf, 4),
                            "box":        [x1, y1, x2, y2],
                            "center":     ((x1 + x2) // 2, (y1 + y2) // 2),
                            "source":     "custom",
                        }
                        all_dets.append(item)
                        if cls_id in self.custom_weapon_class_ids:
                            raw_weapons.append(item)
                        elif cls_id == self.custom_person_class_id and not persons:
                            persons.append(item)
                        else:
                            # Unknown class in custom model → treat as weapon
                            raw_weapons.append(item)
            except Exception as exc:
                logger.error("Custom model inference error: %s", exc, exc_info=False)

        # ── 3. Temporal confirmation ───────────────────────────────────────────
        # Build a set of class-ID keys seen this frame
        seen_cls_keys: set[str] = set()
        for w in raw_weapons:
            key = w["source"] + "_" + str(w["class_id"])
            seen_cls_keys.add(key)
            self._weapon_streak[key] += 1

        # Decay streak for classes not seen this frame
        for key in list(self._weapon_streak.keys()):
            if key not in seen_cls_keys:
                self._weapon_streak[key] = 0

        # Classify each raw weapon as confirmed or pending
        confirmed_weapons: list[dict] = []
        pending_weapons:   list[dict] = []
        for w in raw_weapons:
            key = w["source"] + "_" + str(w["class_id"])
            if self._weapon_streak[key] >= WEAPON_CONFIRM_FRAMES:
                confirmed_weapons.append(w)
            else:
                pending_weapons.append(w)

        # ── 4. Draw annotations ───────────────────────────────────────────────
        annotated = frame.copy()

        # Persons (drawn first — lowest z-order)
        for det in persons:
            _draw_person(annotated, det)

        # Pending weapons (orange corner box — not yet confirmed)
        for det in pending_weapons:
            _draw_weapon(annotated, det, confirmed=False)

        # Confirmed weapons (red corner box + semi-transparent fill)
        for det in confirmed_weapons:
            _draw_weapon(annotated, det, confirmed=True)

        return {
            "persons":               persons,
            "weapons":               confirmed_weapons,
            "weapons_pending":       pending_weapons,
            "all_detections":        all_dets,
            "annotated_frame":       annotated,
            "is_custom_model_loaded": self.is_custom_model_loaded,
            "model_warning":         self.model_warning,
        }
