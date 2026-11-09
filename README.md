# Sentinel Watch: AI-Powered Weapon Detection System

Sentinel Watch is a real-time, AI-driven surveillance and security platform. It streams live video from an Android smartphone, processes it through custom YOLOv8 deep learning models to detect weapons, and dynamically calculates a quantitative Threat Score. High-risk events trigger automated evidence capture, SQLite database logging, and Pushbullet notifications.

**Note:** In accordance with strict operational requirements, this system focuses *exclusively* on Weapon Detection. Modules for Object Tracking, Suspicious Activity, Loitering, and Behaviour Analysis have been explicitly excluded.

---

## 🏗️ System Architecture & Pipeline

1. **Android Smartphone Camera:** Serves as a wireless IP camera.
2. **HTTP Video Stream:** Transmits MJPEG frames over the local network.
3. **OpenCV:** Captures and decodes the incoming video stream.
4. **YOLO Weapon Detection:** Scans frames for weapons and persons.
5. **Threat Score Evaluation:** Dynamically scores the scene (0-100) based on weapon presence, confidence, and person proximity.
6. **Threat Level Assessment:** Categorizes the threat (LOW, MEDIUM, HIGH, CRITICAL).
7. **Alert Threshold Check:** Determines if the threat warrants a security alert.
8. **Evidence Screenshot:** Captures the processed frame if an alert is triggered.
9. **SQLite Database:** Stores the incident metadata and screenshot path.
10. **Pushbullet Alert:** Dispatches a mobile push notification (respecting cooldowns).
11. **Web Dashboard:** Displays live telemetry, video, and recent incidents.
12. **Detection History & PDF Reports:** Archives incidents and generates formal ReportLab PDF documents.

---

## 🛡️ Threat Scoring Logic

The system generates a Threat Score (0-100) based purely on direct detections:

- **Person Only**: Evaluated as a normal presence (Threat Score: 0, Threat Level: **LOW**). No alert generated.
- **Weapon Detected**: Base score + Confidence-based scaling.
- **Person + Weapon**: Compound threat amplifier (+20 points).
- **Persistent Weapon**: Consecutive detections confirm the threat (+10 points).

---

## 📱 Android Smartphone Camera Setup
Sentinel Watch uses **ONE Android smartphone** as the IP camera over local Wi-Fi:

1. Connect your Android phone and computer to the **same Wi-Fi network**.
2. On your Android smartphone, install a free IP camera app such as **IP Webcam** (by Pavel Khlebovich) from the Google Play Store.
3. Open the app, scroll to the bottom, and tap **"Start server"**.
4. Note the URL displayed on the phone screen, for example: `http://192.168.1.34:8080/video`
5. In Sentinel Watch, open `.env` and set:
   ```env
   CAMERA_URL=http://192.168.1.34:8080/video
   ```
   *(If the camera goes offline, the system never crashes; it displays a "CAMERA OFFLINE" overlay until it successfully reconnects.)*

---

## 🎯 YOLO Weapon Detection Model (`models/best.pt`)
The system requires a custom-trained YOLOv8 model located at `models/best.pt`. 
If `best.pt` is missing, the system gracefully falls back to the baseline `yolov8n.pt` model (which detects standard objects like persons, knives, scissors, etc.).

### Training Your Custom Weapon Model (`train.py`)
To train your own custom YOLOv8 weapon detection model:

1. **Prepare your Dataset** in YOLO format:
```
dataset/
├── images/
│   ├── train/
│   └── val/
├── labels/
│   ├── train/
│   └── val/
└── data.yaml
```
2. **Run the Training Script**:
```bash
python train.py --epochs 50 --imgsz 640 --batch 16 --conf 0.25
```
3. **Automatic Deployment**: Upon successful completion, the script automatically generates evaluation metrics (Precision, Recall, mAP50) and copies the best model weights to `models/best.pt`.

---

## 🚀 Installation & Quick Start

### 1. Install Dependencies
```bash
cd SentinelWatch
pip install -r requirements.txt
pip install reportlab  # For PDF Generation
```

### 2. Configure Environment (`.env`)
Create or edit your `.env` file in the root directory:
```env
CAMERA_URL=http://192.168.1.34:8080/video
PUSHBULLET_ACCESS_TOKEN=your_token_here
ALERT_COOLDOWN_SECONDS=15
```

### 3. Launch Sentinel Watch
```bash
python run.py
```

### 4. Access Web Command Center
Navigate your browser to: `http://127.0.0.1:5000`

### 5. Default Credentials
- **Username**: `admin`
- **Password**: `admin123`
*(Authorized admins can generate PDF reports, view history, and review Pushbullet dispatch logs.)*

---

## 📁 Project Directory Structure
```
SentinelWatch/
├── app.py              # Main Flask server & pipeline orchestration
├── config.py           # Configuration parameters and path constants
├── auth.py             # User authentication, sessions, and roles
├── camera.py           # Multi-threaded IP camera stream manager 
├── detect.py           # YOLO inference, bounding boxes, temporal confirmation
├── threat.py           # Quantitative Threat Score (0-100) & Levels
├── alerts.py           # Evidence capture, Pushbullet dispatch, SQLite logging
├── database.py         # SQLite schema and query functions
├── reports.py          # ReportLab PDF incident report generator
├── train.py            # Custom YOLO model training pipeline
├── requirements.txt    # Dependencies
├── .env                # Runtime environment variables
├── run.py              # Application launcher
│
├── models/             # YOLO weights (best.pt, yolov8n.pt)
├── database/           # SQLite database file (sentinelwatch.db)
├── screenshots/        # Incident evidence snapshots
├── reports/            # Generated PDF incident reports
├── logs/               # Application audit logs (sentinel.log)
│
├── templates/          # Jinja2 HTML templates
│   ├── base.html       # Base layout
│   ├── login.html      # Authentication portal
│   ├── register.html   # User registration
│   ├── dashboard.html  # Live command center & video stream
│   ├── history.html    # Incident archive & search
│   ├── alerts.html     # Alert triage log
│   ├── profile.html    # Operator profile settings
│   └── report.html     # PDF report generation UI
│
└── static/             # Static assets (CSS, JS)
```