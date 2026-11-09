SENTINEL WATCH - WEAPON DETECTION MODEL INSTRUCTIONS
======================================================
Place your custom-trained YOLO weapon detection model file here:
Filename: best.pt
Path: SentinelWatch/models/best.pt

If models/best.pt is not present, Sentinel Watch will automatically:
1. Display a visible indicator in the Web Dashboard and console logs stating that models/best.pt must be provided.
2. Gracefully initialize YOLOv8 baseline detection (yolov8n.pt) for person and object tracking.
3. Once you place your trained best.pt here, restart the application or reinitialize the model from the dashboard.
