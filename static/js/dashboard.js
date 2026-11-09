/**
 * Sentinel Watch: AI-Powered Surveillance Dashboard JavaScript
 * Handles real-time telemetry polling, HUD animations, threat meter updates, and audio alerts.
 */

let isAudioEnabled = false;
let audioContext = null;
let lastKnownIncidentId = 0;
let pollInterval = null;

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initAudio();
    initControls();
    initCameraModalForm();
    startTelemetryPolling();
});

/**
 * Update HUD clock every second
 */
function initClock() {
    const updateClock = () => {
        const now = new Date();
        const timeStr = now.toTimeString().split(" ")[0];
        const hudTime = document.getElementById("hudTimestamp");
        if (hudTime) hudTime.textContent = timeStr;
    };
    updateClock();
    setInterval(updateClock, 1000);
}

/**
 * Initialize Web Audio API for alert beeps
 */
function initAudio() {
    const audioBtn = document.getElementById("audioToggleBtn");
    const audioIcon = document.getElementById("audioIcon");

    if (!audioBtn) return;

    audioBtn.addEventListener("click", () => {
        if (!audioContext) {
            audioContext = new (window.AudioContext || window.webkitAudioContext)();
        }

        isAudioEnabled = !isAudioEnabled;

        if (isAudioEnabled) {
            audioIcon.className = "fa-solid fa-volume-high text-warning";
            audioBtn.classList.replace("btn-outline-secondary", "btn-warning");
            playAlertTone(600, 0.1); // Test beep
        } else {
            audioIcon.className = "fa-solid fa-volume-xmark text-secondary";
            audioBtn.classList.replace("btn-warning", "btn-outline-secondary");
        }
    });
}

/**
 * Play a synthesizer alert tone via Web Audio API
 */
function playAlertTone(frequency = 880, duration = 0.3) {
    if (!isAudioEnabled || !audioContext) return;
    try {
        if (audioContext.state === "suspended") {
            audioContext.resume();
        }
        const osc = audioContext.createOscillator();
        const gain = audioContext.createGain();

        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(frequency, audioContext.currentTime);

        gain.gain.setValueAtTime(0.2, audioContext.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + duration);

        osc.connect(gain);
        gain.connect(audioContext.destination);

        osc.start();
        osc.stop(audioContext.currentTime + duration);
    } catch (e) {
        console.warn("Audio alert error:", e);
    }
}

/**
 * Initialize Fullscreen and Snapshot buttons
 */
function initControls() {
    const fsBtn = document.getElementById("fullscreenBtn");
    const videoContainer = document.getElementById("videoContainer");

    if (fsBtn && videoContainer) {
        fsBtn.addEventListener("click", () => {
            if (!document.fullscreenElement) {
                videoContainer.requestFullscreen().catch(err => console.error(err));
            } else {
                document.exitFullscreen();
            }
        });
    }

    const snapBtn = document.getElementById("snapshotBtn");
    if (snapBtn) {
        snapBtn.addEventListener("click", () => {
            const feed = document.getElementById("liveVideoFeed");
            if (feed) {
                const w = window.open("");
                w.document.write(`<img src="${feed.src}?t=${Date.now()}" style="max-width:100%; height:auto;">`);
            }
        });
    }
}

/**
 * Handle Camera Configuration Modal submission via AJAX
 */
function initCameraModalForm() {
    const form = document.getElementById("cameraConfigForm");
    const modalFeedback = document.getElementById("cameraModalFeedback");
    const saveBtn = document.getElementById("btnSaveCameraUrl");

    if (!form) return;

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const urlInput = document.getElementById("modalCameraUrl");
        const newUrl = urlInput.value.trim();

        if (!newUrl) return;

        saveBtn.disabled = true;
        saveBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status"></span> Updating...`;
        modalFeedback.innerHTML = `<span class="text-secondary">Reconnecting camera stream...</span>`;

        try {
            const response = await fetch("/api/update_camera", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ camera_url: newUrl })
            });
            const data = await response.json();

            if (data.status === "success") {
                modalFeedback.innerHTML = `<span class="text-success"><i class="fa-solid fa-circle-check me-1"></i>${data.message}</span>`;
                setTimeout(() => {
                    const modalEl = document.getElementById("cameraSettingsModal");
                    const modal = bootstrap.Modal.getInstance(modalEl);
                    if (modal) modal.hide();
                    saveBtn.disabled = false;
                    saveBtn.innerHTML = `<i class="fa-solid fa-check me-1"></i> Update & Reconnect`;
                    refreshStreamImage();
                }, 1000);
            } else {
                modalFeedback.innerHTML = `<span class="text-danger"><i class="fa-solid fa-triangle-exclamation me-1"></i>${data.message}</span>`;
                saveBtn.disabled = false;
                saveBtn.innerHTML = `<i class="fa-solid fa-check me-1"></i> Update & Reconnect`;
            }
        } catch (err) {
            modalFeedback.innerHTML = `<span class="text-danger">Network error: ${err.message}</span>`;
            saveBtn.disabled = false;
            saveBtn.innerHTML = `<i class="fa-solid fa-check me-1"></i> Update & Reconnect`;
        }
    });
}

/**
 * Refresh stream image element to recover from any network stall
 */
function refreshStreamImage() {
    const feed = document.getElementById("liveVideoFeed");
    if (feed) {
        feed.src = `/video_feed?t=${Date.now()}`;
    }
}

function handleStreamError(img) {
    console.warn("Stream frame read failed. Retrying in 2 seconds...");
    setTimeout(() => {
        img.src = `/video_feed?t=${Date.now()}`;
    }, 2000);
}

/**
 * Poll real-time telemetry API
 */
function startTelemetryPolling() {
    pollInterval = setInterval(fetchTelemetry, 1000);
    fetchTelemetry();
}

async function fetchTelemetry() {
    try {
        const res = await fetch("/api/live_status");
        if (!res.ok) return;
        const data = await res.json();
        updateDashboardUI(data);
    } catch (err) {
        console.debug("Telemetry poll skipped:", err);
    }
}

/**
 * Update all HUD elements, gauges, and counters from server telemetry
 */
function updateDashboardUI(data) {
    // 1. Camera Status
    const camera = data.camera || {};
    const kpiCamStatus = document.getElementById("kpiCamStatus");
    const cameraDot = document.getElementById("cameraDot");
    const cameraUrlBadge = document.getElementById("cameraUrlBadge");
    const navCamStatus = document.getElementById("navCameraStatusText");
    const modalCamUrl = document.getElementById("modalCameraUrl");

    if (camera.online) {
        if (kpiCamStatus) {
            kpiCamStatus.textContent = "ONLINE";
            kpiCamStatus.className = "h3 fw-bold text-success font-monospace mb-0";
        }
        if (cameraDot) cameraDot.className = "status-dot-pulse bg-success";
        if (navCamStatus) navCamStatus.innerHTML = `<span class="text-success fw-bold">ONLINE</span> (${camera.fps} FPS)`;
    } else {
        if (kpiCamStatus) {
            kpiCamStatus.textContent = "OFFLINE";
            kpiCamStatus.className = "h3 fw-bold text-danger font-monospace mb-0";
        }
        if (cameraDot) cameraDot.className = "status-dot-pulse bg-danger";
        if (navCamStatus) navCamStatus.innerHTML = `<span class="text-danger fw-bold">OFFLINE</span> (Reconnecting)`;
    }

    if (cameraUrlBadge && camera.url) {
        cameraUrlBadge.textContent = camera.url.length > 35 ? camera.url.substring(0, 32) + "..." : camera.url;
    }
    if (modalCamUrl && !modalCamUrl.value) {
        modalCamUrl.value = camera.url || "";
    }

    // 2. FPS & Counters
    const hudFps = document.getElementById("hudFps");
    const kpiFps = document.getElementById("kpiFps");
    const fpsVal = camera.fps || 0.0;
    if (hudFps) hudFps.textContent = fpsVal.toFixed(1);
    if (kpiFps) kpiFps.textContent = Math.round(fpsVal);

    const personsCount = data.total_persons || 0;
    const weaponsCount = data.total_weapons || 0;

    const hudPersons = document.getElementById("hudPersons");
    const kpiPersons = document.getElementById("kpiPersons");
    if (hudPersons) hudPersons.textContent = personsCount;
    if (kpiPersons) kpiPersons.textContent = personsCount;

    const hudWeapons = document.getElementById("hudWeapons");
    const kpiWeapons = document.getElementById("kpiWeapons");
    if (hudWeapons) hudWeapons.textContent = weaponsCount;
    if (kpiWeapons) kpiWeapons.textContent = weaponsCount;

    // 3. Activity Display
    const hudActivity = document.getElementById("hudActivity");
    if (hudActivity) {
        hudActivity.textContent = (data.activity_label || data.primary_activity || "SURVEILLANCE ACTIVE").toUpperCase();
    }

    // 4. Model Status Warning Banner
    const modelBanner = document.getElementById("modelWarningBanner");
    const modelText = document.getElementById("modelWarningText");
    if (modelBanner) {
        if (!data.is_custom_model_loaded) {
            modelBanner.classList.remove("d-none");
            if (modelText && data.model_warning) {
                modelText.textContent = data.model_warning;
            }
        } else {
            modelBanner.classList.add("d-none");
        }
    }

    // 5. Threat Score & Level
    const threat = data.threat || {};
    const score = threat.threat_score || 0;
    const level = (threat.threat_level || "LOW").toUpperCase();

    const scoreDisplay = document.getElementById("threatScoreDisplay");
    if (scoreDisplay) scoreDisplay.textContent = score;

    const progressBar = document.getElementById("threatProgressBar");
    if (progressBar) {
        progressBar.style.width = `${score}%`;
        progressBar.setAttribute("aria-valuenow", score);

        // Update progress bar color
        progressBar.className = "progress-bar progress-bar-striped progress-bar-animated";
        if (level === "CRITICAL") progressBar.classList.add("bg-danger");
        else if (level === "HIGH") progressBar.classList.add("bg-orange");
        else if (level === "MEDIUM") progressBar.classList.add("bg-warning", "text-dark");
        else progressBar.classList.add("bg-success");
    }

    // HUD Threat Badge
    const hudThreatBadge = document.getElementById("hudThreatBadge");
    const hudThreatText = document.getElementById("hudThreatText");
    if (hudThreatBadge && hudThreatText) {
        hudThreatText.textContent = `THREAT: ${level}`;
        hudThreatBadge.className = "badge-tactical";
        if (level === "CRITICAL") hudThreatBadge.classList.add("badge-crit");
        else if (level === "HIGH") hudThreatBadge.classList.add("badge-high");
        else if (level === "MEDIUM") hudThreatBadge.classList.add("badge-med");
        else hudThreatBadge.classList.add("badge-low");
    }

    // Threat Tier Pills
    updateTierPills(level);

    // Factors & Confidence
    const confBadge = document.getElementById("confidenceBadge");
    if (confBadge) {
        const confVal = threat.confidence ? Math.round(threat.confidence * 100) : 85;
        confBadge.textContent = `CONF: ${confVal}%`;
    }

    const factorsList = document.getElementById("contributingFactorsList");
    if (factorsList) {
        const factors = threat.contributing_factors || [];
        if (factors.length > 0) {
            factorsList.innerHTML = factors.map(f =>
                `<li class="mb-1"><i class="fa-solid fa-angle-right me-1 text-info"></i>${escapeHtml(f)}</li>`
            ).join("");
        } else {
            factorsList.innerHTML = `<li class="text-secondary font-monospace"><i class="fa-solid fa-check me-1 text-success"></i>Surveillance Zone Clear</li>`;
        }
    }

    // Sound alert on CRITICAL escalation
    if (level === "CRITICAL" && score >= 80) {
        playAlertTone(950, 0.4);
    }
}

/**
 * Highlight active threat tier
 */
function updateTierPills(level) {
    const tiers = {
        "LOW": document.getElementById("tierLow"),
        "MEDIUM": document.getElementById("tierMed"),
        "HIGH": document.getElementById("tierHigh"),
        "CRITICAL": document.getElementById("tierCrit")
    };

    for (const [key, pill] of Object.entries(tiers)) {
        if (!pill) continue;
        if (key === level) {
            pill.classList.add("active");
        } else {
            pill.classList.remove("active");
        }
    }
}

/**
 * Reload custom YOLO model via API
 */
async function reloadCustomModel() {
    try {
        const res = await fetch("/api/reload_model", { method: "POST" });
        const result = await res.json();
        alert(result.message);
        fetchTelemetry();
    } catch (e) {
        alert("Failed to reload model: " + e.message);
    }
}

function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
