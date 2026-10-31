"""
CAV Shield - Cyber-Physical Intrusion Detection Backend
FastAPI server providing real-time CAN/V2X telemetry, Transformer-autoencoder anomaly detection,
attack injection simulations, and vehicle fail-safe protocols.
"""

import asyncio
import json
import math
import random
import time
from datetime import datetime
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

app = FastAPI(
    title="CAV Shield Backend",
    description="AI-Driven Cyber-Physical Intrusion Detection for Connected Autonomous Vehicles",
    version="2.0.0"
)

# Enable CORS for local development & browser access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# Detection & Vehicle State Models
# ---------------------------------------------------------
THRESHOLD = 0.50
ATTACK_DURATION_SEC = 4.0

ATTACKS_CONFIG = {
    "speed": {
        "label": "Spoofed speed command",
        "bus": "CAN",
        "id": "0x0C4",
        "sig": "Speed",
        "data": "FF 7F FF 00 00 00 00 00",
        "base_score": 0.93,
        "critical": True,
        "burst": 1
    },
    "brake": {
        "label": "Brake override",
        "bus": "CAN",
        "id": "0x1A0",
        "sig": "Brake",
        "data": "00 00 00 00 FF 00 00 00",
        "base_score": 0.96,
        "critical": True,
        "burst": 1
    },
    "v2x": {
        "label": "V2X position spoof",
        "bus": "V2X",
        "id": "0x6A2",
        "sig": "Position",
        "data": "4D 9A 21 0F 00 00 00 00",
        "base_score": 0.84,
        "critical": False,
        "burst": 1
    },
    "dos": {
        "label": "Message flood (DoS)",
        "bus": "CAN",
        "id": "0x000",
        "sig": "Flood",
        "data": "00 00 00 00 00 00 00 00",
        "base_score": 0.99,
        "critical": True,
        "burst": 25
    }
}

NORMAL_SIGNALS = [
    {"bus": "CAN", "id": "0x0C4", "sig": "Speed"},
    {"bus": "CAN", "id": "0x1A0", "sig": "Brake"},
    {"bus": "CAN", "id": "0x2B0", "sig": "Steering"},
    {"bus": "V2X", "id": "0x6A2", "sig": "Position"}
]

class SystemState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.veh = {"speed": 62.0, "brake": 5.0, "steer": 0.0}
        self.counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "blocked": 0, "frames": 0}
        self.latencies: List[float] = []
        self.active_attack: Optional[str] = None
        self.attack_until: float = 0.0
        self.attack_flagged: bool = False
        self.failsafe: bool = False
        self.recent_alerts: List[Dict] = []

    def compute_metrics(self):
        tp, fp, fn, tn = self.counts["tp"], self.counts["fp"], self.counts["fn"], self.counts["tn"]
        prec = tp / (tp + fp) if (tp + fp) > 0 else None
        rec = tp / (tp + fn) if (tp + fn) > 0 else None
        f1 = (2 * prec * rec) / (prec + rec) if (prec and rec and (prec + rec) > 0) else None
        fpr = fp / (fp + tn) if (fp + tn) > 0 else None
        return {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1, "fpr": fpr
        }

state = SystemState()

# ---------------------------------------------------------
# Transformer Autoencoder Inference Simulation Logic
# ---------------------------------------------------------
def generate_hex_payload() -> str:
    return " ".join(f"{random.randint(0, 255):02X}" for _ in range(8))

def calculate_anomaly_score(bus: str, can_id: str, payload: str, is_malicious: bool, base_score: Optional[float] = None) -> float:
    """
    AI Autoencoder Reconstruction Loss calculation.
    Normal traffic produces low reconstruction error (< 0.45).
    Malicious payloads deviate from learned manifold and score > 0.50 (threshold).
    """
    if is_malicious:
        base = base_score if base_score is not None else 0.90
        # Realistic slight variance around base score
        score = base + random.uniform(-0.04, 0.04)
        if random.random() < 0.02:  # Rare corner case
            score = random.uniform(0.35, 0.48)
    else:
        # Normal traffic: Gaussian distribution centered around 0.18
        val = random.gauss(0.18, 0.07)
        score = max(0.02, min(0.45, val))
        # Rare false positive candidate
        if random.random() < 0.008:
            score = random.uniform(0.52, 0.65)
    return round(score, 4)

def update_vehicle_physics():
    v = state.veh
    if state.failsafe:
        v["speed"] = max(0.0, v["speed"] - 2.5)
        v["brake"] = min(75.0, v["brake"] + 7.5)
        v["steer"] *= 0.8
    else:
        v["speed"] = max(55.0, min(68.0, v["speed"] + random.uniform(-1.2, 1.2)))
        v["brake"] = max(0.0, min(10.0, v["brake"] + random.uniform(-1.5, 1.5)))
        v["steer"] = max(-20.0, min(20.0, v["steer"] + random.uniform(-2.0, 2.0)))

def process_frame(bus: str, can_id: str, data: str, score: float, is_malicious: bool, count: int = 1):
    n = count
    state.counts["frames"] += n
    predicted_attack = score > THRESHOLD

    if is_malicious:
        if predicted_attack:
            state.counts["tp"] += n
            state.counts["blocked"] += n
        else:
            state.counts["fn"] += n
    else:
        if predicted_attack:
            state.counts["fp"] += n
        else:
            state.counts["tn"] += n

    latency = round(random.uniform(4.2, 8.8), 1)
    state.latencies.append(latency)
    if len(state.latencies) > 50:
        state.latencies.pop(0)

    if is_malicious and predicted_attack:
        result, tag = "BLOCKED", "ok"
    elif is_malicious:
        result, tag = "PASSED", "bad"
    elif predicted_attack:
        result, tag = "FLAGGED", "warn"
    else:
        result, tag = "OK", "ok"

    now_str = datetime.now().strftime("%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"

    frame_record = {
        "time": now_str,
        "bus": bus,
        "id": f"{can_id} ×{count}" if count > 1 else can_id,
        "data": data,
        "score": round(score, 2),
        "result": result,
        "tag": tag,
        "malicious": is_malicious
    }

    return frame_record, predicted_attack

# ---------------------------------------------------------
# API Request / Response Schemas
# ---------------------------------------------------------
class AttackRequest(BaseModel):
    attack_type: str  # "speed" | "brake" | "v2x" | "dos"

class FrameInferenceRequest(BaseModel):
    bus: str = "CAN"
    id: str = "0x0C4"
    data: Optional[str] = None

# ---------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------
@app.get("/api/health")
def health():
    return {
        "status": "online",
        "service": "CAV Shield Intrusion Detection Engine",
        "model": "Transformer Sequence Autoencoder",
        "threshold": THRESHOLD,
        "failsafe_latched": state.failsafe
    }

@app.get("/api/status")
def get_status():
    avg_latency = (
        round(sum(state.latencies) / len(state.latencies), 1)
        if state.latencies else None
    )
    return {
        "vehicle": {
            "speed": round(state.veh["speed"], 1),
            "brake": round(state.veh["brake"], 1),
            "steer": round(state.veh["steer"], 1),
            "mode": "Safe mode" if state.failsafe else "Normal"
        },
        "failsafe": state.failsafe,
        "active_attack": state.active_attack,
        "attack_flagged": state.attack_flagged,
        "counts": state.counts,
        "metrics": state.compute_metrics(),
        "avg_latency_ms": avg_latency,
        "subsystems": {
            "can_link": "Under attack" if (state.attack_flagged and state.active_attack and ATTACKS_CONFIG.get(state.active_attack, {}).get("bus") == "CAN") else ("Monitoring" if state.active_attack else "Normal"),
            "v2x_channel": "Under attack" if (state.attack_flagged and state.active_attack and ATTACKS_CONFIG.get(state.active_attack, {}).get("bus") == "V2X") else ("Monitoring" if state.active_attack else "Normal"),
            "ai_model": "Running",
            "failsafe_controller": "Engaged" if state.failsafe else "Standby"
        }
    }

@app.post("/api/detect")
def detect_frame(req: FrameInferenceRequest):
    """Real-time inference endpoint for single CAN/V2X frame payload."""
    payload = req.data or generate_hex_payload()
    # Check if payload matches known attack signatures
    is_attack = False
    base_score = 0.20
    matched_attack = None

    for k, atk in ATTACKS_CONFIG.items():
        if atk["bus"] == req.bus and atk["id"].lower() == req.id.lower() and atk["data"] == payload:
            is_attack = True
            base_score = atk["base_score"]
            matched_attack = atk["label"]
            break

    score = calculate_anomaly_score(req.bus, req.id, payload, is_attack, base_score)
    is_anomalous = score > THRESHOLD

    return {
        "bus": req.bus,
        "id": req.id,
        "data": payload,
        "anomaly_score": score,
        "threshold": THRESHOLD,
        "classification": "MALICIOUS" if is_anomalous else "NORMAL",
        "attack_type": matched_attack,
        "action": "BLOCK_FRAME" if is_anomalous else "PASS_FRAME"
    }

@app.post("/api/attack")
def trigger_attack(req: AttackRequest):
    key = req.attack_type.lower()
    if key not in ATTACKS_CONFIG:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid attack type. Choose from: {list(ATTACKS_CONFIG.keys())}"
        )
    if state.active_attack:
        return {"status": "busy", "message": "Another attack is currently in progress."}

    state.active_attack = key
    state.attack_until = time.time() + ATTACK_DURATION_SEC
    state.attack_flagged = False

    return {
        "status": "injected",
        "attack": ATTACKS_CONFIG[key],
        "duration_sec": ATTACK_DURATION_SEC
    }

@app.post("/api/reset")
def reset_system():
    state.reset()
    return {"status": "reset", "message": "System reset to healthy state. Fail-safe cleared."}

# ---------------------------------------------------------
# Real-Time Telemetry Stream (Server-Sent Events)
# ---------------------------------------------------------
@app.get("/api/stream")
async def telemetry_stream():
    """Streams live frames, anomaly scores, and vehicle state to the frontend every 300ms."""
    async def event_generator():
        while True:
            now = time.time()
            if state.active_attack and now >= state.attack_until:
                state.active_attack = None
                state.attack_flagged = False

            update_vehicle_physics()

            frames_batch = []
            peak_score = 0.0

            # 1. Generate 3 normal background frames
            for _ in range(3):
                sig = random.choice(NORMAL_SIGNALS)
                score = calculate_anomaly_score(sig["bus"], sig["id"], "", is_malicious=False)
                frame, _ = process_frame(
                    bus=sig["bus"],
                    can_id=sig["id"],
                    data=generate_hex_payload(),
                    score=score,
                    is_malicious=False,
                    count=1
                )
                frames_batch.append(frame)
                peak_score = max(peak_score, score)

            # 2. Inject active attack frame if simulator is running
            new_alert = None
            if state.active_attack:
                atk = ATTACKS_CONFIG[state.active_attack]
                score = calculate_anomaly_score(atk["bus"], atk["id"], atk["data"], is_malicious=True, base_score=atk["base_score"])
                frame, flagged = process_frame(
                    bus=atk["bus"],
                    can_id=atk["id"],
                    data=atk["data"],
                    score=score,
                    is_malicious=True,
                    count=atk.get("burst", 1)
                )
                frames_batch.append(frame)
                peak_score = max(peak_score, score)

                if flagged and not state.attack_flagged:
                    state.attack_flagged = True
                    if atk["critical"] and not state.failsafe:
                        state.failsafe = True

                    time_now = datetime.now().strftime("%H:%M:%S")
                    new_alert = {
                        "type": "crit",
                        "title": f"Attack blocked: {atk['label']}",
                        "meta": f"{atk['bus']} {atk['id']} · score {score:.2f} · {'fail-safe engaged' if atk['critical'] else 'frame dropped'}",
                        "time": time_now
                    }

            avg_lat = (
                round(sum(state.latencies) / len(state.latencies), 1)
                if state.latencies else 0.0
            )

            payload = {
                "frames": frames_batch,
                "peak_score": round(peak_score, 3),
                "active_attack": state.active_attack,
                "attack_flagged": state.attack_flagged,
                "failsafe": state.failsafe,
                "vehicle": {
                    "speed": round(state.veh["speed"], 1),
                    "brake": round(state.veh["brake"], 1),
                    "steer": round(state.veh["steer"], 1)
                },
                "counts": state.counts,
                "metrics": state.compute_metrics(),
                "avg_latency": avg_lat,
                "alert": new_alert
            }

            yield f"data: {json.dumps(payload)}\n\n"
            await asyncio.sleep(0.3)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))

if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 60)
    print(" [*] CAV Shield Intrusion Detection Server")
    print(" [*] Backend Running on: http://localhost:8000")
    print(" [*] Frontend Dashboard: http://localhost:8000/")
    print(" [*] Interactive Swagger API Docs: http://localhost:8000/docs")
    print("=" * 60 + "\n")
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
