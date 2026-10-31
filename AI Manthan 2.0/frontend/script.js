/* =========================================================================
   CAV Shield: simulator and UI logic
   Simulates CAN and V2X traffic with ground truth, applies a detection
   threshold to an anomaly score, and drives the dashboard.
   Replace the score generator with real model output when training is done.
   ========================================================================= */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);

  /* ---------- Config ---------- */
  const THRESHOLD = 0.5;
  const TICK_MS = 300;
  const ATTACK_MS = 4000;
  const POINTS = 120;
  const MAX_ROWS = 12;
  const MAX_LOG = 40;
  const NORMAL_FRAMES_PER_TICK = 3;

  const ATTACKS = {
    speed: { label: "Spoofed speed command", bus: "CAN", id: "0x0C4", sig: "Speed",
             data: "FF 7F FF 00 00 00 00 00", base: 0.93, critical: true },
    brake: { label: "Brake override", bus: "CAN", id: "0x1A0", sig: "Brake",
             data: "00 00 00 00 FF 00 00 00", base: 0.96, critical: true },
    v2x:   { label: "V2X position spoof", bus: "V2X", id: "0x6A2", sig: "Position",
             data: "4D 9A 21 0F 00 00 00 00", base: 0.84, critical: false },
    dos:   { label: "Message flood (DoS)", bus: "CAN", id: "0x000", sig: "Flood",
             data: "00 00 00 00 00 00 00 00", base: 0.99, critical: true, burst: 25 },
  };

  const NORMAL = [
    { bus: "CAN", id: "0x0C4", sig: "Speed" },
    { bus: "CAN", id: "0x1A0", sig: "Brake" },
    { bus: "CAN", id: "0x2B0", sig: "Steering" },
    { bus: "V2X", id: "0x6A2", sig: "Position" },
  ];

  /* ---------- State ---------- */
  const state = {
    veh: { speed: 62, brake: 5, steer: 0 },
    counts: { tp: 0, fp: 0, fn: 0, tn: 0, blocked: 0, frames: 0 },
    lat: [],
    points: [],
    attack: null,
    attackUntil: 0,
    attackFlagged: false,
    failsafe: false,
    muted: false,
    unread: 0,
  };

  /* ---------- Helpers ---------- */
  const rnd = (a, b) => a + Math.random() * (b - a);
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const gauss = () =>
    Math.sqrt(-2 * Math.log(Math.random() || 1e-9)) * Math.cos(2 * Math.PI * Math.random());
  const randHex = () =>
    Array.from({ length: 8 }, () =>
      Math.floor(Math.random() * 256).toString(16).toUpperCase().padStart(2, "0")
    ).join(" ");
  const timeStr = () => {
    const d = new Date();
    return d.toTimeString().slice(0, 8) + "." + String(d.getMilliseconds()).padStart(3, "0");
  };
  const fmtPct = (v) => (v === null ? "—" : (100 * v).toFixed(1) + "%");

  function metrics() {
    const { tp, fp, fn, tn } = state.counts;
    const prec = tp + fp ? tp / (tp + fp) : null;
    const rec = tp + fn ? tp / (tp + fn) : null;
    const f1 = prec !== null && rec !== null && prec + rec > 0 ? (2 * prec * rec) / (prec + rec) : null;
    const fpr = fp + tn ? fp / (fp + tn) : null;
    return { prec, rec, f1, fpr };
  }

  /* ---------- Logging and notifications ---------- */
  function addLog(type, title, meta) {
    const li = document.createElement("li");
    if (type === "crit") li.className = "crit";
    else if (type === "good") li.className = "good";

    const b = document.createElement("b");
    b.textContent = title;
    const sm = document.createElement("small");
    sm.textContent = `${timeStr().slice(0, 8)} · ${meta}`;
    li.append(b, sm);

    const log = $("log");
    log.prepend(li);
    while (log.children.length > MAX_LOG) log.lastElementChild.remove();
  }

  function toast(title, msg, good) {
    const el = document.createElement("div");
    el.className = "toast" + (good ? " good" : "");
    const b = document.createElement("b");
    b.textContent = title;
    const s = document.createElement("span");
    s.textContent = msg;
    el.append(b, s);
    $("toasts").appendChild(el);
    setTimeout(() => el.remove(), 4000);
  }

  let audioCtx = null;
  function beep() {
    if (state.muted) return;
    try {
      audioCtx = audioCtx || new (window.AudioContext || window.webkitAudioContext)();
      const o = audioCtx.createOscillator();
      const g = audioCtx.createGain();
      o.frequency.value = 880;
      g.gain.value = 0.05;
      o.connect(g);
      g.connect(audioCtx.destination);
      o.start();
      o.stop(audioCtx.currentTime + 0.2);
    } catch (e) {
      /* audio unavailable; fail silently */
    }
  }

  /* ---------- Traffic table ---------- */
  function addRow(f, result, cls) {
    const tb = $("rows");
    const tr = document.createElement("tr");
    const displayId = f.count && f.count > 1 ? `${f.id} ×${f.count}` : f.id;
    const scoreVal = typeof f.score === "number" ? f.score.toFixed(2) : f.score;
    const cells = [
      f.time || timeStr(),
      f.bus,
      displayId,
      f.data,
      scoreVal,
      result,
    ];
    cells.forEach((text, i) => {
      const td = document.createElement("td");
      td.textContent = text;
      if (i === 5) td.className = "tag " + cls;
      tr.appendChild(td);
    });
    tb.prepend(tr);
    while (tb.children.length > MAX_ROWS) tb.lastElementChild.remove();
  }

  /* ---------- Detection ---------- */
  // f: { bus, id, data, score, malicious, count }
  // Returns true if the frame was flagged.
  function handleFrame(f) {
    const predicted = f.score > THRESHOLD;
    const n = f.count;
    const c = state.counts;
    c.frames += n;

    if (f.malicious) {
      if (predicted) { c.tp += n; c.blocked += n; }
      else c.fn += n;
    } else {
      if (predicted) c.fp += n;
      else c.tn += n;
    }

    state.lat.push(rnd(4, 9));
    if (state.lat.length > 50) state.lat.shift();

    let result, cls;
    if (f.malicious && predicted)       { result = "BLOCKED";  cls = "ok"; }
    else if (f.malicious)               { result = "PASSED";   cls = "bad"; }
    else if (predicted)                 { result = "FLAGGED";  cls = "warn"; }
    else                                { result = "OK";       cls = "ok"; }

    addRow(f, result, cls);
    return predicted;
  }

  function pushPoint(score, attacking) {
    state.points.push({ s: score, a: attacking });
    if (state.points.length > POINTS) state.points.shift();
  }

  function tick() {
    const now = Date.now();
    if (state.attack && now >= state.attackUntil) endAttack();

    driveVehicle();

    let peak = 0;

    // Normal background traffic
    for (let i = 0; i < NORMAL_FRAMES_PER_TICK; i++) {
      const m = NORMAL[Math.floor(Math.random() * NORMAL.length)];
      const score = Math.random() < 0.01 ? rnd(0.55, 0.7) : clamp(0.18 + gauss() * 0.08, 0.02, 0.45);
      handleFrame({
        bus: m.bus, id: m.id, data: randHex(), score, malicious: false, count: 1,
      });
      peak = Math.max(peak, score);
    }

    // Attack traffic (ground truth: malicious)
    if (state.attack) {
      const a = ATTACKS[state.attack];
      let score = a.base + rnd(-0.05, 0.05);
      if (Math.random() < 0.03) score = rnd(0.3, 0.45); // occasional missed frame
      const flagged = handleFrame({
        bus: a.bus, id: a.id, data: a.data, score,
        malicious: true, count: a.burst || 1,
      });
      peak = Math.max(peak, score);
      if (flagged && !state.attackFlagged) onDetect(state.attack, score);
    }

    pushPoint(peak, !!state.attack);
    render();
  }

  function onDetect(key, score) {
    const a = ATTACKS[key];
    state.attackFlagged = true;
    state.unread++;
    beep();
    addLog("crit", `Attack blocked: ${a.label}`,
      `${a.bus} ${a.id} · score ${score.toFixed(2)} · ${a.critical ? "fail-safe engaged" : "frame dropped"}`);
    toast("Attack detected", `${a.label} blocked on ${a.bus}.`, false);
    if (a.critical && !state.failsafe) engageFailsafe();
  }

  function engageFailsafe() {
    state.failsafe = true;
    addLog("crit", "Fail-safe engaged",
      "Vehicle is slowing to a controlled stop. Manual reset required.");
  }

  /* ---------- Attack control ---------- */
  function startAttack(key) {
    if (state.attack) return;
    state.attack = key;
    state.attackUntil = Date.now() + ATTACK_MS;
    state.attackFlagged = false;
    addLog("info", `Attack injected: ${ATTACKS[key].label}`,
      `${ATTACKS[key].bus} ${ATTACKS[key].id} · simulator`);
    render();
  }

  function endAttack() {
    const a = ATTACKS[state.attack];
    if (!state.attackFlagged) {
      addLog("crit", `Missed attack: ${a.label}`, "No frame crossed the threshold in this window");
    } else {
      addLog("good", "Attack window closed",
        `${a.label} · ${state.failsafe ? "fail-safe still latched" : "system nominal"}`);
    }
    state.attack = null;
    state.attackFlagged = false;
  }

  /* ---------- Vehicle model ---------- */
  function driveVehicle() {
    const v = state.veh;
    if (state.failsafe) {
      v.speed = Math.max(0, v.speed - 2.5);
      v.brake = Math.min(70, v.brake + 8);
      v.steer *= 0.8;
    } else {
      v.speed = clamp(v.speed + rnd(-1.5, 1.5), 55, 68);
      v.brake = clamp(v.brake + rnd(-2, 2), 0, 10);
      v.steer = clamp(v.steer + rnd(-2, 2), -20, 20);
    }
  }

  /* ---------- Rendering ---------- */
  function setCheck(n, cls, text) {
    $("c" + n).className = "dot " + cls;
    const t = $("t" + n);
    t.textContent = text;
    t.className = cls;
  }

  function render() {
    const s = state;
    const c = s.counts;
    const v = s.veh;
    const active = s.attack ? ATTACKS[s.attack] : null;
    const flagged = s.attackFlagged;

    // KPIs
    $("kFrames").textContent = c.frames.toLocaleString();
    $("kBlocked").textContent = c.blocked.toLocaleString();
    const avg = s.lat.length ? s.lat.reduce((a, b) => a + b, 0) / s.lat.length : null;
    $("kLat").textContent = avg === null ? "—" : avg.toFixed(1) + " ms";

    const m = metrics();
    $("kConf").textContent = fmtPct(m.f1);
    $("mTP").textContent = c.tp.toLocaleString();
    $("mFP").textContent = c.fp.toLocaleString();
    $("mFN").textContent = c.fn.toLocaleString();
    $("mTN").textContent = c.tn.toLocaleString();
    $("mPrec").textContent = fmtPct(m.prec);
    $("mRec").textContent = fmtPct(m.rec);
    $("mF1").textContent = fmtPct(m.f1);
    $("mFPR").textContent = fmtPct(m.fpr);

    // Vehicle
    $("vSpeed").textContent = Math.round(v.speed) + " km/h";
    $("bSpeed").style.width = ((v.speed / 120) * 100).toFixed(1) + "%";
    $("vBrake").textContent = Math.round(v.brake) + "%";
    $("bBrake").style.width = v.brake.toFixed(1) + "%";
    $("vSteer").textContent = Math.round(v.steer) + "°";
    $("bSteer").style.width = ((Math.abs(v.steer) / 20) * 100).toFixed(1) + "%";
    const mode = $("vMode");
    mode.textContent = s.failsafe ? "Safe mode" : "Normal";
    mode.className = "mode" + (s.failsafe ? " bad" : "");

    // Subsystem checks
    const canHit = flagged && active && active.bus === "CAN";
    const v2xHit = flagged && active && active.bus === "V2X";
    const canWatch = active && active.bus === "CAN";
    const v2xWatch = active && active.bus === "V2X";
    setCheck(1, canHit ? "bad" : canWatch ? "warn" : "ok", canHit ? "Under attack" : canWatch ? "Monitoring" : "Normal");
    setCheck(2, v2xHit ? "bad" : v2xWatch ? "warn" : "ok", v2xHit ? "Under attack" : v2xWatch ? "Monitoring" : "Normal");
    setCheck(3, "ok", "Running");
    setCheck(4, s.failsafe ? "bad" : "ok", s.failsafe ? "Engaged" : "Standby");

    // Status panel
    let title, sub, bad;
    if (s.failsafe) {
      title = "Fail-safe engaged";
      sub = "Malicious traffic was blocked. The vehicle is slowing to a controlled stop. Reset the system to resume.";
      bad = true;
    } else if (flagged && active) {
      title = "Attack blocked";
      sub = `${active.label} was rejected. Monitoring continues.`;
      bad = true;
    } else if (active) {
      title = "Monitoring suspicious traffic";
      sub = "Inspecting incoming frames.";
      bad = false;
    } else {
      title = "All systems healthy";
      sub = "No anomalies detected. Every CAN and V2X message looks normal.";
      bad = false;
    }
    $("sTitle").textContent = title;
    $("sSub").textContent = sub;
    $("status").classList.toggle("bad", bad);
    $("shieldMark").setAttribute("d", bad ? "M12 8v5M12 16.2v.1" : "M8.5 12l2.5 2.5 4.5-5");

    // Header pill, banner, badge
    $("pill").classList.toggle("bad", bad);
    $("pillTxt").textContent = s.failsafe ? "Fail-safe" : bad ? "Under attack" : "Secure";
    const banner = $("banner");
    banner.textContent = s.failsafe
      ? "FAIL-SAFE ENGAGED: critical attack blocked. Reset the system to resume."
      : "";
    banner.classList.toggle("on", s.failsafe);
    $("badge").style.display = s.unread ? "grid" : "none";
    $("badge").textContent = s.unread > 9 ? "9+" : String(s.unread);

    // Simulator buttons: one attack at a time
    document.querySelectorAll(".sim button[data-a]").forEach((b) => {
      b.disabled = !!s.attack;
    });

    drawChart();
  }

  function drawChart() {
    const c = $("chart");
    if (!c) return;
    const ctx = c.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const w = c.clientWidth;
    const h = c.clientHeight;
    if (!w || !h) return;

    if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) {
      c.width = Math.round(w * dpr);
      c.height = Math.round(h * dpr);
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const css = getComputedStyle(document.documentElement);
    const color = (name) => css.getPropertyValue(name).trim();
    const pad = 10;
    const plotH = h - pad * 2;
    const yOf = (v) => pad + plotH * (1 - clamp(v, 0, 1));
    const step = w / (POINTS - 1);
    const xOf = (i) => (POINTS - state.points.length + i) * step;

    // Grid
    ctx.strokeStyle = color("--line");
    ctx.lineWidth = 1;
    [0.25, 0.5, 0.75].forEach((g) => {
      ctx.beginPath();
      ctx.moveTo(0, yOf(g));
      ctx.lineTo(w, yOf(g));
      ctx.stroke();
    });

    // Attack windows
    ctx.globalAlpha = 0.18;
    ctx.fillStyle = color("--bad");
    state.points.forEach((p, i) => {
      if (p.a) ctx.fillRect(xOf(i) - step / 2, 0, step, h);
    });
    ctx.globalAlpha = 1;

    // Threshold line
    ctx.setLineDash([6, 4]);
    ctx.strokeStyle = color("--bad");
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(0, yOf(THRESHOLD));
    ctx.lineTo(w, yOf(THRESHOLD));
    ctx.stroke();
    ctx.setLineDash([]);

    // Score line
    if (state.points.length > 1) {
      ctx.strokeStyle = color("--acc");
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.beginPath();
      state.points.forEach((p, i) => {
        const x = xOf(i);
        const y = yOf(p.s);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }
  }

  /* ---------- Reset ---------- */
  function reset() {
    state.counts = { tp: 0, fp: 0, fn: 0, tn: 0, blocked: 0, frames: 0 };
    state.lat = [];
    state.points = [];
    state.attack = null;
    state.attackFlagged = false;
    state.failsafe = false;
    state.unread = 0;
    state.veh = { speed: 62, brake: 5, steer: 0 };
    $("rows").innerHTML = "";
    $("log").innerHTML = "";
    addLog("good", "System reset", "Monitoring CAN and V2X. Fail-safe cleared.");
    toast("System reset", "Fail-safe cleared. Monitoring resumed.", true);
    render();
  }

  /* ---------- Backend Connection ---------- */
  const API_BASE = window.location.origin.includes(":8000")
    ? window.location.origin
    : "http://localhost:8000";

  let backendActive = false;
  let eventSource = null;
  let localTicker = null;

  function setBackendStatus(online, msg) {
    const pill = $("backendPill");
    const txt = $("backendTxt");
    if (!pill || !txt) return;
    if (online) {
      pill.className = "pill backend-pill online";
      txt.textContent = msg || "Backend: Connected (FastAPI)";
    } else {
      pill.className = "pill backend-pill offline";
      txt.textContent = msg || "Backend: Offline (Local Mode)";
    }
  }

  function connectBackend() {
    try {
      if (eventSource) {
        eventSource.close();
      }
      eventSource = new EventSource(`${API_BASE}/api/stream`);

      eventSource.onopen = () => {
        backendActive = true;
        setBackendStatus(true);
        if (localTicker) {
          clearInterval(localTicker);
          localTicker = null;
        }
      };

      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handleBackendTick(data);
        } catch (err) {
          console.error("Stream parse error:", err);
        }
      };

      eventSource.onerror = () => {
        backendActive = false;
        setBackendStatus(false);
        if (!localTicker) {
          localTicker = setInterval(tick, TICK_MS);
        }
      };
    } catch (err) {
      backendActive = false;
      setBackendStatus(false);
      if (!localTicker) {
        localTicker = setInterval(tick, TICK_MS);
      }
    }
  }

  function handleBackendTick(data) {
    state.failsafe = data.failsafe;
    state.attack = data.active_attack;
    state.attackFlagged = data.attack_flagged;
    state.counts = data.counts;
    state.veh = data.vehicle;
    if (data.avg_latency) {
      state.lat = [data.avg_latency];
    }

    if (Array.isArray(data.frames)) {
      data.frames.forEach((f) => {
        addRow(f, f.result, f.tag);
      });
    }

    pushPoint(data.peak_score, !!data.active_attack);

    if (data.alert) {
      state.unread++;
      beep();
      addLog(data.alert.type, data.alert.title, data.alert.meta);
      toast("Attack detected", data.alert.title, false);
    }

    render();
  }

  /* ---------- UI wiring ---------- */
  function wireUI() {
    $("thrVal").textContent = THRESHOLD.toFixed(2);

    document.querySelectorAll(".sim button[data-a]").forEach((b) =>
      b.addEventListener("click", () => {
        const atkKey = b.dataset.a;
        if (backendActive) {
          fetch(`${API_BASE}/api/attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ attack_type: atkKey })
          }).catch(() => startAttack(atkKey));
        } else {
          startAttack(atkKey);
        }
      })
    );

    $("reset").addEventListener("click", () => {
      if (backendActive) {
        fetch(`${API_BASE}/api/reset`, { method: "POST" }).catch(() => {});
      }
      reset();
    });

    $("avatar").addEventListener("click", (e) => {
      e.stopPropagation();
      const open = $("menu").classList.toggle("on");
      $("avatar").setAttribute("aria-expanded", String(open));
    });
    document.addEventListener("click", (e) => {
      if (!$("menu").contains(e.target)) $("menu").classList.remove("on");
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") $("menu").classList.remove("on");
    });

    $("muteBtn").addEventListener("click", () => {
      state.muted = !state.muted;
      $("muteBtn").textContent = state.muted ? "Unmute alert sound" : "Mute alert sound";
    });

    $("themeBtn").addEventListener("click", () => {
      const root = document.documentElement;
      const current = root.dataset.theme ||
        (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
      root.dataset.theme = current === "light" ? "dark" : "light";
      drawChart();
    });

    $("outBtn").addEventListener("click", () =>
      toast("Demo mode", "Sign-in is not part of this prototype.", true)
    );

    $("bell").addEventListener("click", () => {
      state.unread = 0;
      render();
      $("log").closest(".card").scrollIntoView({ behavior: "smooth", block: "center" });
    });

    window.addEventListener("resize", drawChart);
  }

  /* ---------- Start ---------- */
  wireUI();
  addLog("info", "System started", "Monitoring CAN and V2X traffic");
  render();

  // Connect to FastAPI backend; if offline, fallback to local tick loop
  connectBackend();
})();