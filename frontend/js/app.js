/* ============================================================
   PHISHGUARD — FRONTEND APPLICATION
   ============================================================ */

const API_BASE = "http://localhost:8000";
const GAUGE_CIRCUMFERENCE = 534.07; // 2 * π * 85

// DOM Elements
const urlInput = document.getElementById("url-input");
const contentTypeSelect = document.getElementById("content-type-select");
const scanBtn = document.getElementById("scan-btn");
const inputHint = document.getElementById("input-hint");
const statusDot = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
const resultsSection = document.getElementById("results-section");
const historySection = document.getElementById("history-section");
const historyBody = document.getElementById("history-body");
const clearHistoryBtn = document.getElementById("clear-history-btn");

// Gauge elements
const gaugeFill = document.getElementById("gauge-fill");
const gaugeValue = document.getElementById("gauge-value");
const verdictBox = document.getElementById("verdict-box");
const verdictIcon = document.getElementById("verdict-icon");
const verdictText = document.getElementById("verdict-text");
const scannedUrl = document.getElementById("scanned-url");
const mlProb = document.getElementById("ml-prob");
const hScore = document.getElementById("h-score");
const confidence = document.getElementById("confidence");
const verdictLabel = document.getElementById("verdict-label");

let scanHistory = [];

/* ============================================================
   BACKEND STATUS CHECK
   ============================================================ */
async function checkBackendStatus() {
  try {
    const res = await fetch(`${API_BASE}/`, {
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      statusDot.className = "status-dot online";
      statusText.textContent = "ONLINE";
      scanBtn.disabled = false;
      return true;
    }
  } catch (_) {
    // fall through
  }
  statusDot.className = "status-dot offline";
  statusText.textContent = "OFFLINE";
  scanBtn.disabled = true;
  return false;
}

// Check every 10s
checkBackendStatus();
setInterval(checkBackendStatus, 10000);

/* ============================================================
   INPUT VALIDATION
   ============================================================ */

function isValidInput(str, type) {
  if (type === "url") {
    try {
      const url = new URL(str);
      return url.protocol === "http:" || url.protocol === "https:";
    } catch {
      return false;
    }
  } else if (type === "email") {
    // Accept any non-empty string for email (could add more checks)
    return str.trim().length > 0;
  }
  return false;
}

function updateInputHint() {
  const val = urlInput.value.trim();
  const type = contentTypeSelect.value;
  if (val === "") {
    urlInput.classList.remove("error");
    inputHint.textContent =
      type === "url"
        ? "Paste any URL starting with http:// or https://"
        : "Paste the email text you want to check";
    inputHint.classList.remove("error");
    scanBtn.disabled = statusDot.classList.contains("offline");
  } else if (!isValidInput(val, type)) {
    urlInput.classList.add("error");
    inputHint.textContent =
      type === "url"
        ? "⚠ Invalid URL — must start with http:// or https://"
        : "⚠ Please paste the email content to scan";
    inputHint.classList.add("error");
    scanBtn.disabled = true;
  } else {
    urlInput.classList.remove("error");
    inputHint.textContent = "Press SCAN or hit Enter to analyze";
    inputHint.classList.remove("error");
    scanBtn.disabled = false;
  }
}

urlInput.addEventListener("input", updateInputHint);
contentTypeSelect.addEventListener("change", () => {
  // Change placeholder and clear input
  if (contentTypeSelect.value === "url") {
    urlInput.placeholder = "Enter URL to analyze...";
  } else {
    urlInput.placeholder = "Paste email content to analyze...";
  }
  urlInput.value = "";
  updateInputHint();
});
updateInputHint();

urlInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !scanBtn.disabled) {
    handleScan();
  }
});

scanBtn.addEventListener("click", handleScan);

/* ============================================================
   SCAN HANDLER
   ============================================================ */
async function handleScan() {
  const content = urlInput.value.trim();
  const contentType = contentTypeSelect.value;
  if (!isValidInput(content, contentType)) return;

  // UI: scanning state
  scanBtn.classList.add("scanning");
  scanBtn.disabled = true;
  urlInput.disabled = true;
  contentTypeSelect.disabled = true;

  try {
    const res = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        content,
        content_type: contentType,
      }),
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Server error" }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    renderResults(content, data, contentType);
    addToHistory(content, data, contentType);
  } catch (err) {
    inputHint.textContent = `⚠ Error: ${err.message}`;
    inputHint.classList.add("error");
  } finally {
    scanBtn.classList.remove("scanning");
    scanBtn.disabled = false;
    urlInput.disabled = false;
    contentTypeSelect.disabled = false;
    urlInput.focus();
  }
}

/* ============================================================
   RENDER RESULTS
   ============================================================ */
function renderResults(url, data) {
  resultsSection.style.display = "";

  const isPhishing = data.prediction === "phishing";
  const risk = data.confidence;

  // --- Gauge animation ---
  const offset = GAUGE_CIRCUMFERENCE - (GAUGE_CIRCUMFERENCE * risk) / 100;
  gaugeFill.style.strokeDashoffset = offset;

  // Color based on risk
  const gaugeColor = risk > 60 ? "#ff2244" : risk > 30 ? "#ffe600" : "#39ff14";
  gaugeFill.style.stroke = gaugeColor;
  gaugeValue.style.color = gaugeColor;

  // Animate counter
  animateCounter(gaugeValue, risk);

  // --- Verdict ---
  verdictBox.className = `verdict-box ${isPhishing ? "phishing" : "safe"}`;
  verdictIcon.textContent = isPhishing ? "🔴" : "🟢";
  verdictText.textContent = isPhishing ? "PHISHING DETECTED" : "SAFE";

  // --- Scanned URL ---
  scannedUrl.textContent = url;

  // --- Metrics ---
  mlProb.textContent = `${(data.ml_probability * 100).toFixed(1)}%`;
  hScore.textContent = `+${data.heuristic_score}`;
  confidence.textContent = `${data.confidence}%`;
  verdictLabel.textContent = data.prediction.toUpperCase();
  verdictLabel.style.color = isPhishing ? "#ff2244" : "#39ff14";

  // Scroll to results
  resultsSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function animateCounter(el, target) {
  const duration = 1000;
  const start = performance.now();
  const from = 0;

  function tick(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    // Ease out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = Math.round(from + (target - from) * eased);
    el.textContent = current;
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

/* ============================================================
   SCAN HISTORY
   ============================================================ */
function addToHistory(url, data) {
  const entry = {
    time: new Date().toLocaleTimeString(),
    url,
    prediction: data.prediction,
    confidence: data.confidence,
  };
  scanHistory.unshift(entry);

  // Keep last 20
  if (scanHistory.length > 20) scanHistory.pop();

  renderHistory();
}

function renderHistory() {
  if (scanHistory.length === 0) {
    historySection.style.display = "none";
    return;
  }

  historySection.style.display = "";
  historyBody.innerHTML = "";

  scanHistory.forEach((entry) => {
    const tr = document.createElement("tr");
    const isPhishing = entry.prediction === "phishing";
    const barColor =
      entry.confidence > 60
        ? "#ff2244"
        : entry.confidence > 30
          ? "#ffe600"
          : "#39ff14";

    tr.innerHTML = `
      <td>${entry.time}</td>
      <td><span class="history-url" title="${escapeHtml(entry.url)}">${escapeHtml(entry.url)}</span></td>
      <td><span class="badge ${isPhishing ? "phishing" : "safe"}">${entry.prediction.toUpperCase()}</span></td>
      <td class="risk-bar-cell">
        <div class="risk-bar-bg">
          <div class="risk-bar-fill" style="width:${entry.confidence}%; background:${barColor}"></div>
        </div>
      </td>
    `;
    historyBody.appendChild(tr);
  });
}

clearHistoryBtn.addEventListener("click", () => {
  scanHistory = [];
  renderHistory();
  resultsSection.style.display = "none";
});

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/* ============================================================
   MATRIX RAIN BACKGROUND
   ============================================================ */
function initMatrixRain() {
  const canvas = document.getElementById("matrix-canvas");
  const ctx = canvas.getContext("2d");

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener("resize", resize);

  const chars =
    "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヰヱヲン0123456789ABCDEF<>/{}[]|";
  const charArr = chars.split("");
  const fontSize = 14;
  let columns = Math.floor(canvas.width / fontSize);
  let drops = new Array(columns).fill(1);

  window.addEventListener("resize", () => {
    columns = Math.floor(canvas.width / fontSize);
    drops = new Array(columns).fill(1);
  });

  function draw() {
    ctx.fillStyle = "rgba(10, 10, 15, 0.08)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = "#00f0ff";
    ctx.font = `${fontSize}px monospace`;

    for (let i = 0; i < drops.length; i++) {
      const char = charArr[Math.floor(Math.random() * charArr.length)];
      ctx.fillText(char, i * fontSize, drops[i] * fontSize);

      if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i]++;
    }
  }

  setInterval(draw, 50);
}

initMatrixRain();
