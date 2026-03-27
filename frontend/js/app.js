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

// Helper to wait for DOM - ensuring no null style errors
const getEl = (id) => document.getElementById(id);

// Gauge elements
const gaugeFill = getEl("gauge-fill");
const gaugeValue = getEl("gauge-value");
const verdictBox = getEl("verdict-box");
const verdictText = getEl("verdict-text");
const scannedUrl = getEl("scanned-url");
const mlProb = getEl("ml-prob");
const hScore = getEl("h-score");
const verdictLabel = getEl("verdict-label");

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
      statusDot.className = "w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(16,185,129,0.5)]";
      statusText.textContent = "ONLINE";
      statusText.className = "text-[10px] font-bold uppercase tracking-widest text-emerald-500";
      scanBtn.disabled = false;
      return true;
    }
  } catch (_) {
    // fall through
  }
  statusDot.className = "w-2 h-2 rounded-full bg-red-400";
  statusText.textContent = "OFFLINE";
  statusText.className = "text-[10px] font-bold uppercase tracking-widest text-red-500";
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
    return str.trim().length > 0;
  }
  return false;
}

function updateInputHint() {
  const val = urlInput.value.trim();
  const type = contentTypeSelect.value;
  if (!val) {
    urlInput.classList.remove("border-red-500", "bg-red-50");
    inputHint.textContent = type === "url" ? "Paste any URL starting with http:// or https://" : "Paste the email text you want to check";
    inputHint.className = "text-xs text-slate-400 px-2 italic";
    scanBtn.disabled = statusText.textContent === "OFFLINE";
  } else if (!isValidInput(val, type)) {
    urlInput.classList.add("border-red-500", "bg-red-50");
    inputHint.textContent = type === "url" ? "⚠ Invalid URL — must start with http:// or https://" : "⚠ Please paste the email content to scan";
    inputHint.className = "text-xs text-red-500 px-2 font-bold";
    scanBtn.disabled = true;
  } else {
    urlInput.classList.remove("border-red-500", "bg-red-50");
    inputHint.textContent = "Ready to scan content.";
    inputHint.className = "text-xs text-emerald-500 px-2 font-bold";
    scanBtn.disabled = false;
  }
}

urlInput.addEventListener("input", updateInputHint);
contentTypeSelect.addEventListener("change", () => {
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

  const btnText = document.getElementById("btn-text");
  const btnLoader = document.getElementById("btn-loader");
  if (btnText) btnText.classList.add("hidden");
  if (btnLoader) btnLoader.classList.remove("hidden");
  
  scanBtn.disabled = true;
  urlInput.disabled = true;

  try {
    const res = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content, content_type: contentType }),
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: "Server error" }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    renderResults(content, data);
    addToHistory(content, data);
  } catch (err) {
    inputHint.textContent = `⚠ Error: ${err.message}`;
    inputHint.className = "text-xs text-red-500 px-2 font-bold";
  } finally {
    if (btnText) btnText.classList.remove("hidden");
    if (btnLoader) btnLoader.classList.add("hidden");
    scanBtn.disabled = false;
    urlInput.disabled = false;
    urlInput.focus();
  }
}

/* ============================================================
   RENDER RESULTS
   ============================================================ */
function renderResults(url, data) {
  const section = getEl("results-section");
  if (section) {
    section.style.display = "grid";
    section.classList.remove("hidden");
  }

  const isPhishing = data.prediction === "phishing" || data.prediction === "Malicious";
  const risk = data.confidence;

  const gFill = getEl("gauge-fill");
  if (gFill) {
    const circumference = 502;
    const offset = circumference - (circumference * risk) / 100;
    gFill.style.strokeDasharray = "502";
    gFill.style.strokeDashoffset = offset.toString();
    gFill.style.stroke = risk > 60 ? "#ef4444" : risk > 30 ? "#f59e0b" : "#6367FF";
  }

  const gVal = getEl("gauge-value");
  if (gVal) {
    animateCounter(gVal, risk);
    gVal.style.color = risk > 60 ? "#ef4444" : risk > 30 ? "#f59e0b" : "#6367FF";
  }

  const vBox = getEl("verdict-box");
  if (vBox) {
    vBox.className = `px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-widest ${isPhishing ? "bg-red-50 text-red-600 border border-red-200" : "bg-emerald-50 text-emerald-600 border border-emerald-200"}`;
  }
  const vText = getEl("verdict-text");
  if (vText) vText.textContent = isPhishing ? "PHISHING DETECTED" : "SAFE";

  const sUrl = getEl("scanned-url");
  if (sUrl) sUrl.textContent = url.length > 50 ? url.substring(0, 47) + "..." : url;

  const mlProbEl = getEl("ml-prob");
  const hScoreEl = getEl("h-score");
  if (mlProbEl) mlProbEl.textContent = `${(data.ml_probability * 100).toFixed(0)}%`;
  if (hScoreEl) hScoreEl.textContent = `+${data.heuristic_score}`;

  const vLabel = getEl("verdict-label");
  if (vLabel) {
    vLabel.textContent = isPhishing ? "THREAT" : "SECURE";
    vLabel.style.color = isPhishing ? "#ef4444" : "#6367FF";
  }

  const expText = getEl("explanation-text");
  if (expText) {
    expText.textContent = data.explanation || (isPhishing ? "This source appears dangerous. Proceed with extreme caution." : "No major threats found.");
    expText.classList.remove("italic", "text-slate-400");
  }

  const keywordContainer = getEl("keyword-pills");
  if (keywordContainer) {
    keywordContainer.innerHTML = "";
    const keywords = data.keywords || (isPhishing ? ["Urgent", "Verification", "Sensitive"] : ["Verified", "Secure", "Legit"]);
    
    keywords.forEach(word => {
      const span = document.createElement("span");
      span.className = "px-4 py-1.5 bg-primary/5 text-primary border border-primary/10 rounded-full text-[10px] font-black uppercase tracking-widest";
      span.textContent = word;
      keywordContainer.appendChild(span);
    });
  }

  const recContainer = getEl("recommendations-container");
  if (recContainer) {
    recContainer.innerHTML = "";
    const recs = data.recommendations || (isPhishing ? ["Do not click any links.", "Report this sender.", "Delete the email immediately."] : ["Continue with caution.", "Verify external links.", "Ensure 2FA is enabled."]);
    recs.forEach((rec, idx) => {
      const div = document.createElement("div");
      div.className = "flex gap-4 items-start";
      div.innerHTML = `
        <div class="w-8 h-8 rounded-full bg-[#6367FF]/10 flex items-center justify-center shrink-0">
          <span class="text-[#6367FF] text-xs font-bold">${String(idx + 1).padStart(2, '0')}</span>
        </div>
        <p class="text-sm font-medium text-slate-700">${rec}</p>
      `;
      recContainer.appendChild(div);
    });
  }

  if (section) section.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function animateCounter(el, target) {
  const duration = 1200;
  const start = performance.now();
  const from = parseFloat(el.textContent) || 0;

  function tick(now) {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = from + (target - from) * eased;
    el.textContent = current.toFixed(current % 1 === 0 ? 0 : 2);
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function addToHistory(url, data) {
  const entry = {
    time: new Date().toLocaleTimeString(),
    url,
    prediction: data.prediction,
    confidence: data.confidence,
  };
  scanHistory.unshift(entry);
  if (scanHistory.length > 20) scanHistory.pop();
}
