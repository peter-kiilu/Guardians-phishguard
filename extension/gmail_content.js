// ============================================================
// PhishGuard — Gmail DOM Inspection Content Script
// Scans email rows for phishing indicators directly from the DOM
// ============================================================

(function () {
  "use strict";

  // Prevent running multiple times
  if (window.__phishguardGmailLoaded) return;
  window.__phishguardGmailLoaded = true;

  const LOG_PREFIX = "[PhishGuard Gmail]";
  const BACKEND_URL = "http://localhost:8000";

  // Request background to close this tab
  function closeCurrentTab() {
    chrome.runtime.sendMessage({ action: "closeTab" });
  }

  // ── Gmail DOM Selectors ──────────────────────────────────────
  // Gmail uses obfuscated class names. These are current as of 2025
  // and may need updating if Gmail changes its HTML structure.
  const SELECTORS = {
    EMAIL_ROW: "tr.zA",                  // Each email row in the inbox
    SENDER: ".yW span[email], .yW .bA4", // Sender name / email
    SUBJECT: ".y6 span.bog",             // Subject text
    SNIPPET: ".y2",                      // Preview snippet
    EMAIL_BODY_VIEW: ".a3s.aiL",         // Full email body (when opened)
    INBOX_TABLE: "table.F.cf.zt",        // The inbox table container
  };

  // ── Trusted Sender Domains ───────────────────────────────────
  // Emails from these domains are NOT flagged for urgency phrases alone.
  // They can still be flagged if they contain phishing links or domains.
  const TRUSTED_SENDERS = new Set([
    "google.com",
    "gmail.com",
    "googlemail.com",
    "accounts.google.com",
    "microsoft.com",
    "outlook.com",
    "live.com",
    "hotmail.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "paypal.com",
    "facebook.com",
    "facebookmail.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "github.com",
    "netflix.com",
    "spotify.com",
    "youtube.com",
    "yahoo.com",
    "safaricom.co.ke",
    "equity.co.ke",
    "kcbgroup.com",
  ]);

  /**
   * Check if a sender domain is trusted (legitimate service).
   */
  function isTrustedSender(domain) {
    if (!domain) return false;
    if (TRUSTED_SENDERS.has(domain)) return true;
    // Check parent domain (e.g. "mail.google.com" → "google.com")
    for (const trusted of TRUSTED_SENDERS) {
      if (domain.endsWith("." + trusted)) return true;
    }
    return false;
  }

  // ── Analysis Functions ───────────────────────────────────────

  /**
   * Extract all URLs from a text string.
   */
  function extractUrls(text) {
    if (!text) return [];
    const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
    return text.match(urlRegex) || [];
  }

  /**
   * Get the domain from a URL string.
   */
  function getDomain(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  /**
   * Check if a domain matches or is a subdomain of any known phishing domain.
   */
  function isPhishingDomain(domain) {
    if (KNOWN_PHISHING_DOMAINS.has(domain)) return true;
    // Check if it's a subdomain of a known phishing domain
    for (const phishDomain of KNOWN_PHISHING_DOMAINS) {
      if (domain.endsWith("." + phishDomain)) return true;
    }
    return false;
  }

  /**
   * Check if a domain is a URL shortener.
   */
  function isUrlShortener(domain) {
    return URL_SHORTENERS.has(domain);
  }

  /**
   * Find urgency phrases in text and return matched phrases.
   */
  function findUrgencyPhrases(text) {
    if (!text) return [];
    // Reset the regex lastIndex since it's global
    URGENCY_REGEX.lastIndex = 0;
    const matches = [];
    let match;
    while ((match = URGENCY_REGEX.exec(text)) !== null) {
      matches.push(match[0]);
    }
    // Deduplicate
    return [...new Set(matches.map((m) => m.toLowerCase()))];
  }

  /**
   * Check for mismatched display text vs actual href in links.
   * Returns suspicious link info if the visible text looks like a URL
   * but points somewhere different.
   */
  function findMismatchedLinks(element) {
    const mismatched = [];
    const anchors = element.querySelectorAll("a[href]");
    anchors.forEach((a) => {
      const href = a.href;
      const displayText = a.textContent.trim();
      // If the display text looks like a URL
      if (/^https?:\/\//i.test(displayText)) {
        const displayDomain = getDomain(displayText);
        const hrefDomain = getDomain(href);
        if (displayDomain && hrefDomain && displayDomain !== hrefDomain) {
          mismatched.push({
            display: displayDomain,
            actual: hrefDomain,
          });
        }
      }
    });
    return mismatched;
  }

  /**
   * Analyze a single email row and return threat analysis results.
   */
  function analyzeEmailRow(row) {
    const reasons = [];

    // ─ Extract sender info ─
    const senderEl = row.querySelector(SELECTORS.SENDER);
    const senderEmail = senderEl ? (senderEl.getAttribute("email") || senderEl.textContent || "").trim() : "";
    const senderDomain = senderEmail.includes("@") ? senderEmail.split("@")[1].toLowerCase() : "";

    // ─ Extract subject ─
    const subjectEl = row.querySelector(SELECTORS.SUBJECT);
    const subject = subjectEl ? subjectEl.textContent.trim() : "";

    // ─ Extract snippet ─
    const snippetEl = row.querySelector(SELECTORS.SNIPPET);
    const snippet = snippetEl ? snippetEl.textContent.trim() : "";

    // Combined text for analysis
    const fullText = `${subject} ${snippet}`;

    // ─ Check 1: Sender from known phishing domain ─
    if (senderDomain && isPhishingDomain(senderDomain)) {
      reasons.push(`Sender domain <strong>${senderDomain}</strong> is a known phishing domain`);
    }

    // ─ Check 2: Urgency phrases (only flag if sender is NOT trusted) ─
    const urgencyMatches = findUrgencyPhrases(fullText);
    const senderIsTrusted = isTrustedSender(senderDomain);
    if (urgencyMatches.length > 0 && !senderIsTrusted) {
      reasons.push(
        `Urgency phrases detected: "${urgencyMatches.slice(0, 3).join('", "')}"`
      );
    }

    // ─ Check 3: URLs in subject/snippet ─
    const urls = extractUrls(fullText);
    for (const url of urls) {
      const domain = getDomain(url);
      if (isPhishingDomain(domain)) {
        reasons.push(
          `Contains link to known phishing domain: <span class="phishguard-tooltip-domain">${domain}</span>`
        );
      }
      if (isUrlShortener(domain)) {
        reasons.push(
          `Contains shortened URL (<span class="phishguard-tooltip-domain">${domain}</span>) — destination hidden`
        );
      }
    }

    // ─ Check 4: Mismatched link text vs href ─
    const mismatched = findMismatchedLinks(row);
    for (const m of mismatched) {
      reasons.push(
        `Link text shows <span class="phishguard-tooltip-domain">${m.display}</span> but goes to <span class="phishguard-tooltip-domain">${m.actual}</span>`
      );
    }

    // ─ Check 5: Links in snippet pointing to shorteners or phishing domains ─
    const snippetAnchors = row.querySelectorAll("a[href]");
    snippetAnchors.forEach((a) => {
      const domain = getDomain(a.href);
      if (domain && isPhishingDomain(domain) && !reasons.some((r) => r.includes(domain))) {
        reasons.push(
          `Contains link to phishing domain: <span class="phishguard-tooltip-domain">${domain}</span>`
        );
      }
      if (domain && isUrlShortener(domain) && !reasons.some((r) => r.includes(domain))) {
        reasons.push(
          `Contains shortened URL (<span class="phishguard-tooltip-domain">${domain}</span>)`
        );
      }
    });

    return {
      flagged: reasons.length > 0,
      reasons,
      sender: senderEmail,
      subject,
      snippet,
    };
  }

  /**
   * Send email data to backend for ML-based classification.
   */
  async function analyzeEmailWithBackend(subject, sender, snippet) {
    try {
      const response = await fetch(`${BACKEND_URL}/analyze-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subject, sender, snippet }),
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) return null;
      return await response.json();
    } catch (err) {
      // Backend may be offline — fail silently, local heuristics still work
      return null;
    }
  }

  // ── Badge & Tooltip Injection ────────────────────────────────

  /**
   * Inject a warning badge into a flagged email row.
   */
  function injectWarningBadge(row, analysis) {
    // Don't double-badge
    if (row.querySelector(".phishguard-badge")) return;

    row.classList.add("phishguard-flagged");

    const badge = document.createElement("span");
    badge.className = "phishguard-badge";
    badge.textContent = "Phishing Risk";

    // Build tooltip
    const tooltip = document.createElement("div");
    tooltip.className = "phishguard-tooltip";

    let tooltipHTML = `<div class="phishguard-tooltip-header">PhishGuard Alert</div>`;
    analysis.reasons.forEach((reason) => {
      tooltipHTML += `<div class="phishguard-tooltip-reason">${reason}</div>`;
    });

    tooltip.innerHTML = tooltipHTML;
    badge.appendChild(tooltip);

    // Insert badge next to the subject
    const subjectEl = row.querySelector(SELECTORS.SUBJECT);
    if (subjectEl && subjectEl.parentNode) {
      subjectEl.parentNode.appendChild(badge);
    } else {
      // Fallback: append to the row's first cell
      const firstCell = row.querySelector("td");
      if (firstCell) firstCell.appendChild(badge);
    }
  }

  // ── Scan Status Indicator ────────────────────────────────────

  let statusEl = null;
  let statusTimeout = null;

  function showScanStatus(message, flagCount) {
    if (!statusEl) {
      statusEl = document.createElement("div");
      statusEl.className = "phishguard-scan-status";
      document.body.appendChild(statusEl);
    }

    statusEl.innerHTML = `
      <span class="phishguard-scan-status-icon">🛡️</span>
      <span class="phishguard-scan-status-text">${message}</span>
    `;
    statusEl.classList.remove("phishguard-hidden");

    // Auto-hide after 4 seconds
    clearTimeout(statusTimeout);
    statusTimeout = setTimeout(() => {
      statusEl.classList.add("phishguard-hidden");
    }, 4000);
  }

  // ── Main Scanner ─────────────────────────────────────────────

  /**
   * Scan all visible email rows in the inbox.
   */
  async function scanInbox() {
    const rows = document.querySelectorAll(SELECTORS.EMAIL_ROW);
    if (rows.length === 0) return;

    // Silent scan — no console noise

    let flaggedCount = 0;
    const rowsToScan = [];

    rows.forEach((row) => {
      // Skip already-scanned rows
      if (row.dataset.phishguardScanned === "true") return;
      row.dataset.phishguardScanned = "true";
      rowsToScan.push(row);
    });

    // Process each row: local heuristics + async backend ML
    const scanPromises = rowsToScan.map(async (row) => {
      const analysis = analyzeEmailRow(row);

      // Also ask the backend for ML classification
      const mlResult = await analyzeEmailWithBackend(
        analysis.subject,
        analysis.sender,
        analysis.snippet
      );

      // If backend says phishing, add that as a reason
      if (mlResult && mlResult.prediction === "phishing") {
        analysis.reasons.push(
          `ML model classified as phishing (${mlResult.confidence}% confidence)`
        );
        analysis.flagged = true;
      }

      if (analysis.flagged) {
        flaggedCount++;
        injectWarningBadge(row, analysis);
        // Log only in debug mode
        console.debug(
          `${LOG_PREFIX} Flagged: "${analysis.subject}" from ${analysis.sender}`
        );
      }
    });

    await Promise.allSettled(scanPromises);

    const totalScanned = document.querySelectorAll('[data-phishguard-scanned="true"]').length;
    if (flaggedCount > 0) {
      showScanStatus(
        `Scanned <strong>${totalScanned}</strong> emails — <strong style="color:#ff2244">${flaggedCount} flagged</strong>`,
        flaggedCount
      );
    } else {
      showScanStatus(`Scanned <strong>${totalScanned}</strong> emails — all clear ✓`, 0);
    }

    // Silent completion
  }

  // ── Also scan currently-open email body ──────────────────────

  function scanOpenEmail() {
    const bodyEl = document.querySelector(SELECTORS.EMAIL_BODY_VIEW);
    if (!bodyEl || bodyEl.dataset.phishguardBodyScanned === "true") return;
    bodyEl.dataset.phishguardBodyScanned = "true";

    const hardReasons = [];   // Dangerous: phishing links, mismatched URLs
    const softReasons = [];   // Suspicious: urgency phrases only
    const bodyText = bodyEl.textContent || "";

    // Check urgency phrases in body
    const urgencyMatches = findUrgencyPhrases(bodyText);
    if (urgencyMatches.length > 0) {
      softReasons.push(`Urgency phrases: "${urgencyMatches.slice(0, 5).join('", "')}"`);
    }

    // Check all links in the body
    const anchors = bodyEl.querySelectorAll("a[href]");
    anchors.forEach((a) => {
      const domain = getDomain(a.href);
      // Skip google.com internal links
      if (isTrustedSender(domain)) return;
      if (isPhishingDomain(domain)) {
        hardReasons.push(`Link to phishing domain: ${domain}`);
        a.style.outline = "2px solid #ff2244";
        a.style.outlineOffset = "2px";
        a.title = `⚠ PhishGuard: Known phishing domain (${domain})`;
      }
      if (isUrlShortener(domain)) {
        hardReasons.push(`Shortened URL: ${domain}`);
        a.style.outline = "2px dashed #ff8a00";
        a.style.outlineOffset = "2px";
        a.title = `⚠ PhishGuard: Shortened URL — destination hidden (${domain})`;
      }
    });

    // Check for mismatched links
    const mismatched = findMismatchedLinks(bodyEl);
    mismatched.forEach((m) => {
      if (!isTrustedSender(m.actual)) {
        hardReasons.push(`Mismatched link: displays "${m.display}" but goes to "${m.actual}"`);
      }
    });

    const allReasons = [...hardReasons, ...softReasons];

    // Only block if there are HARD reasons (phishing links, mismatched URLs)
    if (hardReasons.length > 0) {
      showPhishingBlockOverlay(allReasons);
    } else if (softReasons.length > 0) {
      // Soft warning: just show the status bar, don't block
      showScanStatus(
        `Email has suspicious language — <strong style="color:#ff8a00">${softReasons.length} warning(s)</strong>`,
        softReasons.length
      );
    }
  }

  // ── Phishing Block Overlay ──────────────────────────────────

  /**
   * Show a full-screen blocking overlay when a phishing email is opened.
   * Forces the user to go back to inbox or dismiss.
   */
  function showPhishingBlockOverlay(reasons) {
    // Don't double-inject
    if (document.getElementById("phishguard-block-overlay")) return;

    const overlay = document.createElement("div");
    overlay.id = "phishguard-block-overlay";
    overlay.style.cssText = `
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      z-index: 999999;
      background: rgba(10, 0, 0, 0.95);
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      animation: phishguardFadeIn 0.3s ease;
    `;

    const reasonsList = reasons
      .map((r) => `<li style="margin: 6px 0; color: #ffcccc;">${r}</li>`)
      .join("");

    overlay.innerHTML = `
      <style>
        @keyframes phishguardFadeIn {
          from { opacity: 0; } to { opacity: 1; }
        }
        @keyframes phishguardPulse {
          0%, 100% { transform: scale(1); }
          50% { transform: scale(1.05); }
        }
        #phishguard-block-box {
          background: linear-gradient(135deg, #1a0000, #2a0a0a);
          border: 2px solid #ff2244;
          border-radius: 16px;
          padding: 40px;
          max-width: 520px;
          width: 90%;
          text-align: center;
          box-shadow: 0 0 60px rgba(255, 34, 68, 0.3);
        }
        #phishguard-block-box h1 {
          color: #ff2244;
          font-size: 24px;
          margin: 0 0 8px;
        }
        #phishguard-block-box .shield {
          font-size: 64px;
          animation: phishguardPulse 2s infinite;
        }
        #phishguard-block-box p {
          color: #ffaaaa;
          font-size: 14px;
          margin: 12px 0;
        }
        #phishguard-block-box ul {
          text-align: left;
          font-size: 13px;
          padding-left: 20px;
          margin: 16px 0;
        }
        .phishguard-block-btn {
          padding: 12px 28px;
          border: none;
          border-radius: 8px;
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          margin: 8px;
          transition: transform 0.15s, box-shadow 0.15s;
        }
        .phishguard-block-btn:hover {
          transform: translateY(-2px);
          box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        .phishguard-block-btn-primary {
          background: #ff2244;
          color: #fff;
        }
        .phishguard-block-btn-secondary {
          background: transparent;
          color: #888;
          border: 1px solid #444;
          font-size: 12px;
          padding: 8px 16px;
        }
      </style>
      <div id="phishguard-block-box">
        <div class="shield">🛡️</div>
        <h1>⚠ Phishing Email Detected</h1>
        <p>PhishGuard has detected dangerous content in this email.<br>
           <strong>Do not click any links or download attachments.</strong></p>
        <ul>${reasonsList}</ul>
        <div>
          <button class="phishguard-block-btn phishguard-block-btn-primary"
                  id="phishguard-close-tab">Close Tab</button>
          <button class="phishguard-block-btn phishguard-block-btn-secondary"
                  id="phishguard-go-back">← Go Back to Inbox</button>
        </div>
        <div style="margin-top: 12px;">
          <button class="phishguard-block-btn phishguard-block-btn-secondary" style="border:none; opacity:0.6"
                  id="phishguard-dismiss">I understand the risk — show email anyway</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    // Close the entire tab
    document.getElementById("phishguard-close-tab").addEventListener("click", () => {
      closeCurrentTab();
    });

    // Go back to inbox
    document.getElementById("phishguard-go-back").addEventListener("click", () => {
      overlay.remove();
      // Navigate back to inbox
      window.location.hash = "#inbox";
    });

    // Dismiss overlay (user accepts risk)
    document.getElementById("phishguard-dismiss").addEventListener("click", () => {
      overlay.remove();
    });
  }

  // ── MutationObserver — Re-scan when Gmail SPA navigates ─────

  function startObserver() {
    // MutationObserver started silently

    const observer = new MutationObserver((mutations) => {
      // Debounce: only scan if there are meaningful changes
      let shouldScan = false;
      for (const mutation of mutations) {
        if (mutation.addedNodes.length > 0) {
          for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              // Check if the added node contains email rows or is part of the inbox
              if (
                node.matches?.(SELECTORS.EMAIL_ROW) ||
                node.querySelector?.(SELECTORS.EMAIL_ROW) ||
                node.matches?.(SELECTORS.EMAIL_BODY_VIEW) ||
                node.querySelector?.(SELECTORS.EMAIL_BODY_VIEW)
              ) {
                shouldScan = true;
                break;
              }
            }
          }
        }
        if (shouldScan) break;
      }

      if (shouldScan) {
        // Use requestIdleCallback to avoid blocking Gmail's UI
        if (window.requestIdleCallback) {
          requestIdleCallback(() => {
            scanInbox();
            scanOpenEmail();
          });
        } else {
          setTimeout(() => {
            scanInbox();
            scanOpenEmail();
          }, 300);
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  // ── Initialization ───────────────────────────────────────────

  function init() {
    // PhishGuard Gmail scanner initialized silently

    // Initial scan after Gmail loads
    // Gmail loads content dynamically, so we wait a bit
    const tryInitialScan = (attempt = 0) => {
      const rows = document.querySelectorAll(SELECTORS.EMAIL_ROW);
      if (rows.length > 0) {
        // Gmail inbox detected — starting scan
        scanInbox();
        scanOpenEmail();
        startObserver();
      } else if (attempt < 20) {
        // Retry for up to ~10 seconds
        setTimeout(() => tryInitialScan(attempt + 1), 500);
      } else {
        // No inbox rows found — observer started for future navigation
        startObserver();
      }
    };

    if (document.readyState === "complete" || document.readyState === "interactive") {
      tryInitialScan();
    } else {
      window.addEventListener("DOMContentLoaded", () => tryInitialScan());
    }
  }

  init();
})();
