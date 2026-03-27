chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "showWarning") {
    injectWarningBanner(request.data);
  }
});

function injectWarningBanner(data) {
  // Prevent duplicate banners
  if (document.getElementById("phishguard-banner")) return;

  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  
  banner.innerHTML = `
    <div class="phishguard-content">
      <div class="phishguard-icon">⚠️</div>
      <div class="phishguard-text">
        <strong>Potential Phishing Site Detected</strong><br/>
        Risk Score: ${data.confidence}% | ML Confidence: ${(data.ml_probability * 100).toFixed(1)}%
      </div>
      <div class="phishguard-actions">
        <button id="phishguard-close-tab" class="phishguard-btn" style="background:#ff2244;color:#fff;">Close Tab</button>
        <button id="phishguard-close" class="phishguard-btn phishguard-btn-secondary">Dismiss</button>
      </div>
    </div>
  `;

  document.body.prepend(banner);

  document.getElementById("phishguard-close-tab").addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "closeTab" });
  });

  document.getElementById("phishguard-close").addEventListener("click", () => {
    banner.remove();
  });
}
