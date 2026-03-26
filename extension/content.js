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
        <button id="phishguard-ignore" class="phishguard-btn">Ignore Warning</button>
        <button id="phishguard-close" class="phishguard-btn phishguard-btn-secondary">Dismiss</button>
      </div>
    </div>
  `;

  document.body.prepend(banner);

  document.getElementById("phishguard-ignore").addEventListener("click", () => {
    // Optionally log user's choice or just hide
    banner.style.display = "none";
  });

  document.getElementById("phishguard-close").addEventListener("click", () => {
    banner.remove();
  });
}
