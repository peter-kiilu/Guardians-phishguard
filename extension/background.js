const API_URL = "http://localhost:8000/predict";

// Analyze URL as soon as navigation starts (not after page loads)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Trigger when URL changes (navigation starts), not when page finishes loading
  if (changeInfo.url && changeInfo.url.startsWith('http')) {
    const url = changeInfo.url;

    // Don't analyze our own warning page
    if (url.startsWith(chrome.runtime.getURL(''))) return;

    // Check if user chose to bypass this URL
    chrome.storage.local.get('bypass_' + url, (result) => {
      if (result['bypass_' + url]) {
        // Clear the bypass flag and let them through
        chrome.storage.local.remove('bypass_' + url);
        return;
      }
      console.log(`Analyzing URL: ${url}`);
      analyzeUrl(tabId, url);
    });
  }
});

async function analyzeUrl(tabId, url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);

    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    console.log("Prediction Result:", data);

    if (data.prediction === "phishing") {
      // Redirect to warning page with details
      const warningUrl = chrome.runtime.getURL('warning.html') +
        `?url=${encodeURIComponent(url)}` +
        `&confidence=${data.confidence}` +
        `&ml_prob=${data.ml_probability}` +
        `&h_score=${data.heuristic_score}`;

      chrome.tabs.update(tabId, { url: warningUrl });
    }
  } catch (error) {
    console.error("PhishGuard Background Error:", error);
  }
}
