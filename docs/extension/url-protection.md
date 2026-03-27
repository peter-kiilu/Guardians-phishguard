# URL Protection

The URL Protection module operates at the core of the browser, ensuring continuous real-time safety.

## Background Interception

PhishGuard utilizes `chrome.tabs.onUpdated` and `chrome.webNavigation` from the `background.js` Service Worker to listen for incoming network requests and top-level URL navigations.

1. Once intercepted, the destination URL is transmitted to the FastAPI Backend via the `/predict` endpoint.
2. If the backend is unreachable (e.g., `localhost:8000` is offline), the extension executes a local, lightweight heuristic check as an immediate fallback.

## Local Heuristic Engine

Before falling back entirely, or in conjunction with the ML prediction, PhishGuard checks local lists:

- Compares the URL against an internal array of **20+ generic URL shortener services** (e.g., `bitly.com`, `tinyurl.com`).
- Consults the `KNOWN_PHISHING_DOMAINS` variable housed in `phishing_domains.js`.

## Warning Interface

When the total calculated risk score breaks the 60% threshold, `content.js` forcefully redirects the current tab's DOM to display `warning.html`.

Users are presented with:
- The ML probability score
- The exact localized heuristics that triggered the alarm
- Two distinct options: **"Go back to safety"** (recommended) or **"Proceed anyway"** (bypass).
