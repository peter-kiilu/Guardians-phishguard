# Frontend Dashboard

While the Chrome extension runs silently in the background, PhishGuard also provides a terminal-themed graphical user interface (`frontend/`).

This dashboard offers a direct manual interface for the FastAPI backend, allowing users to verify URLs independently of the browser extension.

## Overview

- **`index.html`**: A minimalistic interface featuring manual input forms for generic URLs.
- **`js/app.js`**: Connects via JavaScript `fetch()` calls to `http://localhost:8000/predict`, retrieves the prediction schema, and displays the risk score breakdown.
- **`css/styles.css`**: Built entirely with a cyberpunk, hacker-style aesthetic using bespoke CSS elements. It implements "Matrix rain" backgrounds using dynamic HTML canvas elements natively in `app.js` and pure CSS styling arrays for visually distinct terminal windows.

## Usage

Simply boot up a local HTML server within the `frontend` directory:

```bash
python -m http.server 5500
```

Navigate to `http://localhost:5500` to manually evaluate arbitrary URLs securely.
