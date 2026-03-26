const BACKEND_URL = "http://localhost:8000/";

document.addEventListener('DOMContentLoaded', async () => {
  const backendStatusEl = document.getElementById('backend-status');
  
  try {
    const response = await fetch(BACKEND_URL, {
      method: 'GET',
      mode: 'cors'
    });
    
    if (response.ok) {
      backendStatusEl.textContent = "Connected";
      backendStatusEl.style.color = "#28a745";
    } else {
      backendStatusEl.textContent = "Error";
      backendStatusEl.style.color = "#dc3545";
    }
  } catch (error) {
    backendStatusEl.textContent = "Offline";
    backendStatusEl.style.color = "#dc3545";
  }
});
