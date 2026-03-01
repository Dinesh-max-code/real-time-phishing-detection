if (!window.__PHISHING_EXT_LOADED__) {
  window.__PHISHING_EXT_LOADED__ = true;

  let hardBlocked = false;

  chrome.runtime.onMessage.addListener((msg) => {

    /* ===============================
       USER EXPLICITLY PROCEEDED
       (ONLY FOR SUSPICIOUS)
    ================================ */
    if (msg.type === "USER_PROCEEDED" && !hardBlocked) {
      enablePage();
      document.getElementById("phish-warning")?.remove();
      return;
    }

    if (msg.type !== "SECURITY_DECISION") return;

    const data = msg.data;

    if (data.status === "safe") cleanup();

    if (data.status === "suspicious") {
      hardBlocked = false;
      showSuspiciousPopup(data);
    }

    if (data.status === "phishing") {
      hardBlocked = true;
      blockPhishingPage(data);
    }
  });

  /* ===============================
     SUSPICIOUS (SOFT BLOCK)
  ================================ */
  function showSuspiciousPopup(data) {
    if (document.getElementById("phish-warning")) return;

    disablePage();

    const box = document.createElement("div");
    box.id = "phish-warning";
    box.innerHTML = `
      <h3>⚠️ Suspicious Website Detected</h3>
      <p>This site may attempt to steal sensitive information.</p>
      <p><b>Current site:</b><br>${location.hostname}</p>
      <ul>${(data.reasons || []).map(r => `<li>${r}</li>`).join("")}</ul>
      <small>ℹ️ Access is blocked until you explicitly proceed.</small>
    `;

    safeInject(box);
    injectStyles();
  }

  /* ===============================
     PHISHING (HARD BLOCK)
  ================================ */
  function blockPhishingPage(data) {
    if (document.getElementById("phish-block")) return;

    disablePage();

    const overlay = document.createElement("div");
    overlay.id = "phish-block";
    overlay.innerHTML = `
      <h1>🚫 Phishing Website Blocked</h1>
      <p>${location.hostname}</p>
      <ul>${(data.reasons || []).map(r => `<li>${r}</li>`).join("")}</ul>
      <p>Access has been permanently blocked for your safety.</p>
    `;

    safeInject(overlay);
    injectStyles();
  }

  /* ===============================
     PAGE CONTROL
  ================================ */
  function disablePage() {
    document.documentElement.style.pointerEvents = "none";
    document
      .querySelectorAll("input,button,textarea,select,form")
      .forEach(el => el.disabled = true);
  }

  function enablePage() {
    document.documentElement.style.pointerEvents = "";
    document
      .querySelectorAll("input,button,textarea,select,form")
      .forEach(el => el.disabled = false);
  }

  function cleanup() {
    hardBlocked = false;
    enablePage();
    document.getElementById("phish-warning")?.remove();
    document.getElementById("phish-block")?.remove();
  }

  /* ===============================
     SAFE DOM INJECT
  ================================ */
  function safeInject(el) {
    if (document.body) document.body.appendChild(el);
    else window.addEventListener("DOMContentLoaded", () =>
      document.body.appendChild(el)
    );
  }

  /* ===============================
     STYLES (UNCHANGED)
  ================================ */
  function injectStyles() {
    if (document.getElementById("phish-style")) return;

    const style = document.createElement("style");
    style.id = "phish-style";
    style.textContent = `
      #phish-warning {
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 999999;
        background: white;
        padding: 16px;
        width: 340px;
        border-left: 6px solid orange;
        box-shadow: 0 10px 40px rgba(0,0,0,.3);
        font-family: Arial;
      }

      #phish-block {
        position: fixed;
        inset: 0;
        background: #111;
        color: white;
        z-index: 999999;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        text-align: center;
        font-family: Arial;
        padding: 20px;
      }
    `;
    document.head.appendChild(style);
  }
}
