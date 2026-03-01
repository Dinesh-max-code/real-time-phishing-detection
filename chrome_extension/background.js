let lastResult = null;

/* ===============================
   TAB MONITORING
================================ */
chrome.tabs.onActivated.addListener(({ tabId }) => {
  analyzeTab(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab.url?.startsWith("http")) {
    analyzeTab(tabId);
  }
});

/* ===============================
   MESSAGE HANDLING
================================ */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.type === "GET_RESULT") {
    sendResponse(lastResult);
    return true;
  }

  // ✅ TEMP SESSION ALLOW
  if (msg.type === "USER_PROCEEDED" && sender.tab) {
    chrome.storage.session.set({
      [`allow_${sender.tab.id}`]: sender.tab.url
    });
  }

  // ✅ TRUST REMOVED → FORCE RECHECK
  if (msg.type === "TRUST_REMOVED" && sender.tab) {
    chrome.storage.session.clear(() => {
      analyzeTab(sender.tab.id);
    });
  }
});

/* ===============================
   ANALYZE TAB
================================ */
async function analyzeTab(tabId) {
  try {
    const tab = await chrome.tabs.get(tabId);
    const url = tab.url;
    if (!url || !url.startsWith("http")) return;

    const domain = new URL(url).hostname;

    const { trusted_sites = {} } =
      await chrome.storage.local.get("trusted_sites");

    const trust = trusted_sites[domain];

    /* ===============================
       🔥 TRUST EXPIRY WARNING (FEATURE 1)
    ================================ */
    if (trust && trust.expiresAt) {
      const remainingMs = trust.expiresAt - Date.now();
      const WARNING_THRESHOLD = 60 * 60 * 1000; // 1 hour

      if (remainingMs > 0 && remainingMs <= WARNING_THRESHOLD) {
        chrome.storage.local.set({
          trust_expiry_warning: {
            domain,
            remainingMs
          }
        });

        chrome.action.openPopup().catch(() => {});
      }

      // Still trusted → skip backend
      if (remainingMs > 0) return;

      // Expired → auto remove
      delete trusted_sites[domain];
      chrome.storage.local.set({ trusted_sites });
    }

    await analyzeUrl(url, tabId);

  } catch {
    // tab closed
  }
}

/* ===============================
   BACKEND CALL
================================ */
async function analyzeUrl(url, tabId) {
  try {
    const res = await fetch("http://127.0.0.1:8000/check-url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!res.ok) throw new Error();

    lastResult = await res.json();
    lastResult.checked_url = url;

    chrome.storage.local.set({ lastResult });

    if (lastResult.status === "safe") {
      setIcon("green", "Site is safe");
      return;
    }

    if (lastResult.status === "suspicious") {
      setIcon("yellow", "Suspicious website detected");
    }

    if (lastResult.status === "phishing") {
      setIcon("red", "Phishing website blocked");
    }

    chrome.action.openPopup().catch(() => {});

    chrome.tabs.sendMessage(tabId, {
      type: "SECURITY_DECISION",
      data: lastResult
    });

    chrome.runtime.sendMessage({ type: "RESULT_READY" });

  } catch {
    lastResult = {
      status: "error",
      checked_url: url,
      reasons: ["Backend unreachable"]
    };
  }
}

/* ===============================
   ICON HANDLER
================================ */
function setIcon(color, title) {
  chrome.action.setIcon({
    path: {
      "16": `icons/${color}.png`,
      "48": `icons/${color}.png`,
      "128": `icons/${color}.png`
    }
  });
  chrome.action.setTitle({ title });
}
