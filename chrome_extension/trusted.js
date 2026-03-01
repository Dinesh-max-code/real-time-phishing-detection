document.addEventListener("DOMContentLoaded", () => {
  loadSites();
  startLiveCountdown(); // 🔥 NEW: live countdown updater
});

/* ===============================
   LOAD & RENDER TRUSTED SITES
================================ */
function loadSites() {
  chrome.storage.local.get("trusted_sites", ({ trusted_sites = {} }) => {
    const list = document.getElementById("site-list");
    const empty = document.getElementById("empty");

    list.innerHTML = "";

    const now = Date.now();
    let changed = false;

    /* ===============================
       AUTO-CLEAN EXPIRED ENTRIES
    ================================ */
    Object.keys(trusted_sites).forEach(domain => {
      const entry = trusted_sites[domain];
      if (entry.expiresAt && entry.expiresAt <= now) {
        delete trusted_sites[domain];
        changed = true;
      }
    });

    if (changed) {
      chrome.storage.local.set({ trusted_sites });
    }

    const domains = Object.keys(trusted_sites);

    if (domains.length === 0) {
      empty.style.display = "block";
      return;
    }

    empty.style.display = "none";

    /* ===============================
       RENDER TRUSTED SITES
    ================================ */
    domains.forEach(domain => {
      const info = trusted_sites[domain];

      const li = document.createElement("li");
      li.dataset.domain = domain;
      li.dataset.expiresAt = info.expiresAt;

      const siteInfo = document.createElement("div");
      siteInfo.className = "site-info";

      const name = document.createElement("div");
      name.className = "domain";
      name.textContent = domain;

      const meta = document.createElement("div");
      meta.className = "meta";
      meta.textContent = formatRemainingTime(info.expiresAt);

      siteInfo.appendChild(name);
      siteInfo.appendChild(meta);

      const btn = document.createElement("button");
      btn.className = "remove-btn";
      btn.textContent = "Remove";
      btn.addEventListener("click", () => removeDomain(domain));

      li.appendChild(siteInfo);
      li.appendChild(btn);
      list.appendChild(li);
    });
  });
}

/* ===============================
   LIVE COUNTDOWN (SECONDS)
================================ */
function startLiveCountdown() {
  setInterval(() => {
    const items = document.querySelectorAll("#site-list li");
    const now = Date.now();

    items.forEach(li => {
      const expiresAt = parseInt(li.dataset.expiresAt, 10);
      const meta = li.querySelector(".meta");

      if (!expiresAt || !meta) return;

      if (expiresAt <= now) {
        meta.textContent = "Expired";
        li.style.opacity = "0.6";
        return;
      }

      meta.textContent = formatRemainingTime(expiresAt);
    });
  }, 1000);
}

/* ===============================
   FORMAT TIME (D:H:M:S)
================================ */
function formatRemainingTime(expiresAt) {
  let diff = Math.max(0, expiresAt - Date.now());

  const seconds = Math.floor(diff / 1000) % 60;
  const minutes = Math.floor(diff / (1000 * 60)) % 60;
  const hours = Math.floor(diff / (1000 * 60 * 60)) % 24;
  const days = Math.floor(diff / (1000 * 60 * 60 * 24));

  if (days > 0) {
    return `Expires in ${days}d ${hours}h ${minutes}m ${seconds}s`;
  }

  if (hours > 0) {
    return `Expires in ${hours}h ${minutes}m ${seconds}s`;
  }

  if (minutes > 0) {
    return `Expires in ${minutes}m ${seconds}s`;
  }

  return `Expires in ${seconds}s`;
}

/* ===============================
   REMOVE TRUSTED DOMAIN
================================ */
function removeDomain(domain) {
  chrome.storage.local.get("trusted_sites", ({ trusted_sites = {} }) => {
    if (!trusted_sites[domain]) return;

    delete trusted_sites[domain];

    chrome.storage.local.set({ trusted_sites }, () => {
      /* ===============================
         CLEAR TEMP SESSION ALLOWS
      ================================ */
      chrome.storage.session.clear(() => {
        /* ===============================
           NOTIFY BACKGROUND
        ================================ */
        chrome.runtime.sendMessage({
          type: "TRUST_REMOVED",
          domain
        });

        /* ===============================
           FORCE TAB RECHECK
        ================================ */
        chrome.tabs.query({}, tabs => {
          tabs.forEach(tab => {
            try {
              if (tab.url && new URL(tab.url).hostname === domain) {
                chrome.tabs.reload(tab.id);
              }
            } catch {}
          });
        });

        loadSites(); // refresh UI
      });
    });
  });
}
