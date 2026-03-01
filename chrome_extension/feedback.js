const DEFAULT_ADMIN_PASSWORD = "admin@phishguard";
const SESSION_KEY = "admin_session_active";

let allFeedback = [];

window.addEventListener("beforeunload", () => {
  chrome.storage.session.remove(SESSION_KEY);
});


document.addEventListener("DOMContentLoaded", () => {
  const loginBox = document.getElementById("loginContainer");
  const dashboard = document.getElementById("dashboardContainer");

  chrome.storage.session.get([SESSION_KEY], res => {
    if (res[SESSION_KEY]) unlockDashboard();
  });

  loginBtn.onclick = attemptLogin;
  adminPassword.addEventListener("keydown", e => {
  if (e.key === "Enter") {
    attemptLogin();
  }
});


  urlFilter.oninput = applyFilters;
  statusFilter.onchange = applyFilters;
  includeSilent.onchange = applyFilters;
  clearFilters.onclick = clearFiltersFn;

  exportCSV.onclick = () => exportData("csv");
  exportJSON.onclick = () => exportData("json");
  clearAll.onclick = clearAllFeedback;

function attemptLogin() {
  const entered = adminPassword.value.trim();
  if (!entered) return;

  chrome.storage.session.get(["admin_password"], res => {
    if ((res.admin_password || DEFAULT_ADMIN_PASSWORD) === entered) {
      chrome.storage.local.set({ [SESSION_KEY]: true });
      unlockDashboard();
    } else {
      loginError.classList.remove("hidden");
    }
  });
}


  function unlockDashboard() {
    loginBox.classList.add("hidden");
    dashboard.classList.remove("hidden");
    loadFeedback();
  }
});

/* ================= LOAD ================= */

function loadFeedback() {
  chrome.storage.local.get(null, data => {
    allFeedback = Object.values(data)
      .flat()
      .filter(f => f && f.url && f.timestamp)
      .sort((a, b) => b.timestamp - a.timestamp);

    applyFilters();
  });
}

/* ================= STATS ================= */

function updateStats(list) {
  const explicit = list.filter(f => !f.silent);
  const helpful = explicit.filter(f => f.helpful).length;
  const notHelpful = explicit.filter(f => f.helpful === false).length;

  totalCount.textContent = list.length;
  helpfulCount.textContent = helpful;
  notHelpfulCount.textContent = notHelpful;

  helpfulPercent.textContent = explicit.length
    ? Math.round((helpful / explicit.length) * 100) + "%"
    : "0%";
}

/* ================= RENDER ================= */

function formatDate(ts) {
  return ts ? new Date(ts).toLocaleString() : "—";
}

function renderList(list) {
  feedbackList.innerHTML = "";

  if (!list.length) {
    feedbackList.innerHTML = `<p class="muted">No feedback found.</p>`;
    return;
  }

  list.forEach(item => {
    const source = item.silent
      ? `<span class="source silent">Silent</span>`
      : `<span class="source explicit">User</span>`;

    feedbackList.innerHTML += `
      <div class="item">
        <div class="top">
          <span class="url">${item.url}</span>
          <span class="badge ${item.status}">${item.status}</span>
        </div>
        <div class="meta">
          <span class="${item.helpful ? "good" : "bad"}">
            ${item.helpful ? "Helpful" : "Not Helpful"}
          </span>
          ${source}
          <span class="date">${formatDate(item.timestamp)}</span>
        </div>
        ${item.comment ? `<div class="comment">💬 ${item.comment}</div>` : ""}
      </div>
    `;
  });
}

/* ================= FILTER ================= */

function applyFilters() {
  const urlText = urlFilter.value.toLowerCase();
  const status = statusFilter.value;
  const showSilent = includeSilent.checked;

  const filtered = allFeedback.filter(f => {
    if (!showSilent && f.silent) return false;
    if (status && f.status !== status) return false;
    if (urlText && !f.url.toLowerCase().includes(urlText)) return false;
    return true;
  });

  updateStats(filtered);
  renderList(filtered);
  renderAnalytics(filtered);
}

function clearFiltersFn() {
  urlFilter.value = "";
  statusFilter.value = "";
  includeSilent.checked = true;
  applyFilters();
}

/* ================= ANALYTICS ================= */

function renderAnalytics(list) {
  renderAccuracy(list);
  renderDomains(list);
}

function renderAccuracy(list) {
  accuracyStats.innerHTML = "";

  ["safe", "suspicious", "phishing"].forEach(status => {
    const items = list.filter(f => f.status === status && !f.silent);
    if (!items.length) return;

    const helpful = items.filter(f => f.helpful).length;
    const percent = Math.round((helpful / items.length) * 100);

    accuracyStats.innerHTML += `
      <div class="card">
        ${status}<br><span>${percent}%</span>
      </div>
    `;
  });
}

function renderDomains(list) {
  const map = {};

  list.forEach(f => {
    try {
      const d = new URL(f.url).hostname;
      map[d] = map[d] || { total: 0, bad: 0 };
      map[d].total++;
      if (!f.helpful && !f.silent) map[d].bad++;
    } catch {}
  });

  domainStats.innerHTML = "";

  Object.entries(map)
    .filter(([_, v]) => v.bad >= 2)
    .sort((a, b) => b[1].bad - a[1].bad)
    .forEach(([domain, v]) => {
      domainStats.innerHTML += `
        <div class="item">
          <strong>${domain}</strong>
          <span>⚠ ${v.bad} false positives</span>
        </div>
      `;
    });
}

/* ================= EXPORT ================= */

function exportData(type) {
  const explicit = allFeedback.filter(f => !f.silent);

  if (type === "json") {
    download(
      JSON.stringify(explicit, null, 2),
      "feedback_ml.json",
      "application/json"
    );
  } else {
    const csv = [
      "url,status,helpful,comment,timestamp",
      ...explicit.map(f =>
        `"${f.url}","${f.status}",${f.helpful},"${(f.comment || "").replace(/"/g, '""')}",${f.timestamp}`
      )
    ].join("\n");

    download(csv, "feedback.csv", "text/csv");
  }
}

function download(content, filename, type) {
  const blob = new Blob([content], { type });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
}

/* ================= CLEAR ================= */

function clearAllFeedback() {
  if (!confirm("Delete ALL feedback permanently?")) return;
  chrome.storage.local.clear(() => {
    allFeedback = [];
    applyFilters();
    alert("All feedback cleared.");
  });
}
