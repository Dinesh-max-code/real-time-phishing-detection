document.addEventListener("DOMContentLoaded", loadResult);

function loadResult() {
  chrome.storage.local.get(
    ["lastResult", "trust_expiry_warning"],
    ({ lastResult, trust_expiry_warning }) => {
      if (!lastResult) return;
      render(lastResult, trust_expiry_warning);
    }
  );
}

function render(data, trustWarning) {
  const banner = document.getElementById("status-banner");
  const severity = document.getElementById("severity-badge");
  const actionSection = document.querySelector(".action-section");
  const actionBtns = document.getElementById("action-buttons");
  const continueBtn = document.getElementById("continue-btn");
  const leaveBtn = document.getElementById("leave-btn");
  const rememberBox = document.getElementById("remember-choice");
  const feedbackSection = document.getElementById("feedback-section");

  document.getElementById("url").innerText = data.checked_url;
  document.getElementById("score").innerText = data.final_risk_score ?? 0;

  document.getElementById("reasons").innerHTML =
    (data.reasons || []).map(r => `<li>${r}</li>`).join("");

    /* ===============================
   OFFICIAL WEBSITE SECTION
   =============================== */

const officialSection = document.getElementById("official-site-section");
const officialContent = document.getElementById("official-site-content");

// Only show for suspicious / phishing
if (data.status !== "safe" && data.impersonation) {
  officialSection.style.display = "block";

  if (data.impersonation.exists && data.impersonation.official_site) {
    officialContent.innerHTML = `
      ⚠ This site may be impersonating a legitimate service.<br><br>
      🔗 <a href="${data.impersonation.official_site}"
           target="_blank"
           rel="noopener noreferrer">
        ${data.impersonation.official_site}
      </a>
      <div style="margin-top:6px;font-size:12px;opacity:0.8;">
        Confidence: ${data.impersonation.confidence}
      </div>
    `;
  } else {
    officialContent.innerHTML = `
      ℹ We could not determine an official website for this URL.
    `;
  }
} else {
  officialSection.style.display = "none";
}


  /* 🔥 Trust expiry warning */
  if (trustWarning && trustWarning.remainingMs > 0) {
    const minutes = Math.ceil(trustWarning.remainingMs / 60000);
    document.getElementById("status-text").innerText =
      `⏳ This site’s trust expires in ${minutes} minutes`;
    chrome.storage.local.remove("trust_expiry_warning");
  }

  /* 🔐 SILENT SAFE FEEDBACK (keep) */
  if (data.status === "safe") {
    saveFeedback(data, true, "", true);
  }

  /* RESET UI */
  actionSection.style.display = "block";
  feedbackSection.style.display = "none";
  actionBtns.style.display = "none";
  continueBtn.style.display = "inline-block";
  rememberBox.parentElement.style.display = "none";

  /* ================= SAFE ================= */
  if (data.status === "safe") {
    banner.className = "banner safe";
    severity.className = "severity low";
    severity.innerText = "✅ Low Risk";
    actionSection.style.display = "none";

    showFeedbackUI("safe", data);
  }

  /* ================= SUSPICIOUS ================= */
  if (data.status === "suspicious") {
    banner.className = "banner suspicious";
    severity.className = "severity medium";
    severity.innerText = "⚠️ Medium Risk";
    actionBtns.style.display = "flex";
    rememberBox.parentElement.style.display = "block";
    startCountdown(continueBtn);
  }

  /* ================= PHISHING ================= */
  if (data.status === "phishing") {
    banner.className = "banner phishing";
    severity.className = "severity high";
    severity.innerText = "🚨 High Risk";
    actionBtns.style.display = "flex";
    continueBtn.style.display = "none";
    rememberBox.parentElement.style.display = "none";

    const trustSelect = document.getElementById("trust-duration");
    if (trustSelect) trustSelect.style.display = "none";

    showFeedbackUI("phishing", data);
  }

  leaveBtn.onclick = leaveSite;

  /* PROCEED (SUSPICIOUS ONLY) */
  continueBtn.onclick = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (!tabs[0]) return;

      const tabId = tabs[0].id;
      const domain = new URL(data.checked_url).hostname;

      chrome.storage.session.set({ [`allow_${tabId}`]: domain });

      if (rememberBox.checked) {
        const hours =
          parseInt(document.getElementById("trust-duration").value, 10) || 24;

        chrome.storage.local.get("trusted_sites", res => {
          chrome.storage.local.set({
            trusted_sites: {
              ...(res.trusted_sites || {}),
              [domain]: {
                risk: data.status,
                addedAt: Date.now(),
                expiresAt: Date.now() + hours * 60 * 60 * 1000,
                durationHours: hours
              }
            }
          });
        });
      }

      actionSection.style.display = "none";
      showFeedbackUI("suspicious", data);

      chrome.tabs.sendMessage(tabId, { type: "USER_PROCEEDED" });
    });
  };

  document.getElementById("manage-sites").onclick = e => {
    e.preventDefault();
    chrome.tabs.create({ url: chrome.runtime.getURL("trusted.html") });
  };
}

/* ================= FEEDBACK UI ================= */

function showFeedbackUI(status, data) {
  const feedbackSection = document.getElementById("feedback-section");
  const question = document.getElementById("feedback-question");
  const yesBtn = document.getElementById("feedback-yes");
  const noBtn = document.getElementById("feedback-no");
  const textBox = document.getElementById("feedback-text");
  const submitBtn = document.getElementById("feedback-submit");

  feedbackSection.style.display = "block";
  textBox.style.display = "none";
  submitBtn.style.display = "none";

  yesBtn.style.display = "inline-block";
  noBtn.style.display = "inline-block";

  if (status === "safe") {
    question.innerText = "Was this SAFE classification correct?";
  } else if (status === "phishing") {
    question.innerText = "Was this phishing warning correct?";
  } else {
    question.innerText = "Was this warning helpful?";
  }

  yesBtn.onclick = () => {
    saveFeedback(data, true, "", false);
    window.close();
  };

  noBtn.onclick = () => {
    textBox.style.display = "block";
    submitBtn.style.display = "block";
    textBox.focus();
  };

  submitBtn.onclick = () => {
    saveFeedback(data, false, textBox.value.trim(), false);
    window.close();
  };
}

/* ================= STORAGE ================= */

function saveFeedback(data, helpful, comment, silent = false) {
  chrome.storage.local.get("feedback_logs", res => {
    const logs = res.feedback_logs || [];
    logs.push({
      url: data.checked_url,
      status: data.status,
      helpful,
      comment,
      silent,
      timestamp: Date.now()
    });
    chrome.storage.local.set({ feedback_logs: logs });
  });
}

/* ================= UTILS ================= */

function startCountdown(btn) {
  let sec = 5;
  btn.disabled = true;
  const timer = setInterval(() => {
    btn.innerText = `Proceed at Your Own Risk (${sec})`;
    sec--;
    if (sec < 0) {
      clearInterval(timer);
      btn.disabled = false;
      btn.innerText = "Proceed at Your Own Risk";
    }
  }, 1000);
}

function leaveSite() {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    if (tabs[0]) chrome.tabs.update(tabs[0].id, { url: "about:blank" });
  });
  window.close();
}
/* ===============================
   OPEN PROJECT WEBSITE
================================ */

document.addEventListener("DOMContentLoaded", () => {
  const projectBtn = document.getElementById("open-project-website");

  if (projectBtn) {
    projectBtn.addEventListener("click", () => {
      chrome.tabs.create({
        url: "http://localhost:5000"   // <-- change if different port
      });
    });
  }
});

