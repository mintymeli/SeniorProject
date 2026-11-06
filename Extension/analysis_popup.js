
const closeButton = document.getElementById("close-panel");
const tabs = document.querySelectorAll(".tab");
const panels = document.querySelectorAll(".tab-panel");

// Switch between Findings, Headers, and What to do
tabs.forEach((tab) => {
  tab.addEventListener("click", () => {
    const targetId = tab.dataset.tab;

    // Update the selected tab
    tabs.forEach((item) => {
      item.classList.toggle("active", item === tab);
    });

    // Show the matching panel
    panels.forEach((panel) => {
      const isSelected = panel.id === targetId;

      panel.classList.toggle("active", isSelected);
      panel.hidden = !isSelected;
    });
  });
});

// Hide the panel without deleting its contents
// Tell Gmail to close the panel
closeButton.addEventListener("click", () => {
  window.parent.postMessage(
    { type: "PHISHCATCHER_CLOSE" },
    "*"
  );
});


/* Receive email headers from content.js */
window.addEventListener("message", (event) => {
  if (event.data?.type !== "PHISHCATCHER_ANALYSIS_RESULT") {
    return;
  }

  const headers = event.data.headers;

  if (!headers) {
    return;
  }

  // Email Information
  document.getElementById("display-from").textContent =
    headers.from || "Not provided";

  document.getElementById("display-subject").textContent =
    headers.subject || "Not provided";

  document.getElementById("display-date").textContent =
    headers.date
      ? new Date(headers.date).toLocaleString()
      : "Not provided";

  document.getElementById("display-reply-to").textContent =
    headers.reply_to?.split("@")[1] || "Not provided";


  // Authentication
  /**
  const authResults =
    headers.authentication_results?.join("\n\n") || "Not provided";

  document.getElementById("auth-spf").textContent = authResults;
  document.getElementById("auth-dkim").textContent = authResults;
  document.getElementById("auth-dmarc").textContent = authResults;
  */

  // Authentication
  const authResults =
    headers.authentication_results?.join("\n\n") || "";

  function getAuthStatus(type) {
    const matches = [
      ...authResults.matchAll(
        new RegExp(
          `\\b${type}=(pass|fail|softfail|neutral|none|temperror|permerror)\\b`,
          "gi"
        )
      )
    ].map(match => match[1].toLowerCase());

    if (matches.length === 0) {
      return "NOT AVAILABLE";
    }

    const hasPass = matches.includes("pass");
    const hasFail = matches.some(status =>
      ["fail", "softfail", "permerror"].includes(status)
    );

    // Handle multiple DKIM signatures
    if (type === "dkim" && matches.length > 1) {
      if (hasPass && hasFail) return "MIXED";
      if (hasFail) return "FAIL";
      if (hasPass) return "PASS";
    }

    const status = matches[0];

    if (status === "pass") return "PASS";

    if (["fail", "softfail", "permerror"].includes(status)) {
      return "FAIL";
    }

    return "NEEDS REVIEW";
  }

  /** UPDATE
  document.getElementById("auth-spf").textContent =
    getAuthStatus("spf");

  document.getElementById("auth-dkim").textContent =
    getAuthStatus("dkim");

  document.getElementById("auth-dmarc").textContent =
    getAuthStatus("dmarc");
  */
 
  // Assign to green, yellow, red
  function displayAuthStatus(elementId, type) {
    const element = document.getElementById(elementId);
    const status = getAuthStatus(type);

    element.textContent = status;

    element.classList.remove(
      "auth-pass",
      "auth-fail",
      "auth-review"
    );

    if (status === "PASS") {
      element.classList.add("auth-pass");
    } else if (status === "FAIL") {
      element.classList.add("auth-fail");
    } else {
      element.classList.add("auth-review");
    }
  }

  displayAuthStatus("auth-spf", "spf");
  displayAuthStatus("auth-dkim", "dkim");
  displayAuthStatus("auth-dmarc", "dmarc");

  // Technical Details
  document.getElementById("display-return-path").textContent =
    headers.return_path?.split("@")[1]?.replace(/[<>]/g, "") || "Not provided";

  document.getElementById("display-received").textContent =
    headers.received?.join("\n\n") || "Not provided";


  // Original Header Values
  document.getElementById("header-from").textContent =
    headers.from || "Not provided";

  document.getElementById("header-subject").textContent =
    headers.subject || "Not provided";

  document.getElementById("header-date").textContent =
    headers.date || "Not provided";

  document.getElementById("header-reply-to").textContent =
    headers.reply_to || "Not provided";

  document.getElementById("header-return-path").textContent =
    headers.return_path || "Not provided";

  document.getElementById("header-auth-results").textContent =
    authResults;

  document.getElementById("header-received").textContent =
    headers.received?.join("\n\n") || "Not provided";

  document.getElementById("header-message-id").textContent =
    headers.message_id || "Not provided";
});
