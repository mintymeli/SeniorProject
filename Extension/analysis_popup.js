
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
 // Authentication UPDATED
  // Preserve all original authentication results
  const allAuthResults =
    headers.authentication_results?.join("\n\n") || "Not provided";

  // Select Google's results for status calculations
  const googleAuthResults = (headers.authentication_results || []).filter(
    result => /^\s*mx\.google\.com\s*;/i.test(result)
  );

  const authResults = googleAuthResults.join("\n\n");
  

  // Authentication
  /** CHECKING SPF  
  const authResults =
    headers.authentication_results?.join("\n\n") || "";
  */
  // const authResults = "spf=pass"; // test SPF pass
  //const authResults = "spf=fail"; // test SPF fail

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
    // if (type === "dkim" && matches.length > 1) {

    // Handles multiple SPF DKIM DMARC signatures
    if (matches.length > 1) {
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

  /**Updated INFO */
  function getAuthDescription(type, status) {
    const descriptions = {
      spf: {
        PASS: "The sending server passed the domain's SPF authentication check.",
        FAIL: "The sending server failed the domain's SPF authentication check.",
        MIXED: "Multiple SPF results were found and they differed.",
        "NEEDS REVIEW": "The SPF result could not be clearly determined."
      },
      dkim: {
        PASS: "At least one DKIM signature passed verification.",
        FAIL: "The DKIM signature or signatures failed verification.",
        MIXED: "Some DKIM signatures passed while others failed.",
        "NEEDS REVIEW": "The DKIM result could not be clearly determined."
      },
      dmarc: {
        PASS: "The email passed the domain's DMARC authentication and alignment requirements.",
        FAIL: "The email failed the domain's DMARC authentication requirements.",
        MIXED: "Multiple DMARC results were found and they differed.",
        "NEEDS REVIEW": "The DMARC result could not be clearly determined."
      }
    };

    return descriptions[type][status] || "Authentication information is unavailable.";
  }

  function displayAuthDescription(elementId, type) {
    const status = getAuthStatus(type);

    document.getElementById(elementId).textContent =
      getAuthDescription(type, status);
  }

  displayAuthDescription("auth-spf-description", "spf");
  displayAuthDescription("auth-dkim-description", "dkim");
  displayAuthDescription("auth-dmarc-description", "dmarc");

  // UPDATE: included authen findings
  // Generate authentication findings
  const findingsContainer = document.getElementById("findings-container");
  findingsContainer.innerHTML = "";

  let authFindingsCount = 0;

  ["spf", "dkim", "dmarc"].forEach(type => {
    const status = getAuthStatus(type);

    if (status === "FAIL" || status === "MIXED") {
      const title = `${type.toUpperCase()} authentication ${status.toLowerCase()}`;

      const explanation = getAuthDescription(type, status);

      const technicalDetails = authResults
        .split(";")
        .filter(part => new RegExp(`\\b${type}=`, "i").test(part))
        .join(";")
        .trim();

      addFinding(
        title,
        `Authentication · ${type.toUpperCase()}`,
        explanation,
        technicalDetails || "No matching technical details available."
      );

      authFindingsCount++;
    }
  });

  if (authFindingsCount === 0) {
    findingsContainer.textContent =
      "No noteworthy authentication findings detected.";
  }

  // Technical Details
  document.getElementById("display-return-path").textContent =
    headers.return_path?.split("@")[1]?.replace(/[<>]/g, "") || "Not provided";

  /** Parse displayed received */
  // Friendly Received display
  const receivedValue = headers.received?.join("\n\n") || "";

  const receivedServer =
    receivedValue.match(/from\s+([^\s(]+)/i)?.[1] || "Not available";

  const receivedIP =
    receivedValue.match(/\[([\d.]+)\]/)?.[1] || "Not available";

  const receivedDate =
    receivedValue.match(/;\s*([A-Za-z]{3},.+)$/m)?.[1] || "Not available";

  document.getElementById("display-received").innerHTML =
    receivedValue
      ? `<span class="received-label">SENDING SERVER:\n</span> ${receivedServer}
        <br><span class="received-label">SERVER IP:</span> <span class="info-icon" title="The IP address of the mail server that handled the email.">ⓘ\n</span> ${receivedIP}
        <br><span class="received-label">RECEIVED DATE:\n</span> ${receivedDate}`
      : "Not provided";


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

  /**document.getElementById("header-auth-results").textContent =
    authResults;
  */
 // UPDATED: includes all authentication results
  document.getElementById("header-auth-results").textContent =
  allAuthResults;

  document.getElementById("header-received").textContent =
    headers.received?.join("\n\n") || "Not provided";

  document.getElementById("header-message-id").textContent =
    headers.message_id || "Not provided";

  
  // UPDATE: Create an expandable security finding
  function addFinding(title, category, explanation, technicalDetails) {
    const container = document.getElementById("findings-container");

    // Finding card
    const card = document.createElement("div");
    card.classList.add("finding-card");

    // Clickable finding title
    const titleButton = document.createElement("button");
    titleButton.classList.add("finding-title");
    titleButton.textContent = title;
    titleButton.setAttribute("aria-expanded", "false");

    // Expandable content
    const content = document.createElement("div");
    content.classList.add("finding-content");
    content.hidden = true;

    const categoryLabel = document.createElement("p");
    categoryLabel.textContent = category;

    const explanationText = document.createElement("p");
    explanationText.textContent = explanation;

    // Technical details button
    const technicalButton = document.createElement("button");
    technicalButton.classList.add("finding-technical-button");
    technicalButton.textContent = "View technical details";

    // Technical details content
    const technicalContent = document.createElement("p");
    technicalContent.textContent = technicalDetails;
    technicalContent.hidden = true;

    // Expand and collapse the finding
    titleButton.addEventListener("click", () => {
      content.hidden = !content.hidden;
      titleButton.setAttribute("aria-expanded", String(!content.hidden));
    });

    // Show and hide technical details
    technicalButton.addEventListener("click", () => {
      technicalContent.hidden = !technicalContent.hidden;
      technicalButton.textContent = technicalContent.hidden
        ? "View technical details"
        : "Hide technical details";
    });

    // Assemble finding
    content.append(categoryLabel, explanationText, technicalButton, technicalContent);
    card.append(titleButton, content);
    container.appendChild(card);
  }
});


