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

// Risk summary and "What to do" tab (result comes from remediation.py)
const RISK_TEXT = {
  none: ["No warning signs found", "Our checks didn't find anything suspicious in this email.", "Low risk"],
  low: ["Looks mostly routine", "Only minor warning signs were found.", "Low risk"],
  medium: ["Be careful with this email", "Some warning signs were found. Check before you click or reply.", "Medium risk"],
  high: ["This email looks risky", "Several warning signs were found. Don't click links or open attachments.", "High risk"]
};

function showRemediation(remediation) {
  if (!remediation || !RISK_TEXT[remediation.risk_level]) {
    return;
  }

  const [title, description, status] = RISK_TEXT[remediation.risk_level];

  document.getElementById("risk-title").textContent = title;
  document.getElementById("risk-description").textContent = description;
  document.getElementById("risk-status-text").textContent = status;
  document.querySelector(".risk-status").dataset.level = remediation.risk_level;

  const actions = remediation.actions || [];
  const list = document.getElementById("action-list");
  list.textContent = "";

  actions.forEach((step) => {
    const item = document.createElement("li");
    item.textContent = step;
    list.appendChild(item);
  });

  document.getElementById("action-why").textContent =
    remediation.why || "";

  document.getElementById("action-note").textContent =
    remediation.source === "ai"
      ? "Steps were worded by AI using only a coded summary of the checks. The email text was not shared."
      : "";

  document.getElementById("action-refs").textContent =
    remediation.references?.length
      ? "Based on: " + remediation.references.join("; ")
      : "";

  document.getElementById("actions-placeholder").hidden = true;
  document.getElementById("actions-result").hidden = false;
}

/* Receive email headers from content.js */
window.addEventListener("message", (event) => {
  if (event.data?.type !== "PHISHCATCHER_ANALYSIS_RESULT") {
    return;
  }

  showRemediation(event.data.remediation);

  const headers = event.data.headers;
  // Include header analysis and threat intel results
  const headerAnalysis = event.data.header_analysis;
  const threatIntelResults = event.data.threat_intel_results;

  // URL threat intelligence results
  const urlVirusTotalResults = threatIntelResults?.url_results || [];
  const urlIPQSResults = threatIntelResults?.ipqs_results || [];
  const urlhausResults = threatIntelResults?.urlhaus_results || [];

  // TEMPORARY UI TEST DATA
  const useMockUrlResults = true;
  if (useMockUrlResults) {
    urlVirusTotalResults.push({
        url: "https://example.com/account/verify",
        status: "Report found",
        malicious: 2,
        suspicious: 1,
        harmless: 65,
        undetected: 24,
        total_vendors: 92
    });
    urlIPQSResults.push({
      url: "https://example.com/account/verify",
      status: "Report found",
      safe: true,
      suspicious: false,
      domain: "example.com",
      malware: false,
      phishing: false,
      risk_score: 12,
      domain_age: "18 years"
  });
  urlhausResults.push({
    url: "https://example.com/account/verify",
    url_status: "online",
    host: "example.com",
    date_added: "2026-11-15 10:30:00 UTC",
    threat: "malware_download",
    urlhaus_blocklist: "Blocked",
    spamhaus_dbl: "Not blocked",
    surbl: "Not blocked"
  });
}

  // Create one unique list of URLs across all three tools
  const allUrls = [
      ...new Set(
          [
              ...urlVirusTotalResults,
              ...urlIPQSResults,
              ...urlhausResults
          ]
              .map(result => result.url || result.indicator)
              .filter(Boolean)
      )
  ];

  // Find a tool's result for a specific URL
  function getUrlResult(results, url) {
      return results.find(
          result => (result.url || result.indicator) === url
      ) || null;
  }

  if (!headers) {
    return;
  }
  // UPDATE: test if header and intel show in console
  console.log("Header Analysis:", headerAnalysis);
  console.log("Header Threat Intel Results:", threatIntelResults);
  console.log("ALL THREAT INTEL RESULTS:", threatIntelResults);

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

      // const explanation = getAuthDescription(type, status);
      const explanationKey = `${type}_${status.toLowerCase()}`;

      const explanation = findingExplanations[explanationKey] || {
        meaning: getAuthDescription(type, status),
        whyItMatters: ""
      };

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

  // Header email addresses
  if (headerAnalysis?.emails?.length > 0) {
    const resultContent = document.createElement("div");
    resultContent.classList.add("finding-results");

    const resultHeading = document.createElement("p");
    resultHeading.classList.add("finding-results-heading");
    resultHeading.textContent =
      `${headerAnalysis.emails.length} email addresses found:`;

    const emailList = document.createElement("ul");
    emailList.classList.add("finding-results-list");

    headerAnalysis.emails.forEach(email => {
      const listItem = document.createElement("li");
      listItem.textContent = email;
      emailList.appendChild(listItem);
    });

    resultContent.append(resultHeading, emailList);

    addHeaderSection(
      "Extracted email addresses",
      "Header Analysis · Email Addresses",
      {
        meaning: "These are the email addresses found in the message headers, including sender, recipient, and reply-to information.",
        whyItMatters: "Reviewing these addresses can help you understand who is involved in the email and identify unexpected or unfamiliar addresses."
      },
      headerAnalysis.emails.join("\n"),
      resultContent
    );
  }

  // Header domain reputation
  const domainResults = threatIntelResults?.header_domain_results || [];

  let virusTotalDialog = null;
  let abuseIPDBDialog = null;

  if (domainResults.length > 0) {
    const resultContent = document.createElement("div");
    resultContent.classList.add("finding-results");

    // Expandable VirusTotal results section
    const domainGroup = document.createElement("div");
    domainGroup.classList.add("finding-result-group");

    const domainToggle = document.createElement("button");
    domainToggle.type = "button";
    domainToggle.classList.add("finding-result-toggle");
    domainToggle.setAttribute("aria-expanded", "false");

    const domainHeading = document.createElement("span");
    domainHeading.textContent = "VirusTotal Results";
    /*UPDATE: Learn more area*/
    const learnMore = document.createElement("span");
    learnMore.textContent = "ⓘ Learn more";
    learnMore.classList.add("finding-learn-more");
    learnMore.title = "Learn more about VirusTotal Results";
    
    // UPDATE: basic popup for VT info
    /*
    learnMore.addEventListener("click", (event) => {
      event.stopPropagation();
    
      const infoDialog = document.createElement("dialog");
      infoDialog.classList.add("finding-info-dialog");
    
      const title = document.createElement("h3");
      title.textContent = "About VirusTotal";
    
      // VT popup info
      const description = document.createElement("p");
      description.textContent =
        "VirusTotal checks domains and IP addresses against multiple security vendors and threat intelligence sources to identify known malicious or suspicious activity.";
    
      const closeButton = document.createElement("button");
      closeButton.type = "button";
      closeButton.textContent = "Close";
      closeButton.addEventListener("click", () => infoDialog.close());
    
      infoDialog.append(title, description, closeButton);
      document.body.appendChild(infoDialog);
    
      infoDialog.addEventListener("close", () => infoDialog.remove());
    
      infoDialog.showModal();
    });*/
    
    
    /*learnMore.addEventListener("click", (event) => {
      event.stopPropagation();
      if (virusTotalDialog) return;
    
      const infoDialog = document.createElement("dialog");
      virusTotalDialog = infoDialog;
      infoDialog.classList.add("finding-info-dialog");
    
      // Popup header
      const dialogHeader = document.createElement("div");
      dialogHeader.classList.add("finding-info-header");
    
      const title = document.createElement("h3");
      title.textContent = "About VirusTotal";
    
      const closeButton = document.createElement("button");
      closeButton.type = "button";
      closeButton.textContent = "×";
      closeButton.classList.add("finding-info-close");
      closeButton.style.position = "relative";
      closeButton.style.zIndex = "1";
      // closeButton.addEventListener("click", () => infoDialog.close());
      closeButton.addEventListener("click", (event) => {
        event.stopPropagation();
        infoDialog.remove();
        virusTotalDialog = null;
      });
      closeButton.addEventListener("pointerdown", (event) => {
        event.stopPropagation();
      });
    
      dialogHeader.append(title, closeButton);
    
      // Popup content
      const description = document.createElement("div");
      description.classList.add("finding-info-content");
    
      const explanation = document.createElement("p");
      explanation.textContent =
        "VirusTotal checks domains and IP addresses against multiple security vendors and threat intelligence sources to identify known malicious or suspicious activity.";
    
      description.appendChild(explanation);
    
      infoDialog.append(dialogHeader, description);
      document.body.appendChild(infoDialog);
    
      infoDialog.addEventListener("close", () => infoDialog.remove());
    
      // Allow the popup to move
      let isDragging = false;
      let startX, startY, initialLeft, initialTop;
    
      dialogHeader.addEventListener("pointerdown", (event) => {
        // Don't start dragging when the close button is clicked
        if (event.target.closest(".finding-info-close")) return;
      
        isDragging = true;
      
        const rect = infoDialog.getBoundingClientRect();
        startX = event.clientX;
        startY = event.clientY;
        initialLeft = rect.left;
        initialTop = rect.top;
      
        dialogHeader.setPointerCapture(event.pointerId);
      });
    
      // UPDATE: limit popup window movement
      dialogHeader.addEventListener("pointermove", (event) => {
        if (!isDragging) return;
      
        const newLeft = initialLeft + event.clientX - startX;
        const newTop = initialTop + event.clientY - startY;
      
        // Keep the popup within the visible extension window
        const maxLeft = window.innerWidth - infoDialog.offsetWidth;
        const maxTop = window.innerHeight - infoDialog.offsetHeight;
      
        const boundedLeft = Math.max(0, Math.min(newLeft, maxLeft));
        const boundedTop = Math.max(0, Math.min(newTop, maxTop));
      
        infoDialog.style.left = `${boundedLeft}px`;
        infoDialog.style.top = `${boundedTop}px`;
      });
    
      dialogHeader.addEventListener("pointerup", () => {
        isDragging = false;
      });
    
      dialogHeader.addEventListener("pointercancel", () => {
        isDragging = false;
      });
    
      // Show without blocking the background
      infoDialog.show();
    });*/
    learnMore.addEventListener("click", (event) => {
      event.stopPropagation();
    
      openInfoDialog(
        "virustotal",
        "About VirusTotal",
        "VirusTotal checks domains and IP addresses against multiple security vendors and threat intelligence sources to identify known malicious or suspicious activity."
      );
    });

    const domainChevron = document.createElement("span");
    domainChevron.classList.add("finding-result-chevron");

    // domainToggle.append(domainHeading, domainChevron);
    domainToggle.append(domainHeading, learnMore, domainChevron);

    const domainGroupContent = document.createElement("div");
    domainGroupContent.classList.add("finding-result-group-content");
    domainGroupContent.hidden = true;

    domainResults.forEach(result => {
      const domainCard = document.createElement("div");
      domainCard.classList.add("finding-result-item");

      const domainName = document.createElement("strong");
      domainName.textContent = result.domain;

      const detectionGrid = document.createElement("div");
      detectionGrid.classList.add("finding-detection-grid");

      [
        ["Malicious", result.malicious],
        ["Suspicious", result.suspicious],
        ["Harmless", result.harmless],
        ["Undetected", result.undetected]
      ].forEach(([label, count]) => {
        const detection = document.createElement("div");
        detection.classList.add("finding-detection");

        // Classifying colors for malicious and suspicious
        if (label === "Malicious" && count > 0) {
          detection.classList.add("finding-detection-malicious");
        } else if (label === "Suspicious" && count > 0) {
          detection.classList.add("finding-detection-suspicious");
        }

        // Include vendor fractions
        const countText = document.createElement("strong");
        countText.textContent =
        count != null && result.total_vendors != null
          ? `${count}/${result.total_vendors}`
          : "N/A";

        const labelText = document.createElement("span");
        labelText.textContent = label;

        detection.append(labelText, countText);
        detectionGrid.appendChild(detection);
      });

      domainCard.append(domainName, detectionGrid);
      domainGroupContent.appendChild(domainCard);
    });

    domainToggle.addEventListener("click", () => {
      domainGroupContent.hidden = !domainGroupContent.hidden;
      domainToggle.setAttribute(
        "aria-expanded",
        String(!domainGroupContent.hidden)
      );
    });

    domainGroup.append(domainToggle, domainGroupContent);
    resultContent.appendChild(domainGroup);

    const domainDetails = domainResults.map(result =>
      `Domain: ${result.domain}
      Status: ${result.status}
      Malicious: ${result.malicious}
      Suspicious: ${result.suspicious}
      Harmless: ${result.harmless}
      Undetected: ${result.undetected}`
          ).join("\n\n");

    addHeaderSection(
      "Domain reputation",
      "Header Analysis · Domains",
      {
        meaning: "These results show the available reputation information for domains extracted from the email headers, based on VirusTotal reports.",
        whyItMatters: "Domain reputation can provide context about whether a domain has been associated with suspicious or malicious activity. Zero detections do not guarantee that a domain is safe."
      },
      domainDetails,
      resultContent
    );
  }

  // Header IP reputation
  const ipVirusTotalResults =
    threatIntelResults?.header_ip_virustotal_results || [];

  const ipAbuseResults =
    threatIntelResults?.header_ip_abuseipdb_results || [];

  if (ipVirusTotalResults.length > 0 || ipAbuseResults.length > 0) {
    const resultContent = document.createElement("div");
    resultContent.classList.add("finding-results");

    // Creates an expandable section for each reputation tool
    //function createExpandableResultGroup(title, results, createCard) {
    function createExpandableResultGroup(title, results, createCard, onLearnMore = null) {
      const group = document.createElement("div");
      group.classList.add("finding-result-group");

      const toggleButton = document.createElement("button");
      toggleButton.type = "button";
      toggleButton.classList.add("finding-result-toggle");
      toggleButton.setAttribute("aria-expanded", "false");

      const heading = document.createElement("span");
      heading.textContent = title;

      const learnMore = document.createElement("span");

      if (onLearnMore) {
        learnMore.textContent = "ⓘ Learn more";
        learnMore.classList.add("finding-learn-more");
        learnMore.title = `Learn more about ${title}`;

        learnMore.addEventListener("click", (event) => {
          event.stopPropagation();
          onLearnMore();
        });
      }

      const chevron = document.createElement("span");
      chevron.classList.add("finding-result-chevron");

      //toggleButton.append(heading, chevron);
      toggleButton.append(
        heading,
        ...(onLearnMore ? [learnMore] : []),
        chevron
      );

      const groupContent = document.createElement("div");
      groupContent.classList.add("finding-result-group-content");
      groupContent.hidden = true;

      results.forEach(result => {
        groupContent.appendChild(createCard(result));
      });

      toggleButton.addEventListener("click", () => {
        groupContent.hidden = !groupContent.hidden;
        toggleButton.setAttribute(
          "aria-expanded",
          String(!groupContent.hidden)
        );
      });

      group.append(toggleButton, groupContent);

      return group;
    }

    // VirusTotal IP result cards
    function createVirusTotalIPCard(result) {
      const ipCard = document.createElement("div");
      ipCard.classList.add("finding-result-item");

      const ipName = document.createElement("strong");
      ipName.textContent = result.ip;

      const detectionGrid = document.createElement("div");
      detectionGrid.classList.add("finding-detection-grid");

      [
        ["Malicious", result.malicious],
        ["Suspicious", result.suspicious],
        ["Harmless", result.harmless],
        ["Undetected", result.undetected]
      ].forEach(([label, count]) => {
        const detection = document.createElement("div");
        detection.classList.add("finding-detection");

        const countText = document.createElement("strong");
        // Inlcude vendor fractions
        countText.textContent =
        count != null && result.total_vendors != null
          ? `${count}/${result.total_vendors}`
          : "N/A";

        const labelText = document.createElement("span");
        labelText.textContent = label;

        detection.append(labelText, countText);
        detectionGrid.appendChild(detection);
      });

      ipCard.append(ipName, detectionGrid);

      return ipCard;
    }

    // AbuseIPDB IP result cards
    function createAbuseIPDBCard(result) {
      const ipCard = document.createElement("div");
      ipCard.classList.add("finding-result-item");

      const ipName = document.createElement("strong");
      ipName.textContent = result.ip;

      const abuseGrid = document.createElement("div");
      abuseGrid.classList.add("finding-detection-grid");

      // Update: add whitelisted to AbuseIPDB results
      const whitelisted = result.whitelisted ?? result.is_whitelisted;

      const whitelistStatus =
        whitelisted === true ? "Yes" :
        whitelisted === false ? "No" :
        "N/A";
      [
        ["Abuse confidence", `${result.abuse_confidence_score ?? "N/A"}`],
        ["Total reports", result.total_reports ?? "N/A"],
        ["Country", result.country_code ?? "N/A"],
        ["ISP", result.isp ?? "N/A"],
        ["Whitelisted", whitelistStatus]
      ].forEach(([label, value]) => {
        const detail = document.createElement("div");
        detail.classList.add("finding-detection");

        const valueText = document.createElement("strong");
        valueText.textContent = value;

        const labelText = document.createElement("span");
        labelText.textContent = label;

        detail.append(labelText, valueText);
        abuseGrid.appendChild(detail);
      });

      ipCard.append(ipName, abuseGrid);

      return ipCard;
    }

    // VirusTotal section
    /*if (ipVirusTotalResults.length > 0) {
      resultContent.appendChild(
        createExpandableResultGroup(
          "VirusTotal Results",
          ipVirusTotalResults,
          createVirusTotalIPCard
        )
      );
    }*/
    if (ipVirusTotalResults.length > 0) {
      resultContent.appendChild(
        createExpandableResultGroup(
          "VirusTotal Results",
          ipVirusTotalResults,
          createVirusTotalIPCard,
          () => openInfoDialog(
            "virustotal",
            "About VirusTotal",
            "VirusTotal checks domains and IP addresses against multiple security vendors and threat intelligence sources to identify known malicious or suspicious activity."
          )
        )
      );
    }

    // Divider between tools
    if (ipVirusTotalResults.length > 0 && ipAbuseResults.length > 0) {
      const divider = document.createElement("div");
      divider.classList.add("finding-results-divider");
      resultContent.appendChild(divider);
    }

    // AbuseIPDB section
    /*if (ipAbuseResults.length > 0) {
      resultContent.appendChild(
        createExpandableResultGroup(
          "AbuseIPDB Results",
          ipAbuseResults,
          createAbuseIPDBCard
        )
      );
    }*/
    if (ipAbuseResults.length > 0) {
      resultContent.appendChild(
        createExpandableResultGroup(
          "AbuseIPDB Results",
          ipAbuseResults,
          createAbuseIPDBCard,
          () => openInfoDialog(
            "abuseipdb",
            "About AbuseIPDB",
            "AbuseIPDB provides information about IP addresses reported for abusive activity. PhishCatcher checks the abuse confidence score, total reports, country, and ISP. A higher confidence score or report count can indicate a history of abuse, but does not prove that an IP address is currently malicious."
          )
        )
      );
    }

    const ipDetails = [
      ...ipVirusTotalResults.map(result =>
        `VirusTotal
  IP: ${result.ip}
  Status: ${result.status}
  Malicious: ${result.malicious}
  Suspicious: ${result.suspicious}
  Harmless: ${result.harmless}
  Undetected: ${result.undetected}`
      ),
      ...ipAbuseResults.map(result =>
        `AbuseIPDB
  IP: ${result.ip}
  Status: ${result.status}
  Abuse Confidence Score: ${result.abuse_confidence_score}%
  Total Reports: ${result.total_reports}
  Country: ${result.country_code}
  ISP: ${result.isp}
  Whitelisted: ${result.is_whitelisted}`
      )
    ].join("\n\n");

    addHeaderSection(
      "IP reputation",
      "Header Analysis · IP Addresses",
      {
        meaning: "These results show available reputation information for public IP addresses extracted from the email's Received headers.",
        whyItMatters: "IP reputation can provide context about the servers involved in delivering an email. A lack of reports or detections does not guarantee that an IP address is trustworthy."
      },
      ipDetails,
      resultContent
    );
  }

  // UPDATE: empty state when both authentication findings and header sections have nothing
  const headerFindingsCount =
  (headerAnalysis?.emails?.length > 0 ? 1 : 0) +
  (domainResults.length > 0 ? 1 : 0) +
  (ipVirusTotalResults.length > 0 || ipAbuseResults.length > 0 ? 1 : 0);

  // Tracking URL count
  const urlFindingsCount = allUrls.length;

  // connecting each URL to its three corresponding results and creating parent finding
  if (allUrls.length > 0) {
    const urlCardsContainer = document.createElement("div");
    urlCardsContainer.className = "url-findings-container";

    allUrls.forEach(url => {
      const virusTotalResult = getUrlResult(urlVirusTotalResults, url);
      const ipqsResult = getUrlResult(urlIPQSResults, url);
      const urlhausResult = getUrlResult(urlhausResults, url);
  
      const urlCard = document.createElement("div");
      urlCard.className = "url-finding-card";
  
      const urlTitle = document.createElement("p");
      urlTitle.className = "url-finding-title";
      // urlTitle.textContent = url;
      // Show domain separately, shorten URL path, truncate long URLs
      const parsedUrl = new URL(url);

      // Display domain
      const urlDomain = document.createElement("strong");
      urlDomain.className = "url-finding-domain";
      urlDomain.textContent = parsedUrl.hostname;

      // Display path
      const urlPath = document.createElement("p");
      urlPath.className = "url-finding-path";

      const fullPath = parsedUrl.pathname;
      const maxPathLength = 45;

      urlPath.textContent =
          fullPath.length > maxPathLength
              ? `${fullPath.substring(0, maxPathLength)}...`
              : fullPath || "/";

      // Add domain and path to URL title
      //urlTitle.append(urlDomain, urlPath);
      // View full URL button
      const viewUrlButton = document.createElement("button");
      viewUrlButton.className = "url-view-full-button";
      viewUrlButton.type = "button";
      viewUrlButton.textContent = "View full URL";

      const fullUrlText = document.createElement("p");
      fullUrlText.className = "url-full-text";
      fullUrlText.textContent = url;
      fullUrlText.hidden = true;

      viewUrlButton.addEventListener("click", () => {
          fullUrlText.hidden = !fullUrlText.hidden;

          viewUrlButton.textContent = fullUrlText.hidden
              ? "View full URL"
              : "Hide full URL";
      });

      urlTitle.append(urlDomain, urlPath, viewUrlButton, fullUrlText);
  
      urlCard.appendChild(urlTitle);
      // Include:
      const toolSections = [
        { name: "VirusTotal", result: virusTotalResult },
        { name: "IPQualityScore", result: ipqsResult },
        { name: "URLhaus", result: urlhausResult }
      ];
      
      // Create accordian
      toolSections.forEach(tool => {
        const toolSection = document.createElement("div");
        toolSection.className = "url-tool-section";
    
        const toolToggle = document.createElement("button");
        toolToggle.className = "url-tool-toggle";
        toolToggle.type = "button";
        toolToggle.setAttribute("aria-expanded", "false");
    
        /*const toolHeading = document.createElement("span");
        toolHeading.textContent = tool.name;
    
        const chevron = document.createElement("span");
        chevron.className = "url-tool-chevron";
        chevron.textContent = "⌄";
    
        toolToggle.append(toolHeading, chevron);*/
        
        const toolHeading = document.createElement("span");
        toolHeading.textContent = tool.name;
        
        // Add Learn more for VirusTotal
        if (tool.name === "VirusTotal") {
            const learnMore = document.createElement("span");
            learnMore.textContent = "ⓘ Learn more";
            learnMore.classList.add("finding-learn-more");
            learnMore.title = "Learn more about VirusTotal Results";
        
            learnMore.addEventListener("click", (event) => {
                event.stopPropagation();
        
                openInfoDialog(
                    "virustotal",
                    "About VirusTotal",
                    "VirusTotal checks domains and IP addresses against multiple security vendors and threat intelligence sources to identify known malicious or suspicious activity."
                );
            });
        
            toolToggle.append(toolHeading, learnMore);
        } else {
            toolToggle.appendChild(toolHeading);
        }
        
        const chevron = document.createElement("span");
        chevron.className = "url-tool-chevron";
        chevron.textContent = "⌄";
        
        toolToggle.appendChild(chevron);
        
    
        const toolContent = document.createElement("div");
        toolContent.className = "url-tool-content";
        toolContent.hidden = true;
    
        const toolStatus = document.createElement("p");
        toolStatus.className = "url-tool-status";
        /*toolStatus.textContent = tool.result?.status
            || tool.result?.url_status
            || "No result available";
    
        toolContent.appendChild(toolStatus);*/
        // UPDATE: VT results for URLs
        if (tool.name === "VirusTotal") {
          if (tool.result?.status === "Report found") {
              const metrics = [
                  ["Malicious", tool.result.malicious],
                  ["Suspicious", tool.result.suspicious],
                  ["Harmless", tool.result.harmless],
                  ["Undetected", tool.result.undetected]
              ];
      
              const total = tool.result.total_vendors ?? "N/A";
      
              const metricsContainer = document.createElement("div");
              metricsContainer.className = "finding-detection-grid";
      
              metrics.forEach(([label, value]) => {
                  const metric = document.createElement("div");
                  metric.className = "finding-detection";
      
                  const metricLabel = document.createElement("span");
                  metricLabel.textContent = label;
      
                  const metricValue = document.createElement("strong");
                  metricValue.textContent = `${value ?? "N/A"} / ${total}`;
      
                  metric.append(metricLabel, metricValue);
                  metricsContainer.appendChild(metric);
              });
      
              toolContent.appendChild(metricsContainer);
          } else {
              toolStatus.textContent =
                  tool.result?.error ||
                  (tool.result?.status === "No report found"
                      ? "No existing VirusTotal report was found for this URL."
                      : `VirusTotal result unavailable: ${tool.result?.status || "No result available"}.`);
      
              toolContent.appendChild(toolStatus);
          }
        }
        // IPQS, displays only fields with actual values
        else if (tool.name === "IPQualityScore") {
          if (tool.result?.status === "Report found") {
              const fields = [
                  ["Safe", tool.result.safe],
                  ["Suspicious", tool.result.suspicious],
                  ["Domain", tool.result.domain],
                  ["Malware", tool.result.malware],
                  ["Phishing", tool.result.phishing],
                  ["Risk Score", tool.result.risk_score],
                  ["Domain Age", tool.result.domain_age]
              ];

              const fieldsContainer = document.createElement("div");
              fieldsContainer.className = "finding-detection-grid";

              fields.forEach(([label, value]) => {
                  if (
                      value === undefined ||
                      value === null ||
                      value === "Not found"
                  ) {
                      return;
                  }

                  const field = document.createElement("div");
                  field.className = "finding-detection";

                  const fieldLabel = document.createElement("span");
                  fieldLabel.textContent = label;

                  const fieldValue = document.createElement("strong");

                  if (typeof value === "boolean") {
                      fieldValue.textContent = value ? "Yes" : "No";
                  } else {
                      fieldValue.textContent = value;
                  }

                  field.append(fieldLabel, fieldValue);
                  fieldsContainer.appendChild(field);
              });

              toolContent.appendChild(fieldsContainer);
          } else {
              toolStatus.textContent =
                  tool.result?.error ||
                  `IPQualityScore result unavailable: ${tool.result?.status || "No result available"}.`;

              toolContent.appendChild(toolStatus);
        }
      }
      // URLhaus results for URLs
      else if (tool.name === "URLhaus") {
          if (tool.result?.url_status === "Not found") {
              toolStatus.textContent =
                  "This URL was not found in the URLhaus database.";

              toolContent.appendChild(toolStatus);
          } else if (tool.result?.url_status === "Error") {
              toolStatus.textContent =
                  tool.result?.error ||
                  "URLhaus results are currently unavailable.";

              toolContent.appendChild(toolStatus);
          } else if (tool.result?.url_status) {
              const fields = [
                  ["URL Status", tool.result.url_status],
                  ["Host", tool.result.host],
                  ["Date Added", tool.result.date_added],
                  ["Threat Type", tool.result.threat],
                  ["URLhaus Blocklist", tool.result.urlhaus_blocklist],
                  ["Spamhaus DBL", tool.result.spamhaus_dbl],
                  ["SURBL", tool.result.surbl]
              ];

              const fieldsContainer = document.createElement("div");
              fieldsContainer.className = "finding-detection-grid";

              fields.forEach(([label, value]) => {
                  if (
                      value === undefined ||
                      value === null ||
                      value === "Not found" ||
                      value === "N/A"
                  ) {
                      return;
                  }

                  const field = document.createElement("div");
                  field.className = "finding-detection";

                  const fieldLabel = document.createElement("span");
                  fieldLabel.textContent = label;

                  const fieldValue = document.createElement("strong");
                  fieldValue.textContent = value;

                  field.append(fieldLabel, fieldValue);
                  fieldsContainer.appendChild(field);
              });

              toolContent.appendChild(fieldsContainer);
          } else {
              toolStatus.textContent =
                  "No URLhaus result is available.";

              toolContent.appendChild(toolStatus);
          }
      }
    
      toolToggle.addEventListener("click", () => {
            const isExpanded =
                toolToggle.getAttribute("aria-expanded") === "true";
    
            toolToggle.setAttribute("aria-expanded", String(!isExpanded));
            toolContent.hidden = isExpanded;
            chevron.textContent = isExpanded ? "⌄" : "⌃";
        });
    
        toolSection.append(toolToggle, toolContent);
        urlCard.appendChild(toolSection);
      });
      urlCardsContainer.appendChild(urlCard);
    });

    addFinding(
        "URL Analysis",
        "URL Findings",
        "Reputation results for URLs found in the email.",
        "",
        urlCardsContainer
    );
  }
  
  // display non empty-state message when URLs were found
  if (
    authFindingsCount === 0 &&
    headerFindingsCount === 0 &&
    urlFindingsCount === 0
  ) {
    findingsContainer.textContent =
      "No noteworthy header or authentication findings detected.";
  }

  // Creates a reusable information popup
  /*function openInfoDialog(tool, titleText, explanationText) {
    const isVirusTotal = tool === "virustotal";
    const existingDialog = isVirusTotal
      ? virusTotalDialog
      : abuseIPDBDialog;

    if (existingDialog) return;

    const infoDialog = document.createElement("dialog");

    if (isVirusTotal) {
      virusTotalDialog = infoDialog;
    } else {
      abuseIPDBDialog = infoDialog;
    }

    infoDialog.classList.add("finding-info-dialog");

    // Popup header
    const dialogHeader = document.createElement("div");
    dialogHeader.classList.add("finding-info-header");

    const title = document.createElement("h3");
    title.textContent = titleText;

    const closeButton = document.createElement("button");
    closeButton.type = "button";
    closeButton.textContent = "×";
    closeButton.classList.add("finding-info-close");
    closeButton.style.position = "relative";
    closeButton.style.zIndex = "1";

    closeButton.addEventListener("click", (event) => {
      event.stopPropagation();
      infoDialog.remove();

      if (isVirusTotal) {
        virusTotalDialog = null;
      } else {
        abuseIPDBDialog = null;
      }
    });

    closeButton.addEventListener("pointerdown", (event) => {
      event.stopPropagation();
    });

    dialogHeader.append(title, closeButton);

    // Popup content
    const description = document.createElement("div");
    description.classList.add("finding-info-content");

    const explanation = document.createElement("p");
    explanation.textContent = explanationText;

    description.appendChild(explanation);

    infoDialog.append(dialogHeader, description);
    document.body.appendChild(infoDialog);

    // Allow the popup to move
    let isDragging = false;
    let startX, startY, initialLeft, initialTop;

    dialogHeader.addEventListener("pointerdown", (event) => {
      if (event.target.closest(".finding-info-close")) return;

      isDragging = true;

      const rect = infoDialog.getBoundingClientRect();
      startX = event.clientX;
      startY = event.clientY;
      initialLeft = rect.left;
      initialTop = rect.top;

      dialogHeader.setPointerCapture(event.pointerId);
    });

    dialogHeader.addEventListener("pointermove", (event) => {
      if (!isDragging) return;

      const newLeft = initialLeft + event.clientX - startX;
      const newTop = initialTop + event.clientY - startY;

      const maxLeft = window.innerWidth - infoDialog.offsetWidth;
      const maxTop = window.innerHeight - infoDialog.offsetHeight;

      infoDialog.style.left =
        `${Math.max(0, Math.min(newLeft, maxLeft))}px`;
      infoDialog.style.top =
        `${Math.max(0, Math.min(newTop, maxTop))}px`;
    });

    dialogHeader.addEventListener("pointerup", () => {
      isDragging = false;
    });

    dialogHeader.addEventListener("pointercancel", () => {
      isDragging = false;
    });

    infoDialog.show();
  }*/

  // Creates a reusable information popup
  function openInfoDialog(tool, titleText, explanationText) {
    const isVirusTotal = tool === "virustotal";
    const existingDialog = isVirusTotal
      ? virusTotalDialog
      : abuseIPDBDialog;

    if (existingDialog) return;

    // Get the information stored in tool_info.js
    const info = toolInfo[tool];

    const infoDialog = document.createElement("dialog");

    if (isVirusTotal) {
      virusTotalDialog = infoDialog;
    } else {
      abuseIPDBDialog = infoDialog;
    }

    infoDialog.classList.add("finding-info-dialog");

    // Popup header
    const dialogHeader = document.createElement("div");
    dialogHeader.classList.add("finding-info-header");

    const title = document.createElement("h3");
    title.textContent = info?.title || titleText;

    const closeButton = document.createElement("button");
    closeButton.type = "button";
    closeButton.textContent = "×";
    closeButton.classList.add("finding-info-close");
    closeButton.style.position = "relative";
    closeButton.style.zIndex = "1";

    closeButton.addEventListener("click", (event) => {
      event.stopPropagation();
      infoDialog.remove();

      if (isVirusTotal) {
        virusTotalDialog = null;
      } else {
        abuseIPDBDialog = null;
      }
    });

    closeButton.addEventListener("pointerdown", (event) => {
      event.stopPropagation();
    });

    dialogHeader.append(title, closeButton);

    // Popup content
    const description = document.createElement("div");
    description.classList.add("finding-info-content");

    // Display structured information from tool_info.js
    if (info?.sections) {
      info.sections.forEach((section) => {
        const sectionContainer = document.createElement("section");
        sectionContainer.classList.add("finding-info-section");

        const heading = document.createElement("h4");
        heading.textContent = section.heading;
        sectionContainer.appendChild(heading);

        // Regular paragraphs
        section.paragraphs?.forEach((paragraphText) => {
          const paragraph = document.createElement("p");
          paragraph.textContent = paragraphText;
          sectionContainer.appendChild(paragraph);
        });

        // Definitions
        section.definitions?.forEach((definition) => {
          const definitionContainer = document.createElement("div");
          definitionContainer.classList.add("finding-info-definition");

          const term = document.createElement("strong");
          term.textContent = `${definition.term}: `;

          const meaning = document.createElement("span");
          meaning.textContent = definition.meaning;

          definitionContainer.append(term, meaning);
          sectionContainer.appendChild(definitionContainer);
        });

        // Paragraphs that appear after definitions
        section.paragraphsAfterDefinitions?.forEach((paragraphText) => {
          const paragraph = document.createElement("p");
          paragraph.textContent = paragraphText;
          sectionContainer.appendChild(paragraph);
        });

        // Example results
        if (section.example) {
          const example = section.example;

          const exampleDescription = document.createElement("p");
          exampleDescription.textContent = example.description;
          sectionContainer.appendChild(exampleDescription);

          const exampleResults = document.createElement("ul");

          example.results.forEach((result) => {
            const item = document.createElement("li");
            
            const label = document.createElement("strong");
            label.textContent = `${result.label}: `;
            
            const value = document.createElement("span");
            value.textContent =
            example.total > 0
              ? `${result.count}/${example.total}`
              : result.count;
            
            item.append(label, value);
            exampleResults.appendChild(item);
          });

          sectionContainer.appendChild(exampleResults);

          const steps = document.createElement("ol");

          example.steps.forEach((step) => {
            const item = document.createElement("li");
            item.textContent = step;
            steps.appendChild(item);
          });

          // Inlcude ex note in popup
          sectionContainer.appendChild(steps);

          // Include example note after the numbered steps
          if (example.note) {
            const note = document.createElement("p");
            note.classList.add("finding-info-note");

            const noteLabel = document.createElement("strong");
            noteLabel.textContent = "Note: ";

            const noteText = document.createElement("span");
            noteText.textContent = example.note;

            note.append(noteLabel, noteText);
            sectionContainer.appendChild(note);
          }
        }

        description.appendChild(sectionContainer);
      });

      // Disclosure note at the bottom
      if (info.disclosure) {
        const disclosure = document.createElement("div");
        disclosure.classList.add("finding-info-disclosure");

        const disclosureHeading = document.createElement("strong");
        disclosureHeading.textContent = info.disclosure.heading;

        const disclosureText = document.createElement("p");
        disclosureText.textContent = info.disclosure.text;

        disclosure.append(disclosureHeading, disclosureText);
        description.appendChild(disclosure);
      }
    } else {
      // Fallback for tools without structured information yet
      const explanation = document.createElement("p");
      explanation.textContent = explanationText;
      description.appendChild(explanation);
    }

    infoDialog.append(dialogHeader, description);
    document.body.appendChild(infoDialog);

    // Allow the popup to move
    let isDragging = false;
    let startX, startY, initialLeft, initialTop;

    dialogHeader.addEventListener("pointerdown", (event) => {
      if (event.target.closest(".finding-info-close")) return;

      isDragging = true;

      const rect = infoDialog.getBoundingClientRect();
      startX = event.clientX;
      startY = event.clientY;
      initialLeft = rect.left;
      initialTop = rect.top;

      dialogHeader.setPointerCapture(event.pointerId);
    });

    dialogHeader.addEventListener("pointermove", (event) => {
      if (!isDragging) return;

      const newLeft = initialLeft + event.clientX - startX;
      const newTop = initialTop + event.clientY - startY;

      const maxLeft = window.innerWidth - infoDialog.offsetWidth;
      const maxTop = window.innerHeight - infoDialog.offsetHeight;

      infoDialog.style.left =
        `${Math.max(0, Math.min(newLeft, maxLeft))}px`;
      infoDialog.style.top =
        `${Math.max(0, Math.min(newTop, maxTop))}px`;
    });

    dialogHeader.addEventListener("pointerup", () => {
      isDragging = false;
    });

    dialogHeader.addEventListener("pointercancel", () => {
      isDragging = false;
    });

    infoDialog.show();
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
  function addFinding(title, category, explanation, technicalDetails, resultContent = null) {
    const container = document.getElementById("findings-container");

    // Finding card
    const card = document.createElement("div");
    card.classList.add("finding-card");

    // Clickable finding title
    const titleButton = document.createElement("button");
    titleButton.classList.add("finding-title");
    //titleButton.textContent = title;
    titleButton.innerHTML = `
      <span>${title}</span>
      <span class="finding-chevron"></span>
    `;
    titleButton.setAttribute("aria-expanded", "false");

    // Expandable content
    const content = document.createElement("div");
    content.classList.add("finding-content");
    content.hidden = true;

    const categoryLabel = document.createElement("p");
    categoryLabel.textContent = category;
    // UPDATE
    categoryLabel.classList.add("finding-category");

    //const explanationText = document.createElement("p");
    //explanationText.textContent = explanation;
    const meaningLabel = document.createElement("strong");
    meaningLabel.textContent = "What it means";

    const explanationDivider = document.createElement("div");
    explanationDivider.classList.add("finding-explanation-divider");

    const meaningText = document.createElement("p");
    meaningText.textContent = explanation.meaning;

    const whyLabel = document.createElement("strong");
    whyLabel.textContent = "Why it matters";

    const whyText = document.createElement("p");
    whyText.textContent = explanation.whyItMatters;

    // Technical details button
    const technicalButton = document.createElement("button");
    technicalButton.classList.add("finding-technical-button");
    technicalButton.textContent = "View technical details";

    // Technical details content
    const technicalContent = document.createElement("p");
    technicalContent.classList.add("finding-technical-details");
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
    // content.append(categoryLabel, explanationText, technicalButton, technicalContent);
    content.append(
      categoryLabel,
      ...(resultContent ? [resultContent] : []),
      explanationDivider,
      meaningLabel,
      meaningText,
      whyLabel,
      whyText,
      technicalButton,
      technicalContent
    );
    card.append(titleButton, content);
    container.appendChild(card);
  } 

  // Helper function
  function addHeaderSection(title, category, explanation, technicalDetails, resultContent) {
    addFinding(
      title,
      category,
      explanation,
      technicalDetails,
      resultContent
    );
  }
});


