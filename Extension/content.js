// Testing
// console.log("PhishCatcher content.js is running!");

// PhishCatcher Content Script
/**
function checkCurrentEmail() {
  console.log("Checking current Gmail page...");
  console.log("Current URL:", window.location.href);
}

checkCurrentEmail();
*/

// Testing Web ID
/**
function checkCurrentEmail() {
  const hash = window.location.hash;
  const parts = hash.split("/");

  if (parts.length >= 2 && parts[1]) {
    const gmailWebId = parts[1];

    console.log("Gmail web ID:", gmailWebId);
  } else {
    console.log("No email is currently open.");
  }
}

checkCurrentEmail(); 
*/

// Testing data-legacy-message-id
// PhishCatcher Content Script

let phishCatcherPanel = null;
let phishCatcherReopenTab = null;

function createAnalysisPanel() {
  // Reuse the existing panel if it was already created.
  if (phishCatcherPanel) {
    phishCatcherPanel.style.display = "block";
    phishCatcherReopenTab.style.display = "none";
    return;
  }

  // Create the panel container.
  const panel = document.createElement("iframe");
  panel.id = "phishcatcher-analysis-frame";
  panel.src = chrome.runtime.getURL("analysis_popup.html");

  Object.assign(panel.style, {
    position: "fixed",
    top: "0",
    right: "0",
    width: "380px",
    height: "100vh",
    border: "none",
    background: "#f7f9fc",
    boxShadow: "-4px 0 20px rgba(0,0,0,0.15)",
    zIndex: "1000001"
  });

  document.body.appendChild(panel);
  phishCatcherPanel = panel;

  // Create a tab that lets user reopen the panel
  const reopenTab = document.createElement("button");
  reopenTab.id = "phishcatcher-reopen-tab";
  reopenTab.textContent = "🐟 PhishCatcher";
  reopenTab.title = "Reopen PhishCatcher analysis";

  Object.assign(reopenTab.style, {
    position: "fixed",
    top: "50%",
    right: "0",
    transform: "translateY(-50%)",
    padding: "12px 10px",
    border: "1px solid #dce5f5",
    borderRight: "none",
    borderRadius: "12px 0 0 12px",
    background: "white",
    color: "#4776e6",
    fontSize: "12px",
    fontWeight: "600",
    cursor: "pointer",
    boxShadow: "-2px 2px 10px rgba(0,0,0,0.12)",
    zIndex: "1000000",
    display: "none"
  });

  reopenTab.addEventListener("click", () => {
    panel.style.display = "block";
    reopenTab.style.display = "none";
  });

  document.body.appendChild(reopenTab);
  phishCatcherReopenTab = reopenTab;
}

// Listen for the popup's close button.
window.addEventListener("message", (event) => {
  if (
    event.source === phishCatcherPanel?.contentWindow &&
    event.data?.type === "PHISHCATCHER_CLOSE"
  ) {
    phishCatcherPanel.style.display = "none";
    phishCatcherReopenTab.style.display = "block";
  }
});

function getCurrentEmailId() {
  const emailElement = document.querySelector('div.adn');

  if (emailElement) {
    const messageId = emailElement.getAttribute('data-legacy-message-id');

    if (messageId) {
      console.log("PhishCatcher found Gmail API message ID:", messageId);

      // UPDATE CHANGE
      chrome.runtime.sendMessage({
      action: "ANALYZE_EMAIL",
      messageId: messageId
      });

      return;
    }
  }

  console.log("Email not ready yet. Checking again...");
  setTimeout(getCurrentEmailId, 1000);
}

//getCurrentEmailId();

// Analyze Email Button Tester (it's a work in progress)

  // analyze email button 
  function createAnalyzeButton() {

  // prevent duplicate buttons
  if (document.getElementById("phishcatcher-analyze-button")) {
    return;
  }

  const button = document.createElement("button");

  button.id = "phishcatcher-analyze-button";
  button.innerHTML = "🐟 Analyze Email";

  // button position
  button.style.position = "fixed";
  button.style.top = "73px";
  button.style.left = "60%";
  button.style.transform = "translateX(-50%)";
  button.style.zIndex = "999999";

  // button appearance
  button.style.padding = "8px 16px";
  button.style.borderRadius = "18px";
  button.style.border = "1px solid #ddd";
  button.style.background = "white";
  button.style.color = "#4f6fd8";
  button.style.fontSize = "12px";
  button.style.fontWeight = "600";
  button.style.cursor = "pointer";

  button.style.boxShadow = "0 2px 8px rgba(0,0,0,0.15)";

  // when button is clicked
  button.addEventListener("click", () => {

    console.log("PhishCatcher Analyze button clicked.");
    // update
    createAnalysisPanel();
    const emailElement = document.querySelector('div.adn');

   if (!emailElement) {
     alert("Open an email first.");
      return;
    }

   //const messageId = getCurrentEmailId();

    const messageId =
      emailElement.getAttribute("data-legacy-message-id");

    if (!messageId) {
      alert("Could not find the email ID.");
      return;
    }

    console.log("Analyzing email:", messageId);

    chrome.runtime.sendMessage(
      { action: "ANALYZE_EMAIL", messageId: messageId },
      (response) => {
        // The backend results come back here (background.js has to call sendResponse).
        if (chrome.runtime.lastError) {
          console.log("PhishCatcher: no response from background.js:", chrome.runtime.lastError.message);
          return;
        }

        // Check whether headers reached content.js
        console.log("Headers received in content.js:", response?.headers);

        // update: send header object to main
        if (response && response.headers && phishCatcherPanel?.contentWindow) {
          phishCatcherPanel.contentWindow.postMessage(
            {
              type: "PHISHCATCHER_ANALYSIS_RESULT",
              headers: response.headers
            },
            "*"
          );
        }
        if (response && response.body_findings && typeof phishcatcherHighlight === "function") {
          const count = phishcatcherHighlight(response.body_findings);
          console.log("PhishCatcher highlighted", count, "phrase(s) in the email");
        }
      }
    );

    // button text
    button.innerHTML = "Analyzing...";
    button.disabled = true;

    setTimeout(() => {
      button.innerHTML = "🐟 Analyze Email";
      button.disabled = false;
    }, 2000);
  });

  document.body.appendChild(button);

  console.log("PhishCatcher Analyze Email button added.");
}

// only shows when an email is open
function updateAnalyzeButtonVisibility() {

  const button = document.getElementById("phishcatcher-analyze-button");

  if (!button) {
    return;
  }

  // gmail has an open email when div.adn exists
  const emailIsOpen = document.querySelector("div.adn");

  if (emailIsOpen) {
    button.style.display = "block";
  } else {
    button.style.display = "none";
  }
}

// starting the button
function initializePhishCatcher() {

  if (!document.body) {
    setTimeout(initializePhishCatcher, 500);
    return;
  }

  createAnalyzeButton();
  
  // checks immediately
  updateAnalyzeButtonVisibility();

  // watches gmail for opening/closing/switching emails
  const observer = new MutationObserver(() => {
    updateAnalyzeButtonVisibility();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

initializePhishCatcher();

//getCurrentEmailId();