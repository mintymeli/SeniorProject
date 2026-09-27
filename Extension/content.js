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

  // when the button is clicked
  button.addEventListener("click", () => {

    console.log("PhishCatcher Analyze button clicked.");

    const emailElement = document.querySelector('div.adn');

    if (!emailElement) {
      alert("Open an email first.");
      return;
    }

    const messageId =
      emailElement.getAttribute("data-legacy-message-id");

    if (!messageId) {
      alert("Could not find the email ID.");
      return;
    }

    console.log("Analyzing email:", messageId);

    chrome.runtime.sendMessage({
      action: "ANALYZE_EMAIL",
      messageId: messageId
    });

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