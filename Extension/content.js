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
      return;
    }
  }

  console.log("Email not ready yet. Checking again...");
  setTimeout(getCurrentEmailId, 1000);
}

getCurrentEmailId();