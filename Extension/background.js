// PhishCatcher Background Service Worker

// Function to log the user in and get their Google OAuth Access Token
function getAuthToken() {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive: true }, function(token) {
      if (chrome.runtime.lastError) {
        reject(chrome.runtime.lastError);
      } else {
        resolve(token);
      }
    });
  });
}

// Function to fetch email payload using token and send it to your backend
async function analyzeEmail(messageId) {
  try {
    console.log("Fetching authentication token...");
    const token = await getAuthToken();
    
    // Google API URL to fetch a specific email message by its ID
    const googleApiUrl = `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`;
    
    console.log(`Fetching email data for ID: ${messageId}`);
    
    const response = await fetch(googleApiUrl, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const emailData = await response.json();

    // POST the email JSON data directly to your local Python FastAPI server
    console.log("Forwarding email data to PhishCatcher backend...");
    const backendResponse = await fetch('http://127.0.0.1:8000/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(emailData)
    });
    
    const analysisResult = await backendResponse.json();
    console.log("PhishCatcher Analysis Verdict:", analysisResult);
    
  } catch (error) {
    console.error("Error processing email in background script:", error);
  }
}

// Listener for installation confirmation
chrome.runtime.onInstalled.addListener(() => {
  console.log("PhishCatcher Extension successfully installed!");
});