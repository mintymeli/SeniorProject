// PhishCatcher Background Service Worker

// Function to log user in and get their Google OAuth Access Token
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

// Fetchs the actual data for Gmail attachment
async function fetchAttachmentData(token, messageId, attachmentId) {
  const attachmentUrl =
    `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}/attachments/${attachmentId}`;

  const response = await fetch(attachmentUrl, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  // Stops if Gmail could not retrieve the attachment
  if (!response.ok) {
    throw new Error(`Failed to fetch attachments: ${response.status}`);
  }

  const attachmentData = await response.json();

  // Gmail returns the attachment data 
  return attachmentData.data;
}

// Finds attachments throughout the email and retrieves their data
async function retrieveAttachments(part, token, messageId) {
  if (!part) return;

  const filename = part.filename || "";
  const mimeType = part.mimeType || "";
  const body = part.body || {};

  // Check whether it's an image or a named attachment
  const isAttachment = filename !== "" || mimeType.startsWith("image/");

  // Retrieve the actual data when Gmail provides an attachment ID
  if (isAttachment && body.attachmentId) {
    console.log(`Fetching attachment: ${filename || mimeType}`);

    const attachmentData = await fetchAttachmentData(
      token,
      messageId,
      body.attachmentId
    );

    // Store the retrieved data in the email payload for the backend
    part.body.data = attachmentData;

    console.log(`Retrieved attachment: ${filename || mimeType}`);
  }

  // Checks nested email parts too
  if (part.parts && part.parts.length > 0) {
    for (const childPart of part.parts) {
      await retrieveAttachments(childPart, token, messageId);
    }
  }
}

// Function to fetch email payload sends it to the backend
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

    // Checks whether Gmail successfully returned the email
    if (!response.ok) {
      throw new Error(`Failed to fetch email: ${response.status}`);
    }

    const emailData = await response.json();

    // Retrieves attachment data 
    console.log("Checking email for attachments");

    if (emailData.payload) {
      await retrieveAttachments(emailData.payload, token, messageId);
    }

    // POST the email JSON data directly to local Python FastAPI server
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

// UPDATE CHANGE
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "ANALYZE_EMAIL") {
    console.log("Received Gmail API message ID:", message.messageId);
    analyzeEmail(message.messageId);
  }
});