// content.js - Scrapes visible text from the open Gmail page

function extractActiveEmailHeader() {
  // Gmail uses 'span.gD' for the sender string and 'h1.hP' for the subject text
  const senderElement = document.querySelector('span.gD');
  const subjectElement = document.querySelector('h1.hP');

  if (senderElement && subjectElement) {
    const headerPayload = {
      action: "ANALYZE_RAW_HEADERS",
      sender: senderElement.getAttribute('email') || senderElement.innerText,
      subject: subjectElement.innerText
    };

    console.log("PhishCatcher scraped values:", headerPayload);
    
    // Pass the text strings directly to your background.js script
    chrome.runtime.sendMessage(headerPayload);
  }
}

// Watch for clicks inside Gmail. When a user clicks an email row, wait 1 second and scan.
window.addEventListener('click', () => {
  setTimeout(extractActiveEmailHeader, 1000);
});