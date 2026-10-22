from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware 
from email_checks import analyze_attachments, analyze_sender_and_recipients
import base64
import re 
import hashlib

from body_classifier import BodyAnalyzer

app = FastAPI()

body_analyzer = BodyAnalyzer()

# Allows Chrome Extension to talk to local backend server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Extracts the email body
def extract_email_body(payload):

     # Get the body data from the email
    body_data = payload.get("body", {}).get("data")

    if body_data:
        return body_data

     # Check each part of the email for the body
    for part in payload.get("parts", []):
        body = extract_email_body(part)

        if body:
            return body

    # Return an empty value if no body was found
    return ""

# Extracts URLs from the email body
def extract_urls(email_body): 

    # Finds URLs that start with http:// or https://
    urls = re.findall(r'https?://[^\s<>"\']+', email_body)

    # Removes duplicate URLs
    return list(dict.fromkeys(urls))

# Find images/attachments in the email and retrives hashes
def extract_attachment_hashes(payload):
    attachment_hashes = []

    # Checks each part of the email
    def check_parts(part):
        filename = part.get("filename", "")
        mime_type = part.get("mimeType", "")
        body = part.get("body", {})

        # Check if it's an image or a named attachment
        is_attachment = bool(filename) or mime_type.startswith("image/")

        # Gets the attachment data if it's available
        if is_attachment and body.get("data"):
            try:
                # Converts the attachment data back into file bytes
                data = body["data"]
                padding = "=" * (-len(data) % 4)
                file_bytes = base64.urlsafe_b64decode(data + padding)

                # Calculates the file's hash
                sha256_hash = hashlib.sha256(file_bytes).hexdigest()

                # Saves the filename and hash
                attachment_hashes.append({
                    "filename": filename or "Unnamed image",
                    "mime_type": mime_type,
                    "sha256": sha256_hash
                })

            except Exception as error:
                print(f"Could not hash {filename}: {error}")

        # Check any parts inside this part
        for child_part in part.get("parts", []):
            check_parts(child_part)

    check_parts(payload)
    return attachment_hashes

@app.post("/analyze")
async def analyze_email(request: Request):
    # 1. Catch the raw JSON payload coming from background.js
    email_json = await request.json()
    
    # 2. Navigate to where Google stores headers inside the JSON
    headers = email_json.get('payload', {}).get('headers', [])


    '''
    # 3. Pull out the specific headers we want to read
    email_subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), "No Subject")
    email_sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), "Unknown Sender")
    email_date = next((h['value'] for h in headers if h['name'].lower() == 'date'), "No Date")
    '''

    # Extracts the email body
    email_body = extract_email_body(email_json.get ('payload', {}))
    
    # UPDATE: Organize the headers by name for easier lookup
    header_map = {
        h["name"].lower(): h["value"]
        for h in headers
        if "name" in h and "value" in h
    }
    # Extract basic email information
    email_subject = header_map.get("subject", "No Subject")
    email_sender = header_map.get("from", "Unknown Sender")
    email_date = header_map.get("date", "No Date")

    # Extract security-relevant headers
    email_reply_to = header_map.get("reply-to", "Not provided")
    email_return_path = header_map.get("return-path", "Not provided")
    email_received = [
        h["value"] for h in headers
        if h.get("name", "").lower() == "received"
    ]
    email_auth_results = [
        h["value"] for h in headers
        if h.get("name", "").lower() == "authentication-results"
    ]
    email_message_id = header_map.get("message-id", "Not provided")

    # Decodes the Base64URL encoded body
    body_decoded_ok = False 

    # Decodes the Base64URL encoded body
    if email_body:

        try:
            decoded_body = base64.urlsafe_b64decode(
                email_body + "=="
            ).decode("utf-8", errors="replace")
            body_decoded_ok = True

        except Exception as error:
            print("Could not decode email body:", error)
            decoded_body = "Could not decode email body."

    else:
        decoded_body = "No email body found."

    email_urls = extract_urls(decoded_body)

    body_findings = body_analyzer.analyze(decoded_body) if body_decoded_ok else []

    # Attachment and sender/recipient checks stay separate from the body findings
    attachment_findings = analyze_attachments(email_json.get("payload", {}), decoded_body if body_decoded_ok else "", body_analyzer)
    sender_findings = analyze_sender_and_recipients(header_map)

    # Calculates hashes for images/attachments
    attachment_hashes = extract_attachment_hashes(email_json.get("payload", {}))
    
    # 4. Print headers to terminal
    print("\n" + "="*50)
    print("[NEW EMAIL RECEIVED FROM EXTENSION]")
    print(f"MESSAGE ID: {email_json.get('id')}")
    print(f"SENDER:  {email_sender}")
    print(f"SUBJECT: {email_subject}")
    print(f"DATE:    {email_date}")

    # UPDATE: Print extra headers
    print(f"🐟 REPLY-TO: {email_reply_to}")
    print(f"🐟 RETURN-PATH: {email_return_path}")
    print(f"🐟 MESSAGE-ID HEADER: {email_message_id}")

    print("🐟 RECEIVED HEADERS:")
    for value in email_received:
        print(value)

    print("🐟 AUTHENTICATION RESULTS:")
    for value in email_auth_results:
        print(value)

    # Prints URLs
    print("🐟 LINK RESULTS:")

    if email_urls: 
        for url in email_urls:
            print(f"URL: {url}")
            print()
    else:
        print("No URLs found.")
        print()

   # Prints filename, type of attachment, and hash  
    if attachment_hashes:
        print("🐟 SHA256 ANALYSIS:")
        
        for attachment in attachment_hashes:
            print("Filename:", attachment["filename"])
            print("Type:", attachment["mime_type"])
            print("SHA256:", attachment["sha256"])
            print()
    else:
        print("🐟 SHA256 ANALYSIS: No attachments found.")
        print()

    print("🐟 ATTACHMENT ANALYSIS:")
    if attachment_findings:
        for finding in attachment_findings:
            print(f"[{finding['severity']}] {finding['type']}: {finding['description']}")
    else:
        print("No attachment warning signs found.")
    print()

    print("🐟 SENDER & RECIPIENT ANALYSIS:")
    if sender_findings:
        for finding in sender_findings:
            print(f"[{finding['severity']}] {finding['type']}: {finding['description']}")
    else:
        print("No sender or recipient warning signs found.")
    print()

    print("🐟 BODY ANALYSIS:")
    if body_findings:
        for finding in body_findings:
            print(f"[{finding['severity']}] {finding['type']}: {finding['description']}")
    else:
        print("No warning signs found in the message wording.")
    print()

    # Print the decoded email body
    print("🐟 BODY:")
    print()
    print(decoded_body)
    print("="*50 + "\n")

    # 5. Send a quick success message back to the Chrome Extension
    return {
        "status": "Success",
        "message": f"Successfully read header for email: {email_subject}",

        # Header object with exttracted values
        "headers": {
            "subject": email_subject,
            "from": email_sender,
            "date": email_date,
            "reply_to": email_reply_to,
            "return_path": email_return_path,
            "received": email_received,
            "authentication_results": email_auth_results,
            "message_id": email_message_id,
        },

        "body_findings": body_findings,
        "attachment_findings": attachment_findings,
        "sender_findings": sender_findings,
        "links": email_urls,
    }

if __name__ == "__main__":
    import uvicorn
    # Starts your local server on http://127.0.0.1:8000
    uvicorn.run(app, host="127.0.0.1", port=8000)