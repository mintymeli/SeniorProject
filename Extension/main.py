from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware 
import base64

app = FastAPI()

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
    if email_body:

        try:
            decoded_body = base64.urlsafe_b64decode(
                email_body + "=="
            ).decode("utf-8", errors="replace")

        except Exception as error:
            print("Could not decode email body:", error)
            decoded_body = "Could not decode email body."

    else:
        decoded_body = "No email body found."
    
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

    # Print the decoded email body
    print("BODY:")
    print()
    print(decoded_body)
    print("="*50 + "\n")
    
    # 5. Send a quick success message back to the Chrome Extension
    return {
        "status": "Success",
        "message": f"Successfully read header for email: {email_subject}"
    }

if __name__ == "__main__":
    import uvicorn
    # Starts your local server on http://127.0.0.1:8000
    uvicorn.run(app, host="127.0.0.1", port=8000)