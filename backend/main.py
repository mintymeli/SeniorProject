from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware 
from email_checks import analyze_attachments, analyze_sender_and_recipients
from threat_intel import analyze_tools, vt_result
import base64
import re 
import hashlib
import html
import ipaddress
from remediation import build_payload, get_remediation
from body_classifier import BodyAnalyzer
from header_analysis import analyze_headers

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

MAX_LINKS = 10
SKIP_LINK_PATTERNS = (
    r"^https?://(www\.)?w3\.org/",             # HTML boilerplate (DOCTYPE, xmlns)
    r"\.(png|jpe?g|gif|svg|webp|ico)(\?|$)",   # images
    r"/wf/open\b",                             # 1x1 tracking pixel
)

def is_useful_link(url):
    return not any(re.search(p, url, re.IGNORECASE) for p in SKIP_LINK_PATTERNS)

# Reads a Gmail body part (base64url) into text
def decode_part(data):
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding).decode("utf-8", errors="replace")

# Finds links inside the HTML part, including buttons and image links
def extract_html_links(payload):
    links = []

    def walk(part):
        data = part.get("body", {}).get("data")
        if part.get("mimeType") == "text/html" and data:
            try:
                page = decode_part(data)
                for href in re.findall(r'href\s*=\s*["\']([^"\']+)["\']', page, flags=re.I):
                    href = html.unescape(href).strip()
                    if href.lower().startswith(("http://", "https://")):
                        links.append(href)
            except Exception as error:
                print("Could not read HTML links:", error)

        for child in part.get("parts", []):
            walk(child)

    walk(payload)
    return links

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

    # TEMPORARY
    '''
    print("\n--- HI AUTHENTICATION-RELATED HEADERS ---")

    for h in headers:
        name = h.get("name", "").lower()

        if name in (
            "authentication-results",
            "arc-authentication-results",
            "received",
            "received-spf"
        ):
            print(f"{h.get('name')}: {h.get('value')}")
    '''

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
    # UPDATE:
    header_analysis = analyze_headers(header_map, email_received)
    # Keeps only public IP addresses for external threat intelligence checks
    public_header_ips = [
        ip for ip in header_analysis["ips"]
        if ipaddress.ip_address(ip).is_global
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

    email_urls = [
        u for u in dict.fromkeys(
            extract_urls(decoded_body) + extract_html_links(email_json.get("payload", {}))
        ) if is_useful_link(u)
    ][:MAX_LINKS]

    body_findings = body_analyzer.analyze(decoded_body) if body_decoded_ok else []

    # Attachment and sender/recipient checks stay separate from the body findings
    attachment_findings = analyze_attachments(email_json.get("payload", {}), decoded_body if body_decoded_ok else "", body_analyzer)
    sender_findings = analyze_sender_and_recipients(header_map)

    # Calculates hashes for images/attachments
    attachment_hashes = extract_attachment_hashes(email_json.get("payload", {}))

    '''remediation_payload = build_payload(
        body_findings, attachment_findings, sender_findings,
        auth_results=email_auth_results, from_header=email_sender,
        url_count=len(email_urls),
        attachment_kinds=[a["mime_type"] for a in attachment_hashes],
    )'''

    # Analyze email links and attachment hashes using threat intel tools
    threat_intel_results = analyze_tools(
        email_urls, 
        attachment_hashes,
        # UPDATE: include header indicators
        header_domains=header_analysis["domains"],
        header_ips=public_header_ips
    )

    remediation_payload = build_payload(
        body_findings, attachment_findings, sender_findings,
        auth_results=email_auth_results, from_header=email_sender,
        reply_to=email_reply_to,
        url_count=len(email_urls),
        attachment_kinds=[a["mime_type"] for a in attachment_hashes],
        intel=threat_intel_results,
    )

    remediation = get_remediation(remediation_payload)

    print("🐟 REMEDIATION:")
    print(f"[{remediation['risk_level']}] {remediation['verdict']} (from {remediation['source']})")
    for action in remediation["actions"]:
        print(" -", action)
    print()

    
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

    # Prints extracted header email addresses
    print("\n🐟🐟 HEADER EMAIL EXTRACTION:")

    if header_analysis["emails"]:
        for email in header_analysis["emails"]:
            print(f"Email: {email}")
    else:
        print("No email addresses found.")

    # ----- Prints Threat Intel Results -----
    # Prints header domain VirusTotal Results
    print("\n🐟🐟 HEADER DOMAIN VIRUSTOTAL ANALYSIS:")

    if threat_intel_results["header_domain_results"]:
        for result in threat_intel_results["header_domain_results"]:
            print(f"Domain: {result.get('domain')}")
            print(f"Status: {result.get('status')}")
            print(f"Malicious: {result.get('malicious')}")
            print(f"Suspicious: {result.get('suspicious')}")
            print(f"Harmless: {result.get('harmless')}")
            print(f"Undetected: {result.get('undetected')}")
            print("-" * 30)
    else:
        print("No header domain results found.")
    
    # Prints VT URL Results
    print("🐟 VIRUSTOTAL URL ANALYSIS:")

    if threat_intel_results["url_results"]:
        for result in threat_intel_results["url_results"]:
            print(vt_result(result, "URL"))
            print()
    else:
        print("No URLs found.")

    # Prints VT Hash Results
    print("\n🐟 VIRUSTOTAL HASH ANALYSIS:")

    if threat_intel_results["file_hash_results"]:
        for result in threat_intel_results["file_hash_results"]:
            print(vt_result(result, "SHA256"))
            print()
    else:
        print("No attachment hashes found.")

    # IPQS analysis results
    print("\n🐟 IPQUALITYSCORE ANALYSIS:")

    if threat_intel_results["ipqs_results"]:
        for result in threat_intel_results["ipqs_results"]:
            safe = result.get("safe")
            safe_output = (
                "Yes" if safe is True
                else "No" if safe is False
                else "Not found"
            )

            print(f"URL: {result.get('url', 'Not found')}")
            print(f"Safe: {safe_output}")
            print(f"Suspicious: {result.get('suspicious', 'Not found')}")
            print(f"Domain: {result.get('domain', 'Not found')}")
            print(f"Malware: {result.get('malware', 'Not found')}")
            print(f"Phishing: {result.get('phishing', 'Not found')}")
            print(f"Risk Score: {result.get('risk_score', 'Not found')}")
            print(f"Domain Age: {result.get('domain_age') or 'Not found'}")
            print()
    else:
        print("No URLs found for analysis.") 

    # URLscan.io analysis results
    print("\n🐟 URLSCAN.IO URL ANALYSIS:")

    if threat_intel_results["urlscan_results"]:

        for result in threat_intel_results["urlscan_results"]:

            print(f"URL: {result.get('url', 'No links found.')}")

            if result.get("status") == "Submission failed":
                print(
                    f"Submission failed: HTTP "
                    f"{result.get('http_code', 'Unknown')}"
            )

            if result.get("status") == "Report found":

                print(f"Page Title: {result.get('page_title', 'Not found.')}")
                print(f"Final Destination: {result.get('final_url', 'Not found.')}")
                print(f"Domain created: {result.get('domain_created', 'Not found.')}")
                print(f"Domain registrar: {result.get('domain_registrar', 'Not found.')}")
                print(f"IP Address: {result.get('ip', 'Not found.')}")
                print(f"Country: {result.get('country', 'Not found.')}")

            else:
                print(result.get("message", result.get("error", "Report unavailable.")))

            print()

    else:
        print("No URLs found for analysis.")

    # URLHaus Analysis Results
    print("\n🐟 URLHAUS URL ANALYSIS:")

    if threat_intel_results["urlhaus_results"]:

        for result in threat_intel_results["urlhaus_results"]:

            print(f"URL: {result.get('url') or 'Not found'}")

            if result.get("url_status") == "Not found":
                print("No report found.")

            elif result.get("url_status") == "Error":
                print(f"Error: {result.get('error') or 'Analysis unavailable.'}")

            else:
                print(f"URL Status: {result.get('url_status') or 'Not found'}")

                print(f"Host: {result.get('host') or 'Not found'}")
                print(f"Date Added: {result.get('date_added') or 'Not found'}")
                print(f"Threat: {result.get('threat', 'Not found').replace('_', ' ')}")
                print(f"URLhaus Blocklist: {result.get('urlhaus_blocklist') or 'Not found'}")
                print(f"Spamhaus DBL: {result.get('spamhaus_dbl') or 'Not found'}")
                print(f"SURBL: {result.get('surbl') or 'Not found'}")

            print()

    else:
        print("No URLs found for analysis.")

    # MalwareBazaar Analysis Results
    print("\n🐟 MALWAREBAZAAR HASH ANALYSIS:")

    if threat_intel_results["malwarebazaar_results"]:

        for result in threat_intel_results["malwarebazaar_results"]:

            print(f"SHA-256: {result.get('hash') or 'Not found'}")

            if result.get("status") == "Not found":
                print("No report found.")

            elif result.get("status") == "Report found":

                print(f"File Name: {result.get('file_name') or 'Not found'}")
                print(f"File Type: {result.get('file_type') or 'Not found'}")
                print(f"File MIME Type: {result.get('file_type_mime') or 'Not found'}")
                print(f"File size: {result.get('file_size') or 'Not found'}")
                print(f"First Seen: {result.get('first_seen') or 'Not found'}")
                print(f"Last Seen: {result.get('last_seen') or 'Not found'}")

            elif result.get("status") == "Error":
                print(f"Error: {result.get('error') or 'Analysis unavailable.'}")
            print()

    else:
        print("No attachment hashes found for analysis.")

    # ----- AbuseIPDB (URLscan) IP Analysis Results -----

    print("\n🐟 ABUSEIPDB (URLSCAN) IP ANALYSIS:")

    if threat_intel_results["urlscan_ip_abuseipdb_results"]:

        for result in threat_intel_results["urlscan_ip_abuseipdb_results"]:

            print(f"Source URL: {result.get('source_url') or 'Not found'}")
            print(f"IP Address: {result.get('ip') or 'Not found'}")

            # Checks whether AbuseIPDB found a report
            if result.get("status") == "Report found":

                print(f"Abuse Confidence Score: {result.get('abuse_confidence_score') if result.get('abuse_confidence_score') is not None else 'Not found'}%")
                print(f"Total Reports: {result.get('total_reports') if result.get('total_reports') is not None else 'Not found'}")
                print(f"Country: {result.get('country_code') or 'Not found'}")
                print(f"ISP: {result.get('isp') or 'Not found'}")
                print(f"Whitelisted: {result.get('is_whitelisted') if result.get('is_whitelisted') is not None else 'Not found'}")

            # Handles missing API key or unavailable analysis
            else:
                print(f"Status: {result.get('status', 'Analysis unavailable')}")
                print(f"Error: {result.get('error', 'No additional information available.')}")

            print()

    else:
        print("No IP addresses found from URLscan for analysis.")
        print()

    # ----- VirusTotal (URLscan) IP Analysis Results -----

    print("\n🐟 VIRUSTOTAL (URLSCAN) IP ANALYSIS:")

    if threat_intel_results["urlscan_ip_vt_results"]:

        for result in threat_intel_results["urlscan_ip_vt_results"]:

            print(f"Source URL: {result.get('source_url') or 'Not found'}")
            print(f"IP Address: {result.get('ip') or 'Not found'}")

            # Displays VirusTotal detection results
            if result.get("status") == "Report found":

                print(f"Malicious: {result.get('malicious', 0)}")
                print(f"Suspicious: {result.get('suspicious', 0)}")
                print(f"Harmless: {result.get('harmless', 0)}")
                print(f"Undetected: {result.get('undetected', 0)}")

            # Handles missing reports or unavailable analysis
            else:
                print(f"Status: {result.get('status', 'Error')}")
                print(f"Error: {result.get('error', 'No additional information available.')}")

            print()

    else:
        print("No IP addresses found from URLscan for analysis.")
        print()

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

        # UPDATE: include header analysis info
        "header_analysis": header_analysis,

        "body_findings": body_findings,
        "attachment_findings": attachment_findings,
        "sender_findings": sender_findings,
        "links": email_urls,
        "remediation": remediation,
        "threat_intel_results": threat_intel_results,
    }

if __name__ == "__main__":
    import uvicorn
    # Starts your local server on http://127.0.0.1:8000
    uvicorn.run(app, host="127.0.0.1", port=8000)