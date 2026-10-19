import base64
import io
import re

from body_classifier import clean_body

try:
    from pypdf import PdfReader
except ImportError:  # the checks still work, we just can't read PDF text
    PdfReader = None

FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "proton.me", "protonmail.com", "mail.com", "gmx.com",
}

# Words that make an address look like a business or an official team.
BUSINESS_WORDS = [
    "service", "services", "company", "support", "helpdesk", "official", "admin",
    "security", "billing", "payroll", "recruit", "hiring", "lawyer", "attorney",
    "bank", "invoice", "accounts",
]

MIN_BODY_CHARS = 20       # same cutoff body_classifier uses for "no readable text"
MANY_RECIPIENTS = 10      # visible To/Cc addresses; real mass mail normally uses Bcc
MAX_PDF_PAGES = 5
MAX_PDF_CHARS = 5000


def list_attachments(payload: dict) -> list[dict]:
    """Every named attachment in the Gmail payload: {filename, mime, data}."""
    found = []

    def walk(part):
        if not part:
            return
        filename = part.get("filename") or ""
        if filename:
            found.append({
                "filename": filename,
                "mime": part.get("mimeType", ""),
                "data": part.get("body", {}).get("data"),  # background.js fills this in
            })
        for child in part.get("parts", []) or []:
            walk(child)

    walk(payload)
    return found


def pdf_text(attachment: dict) -> str:
    """Plain text from a PDF attachment, or "" if it is not a readable PDF."""
    is_pdf = attachment["mime"] == "application/pdf" or attachment["filename"].lower().endswith(".pdf")
    if not is_pdf or not attachment.get("data") or PdfReader is None:
        return ""
    try:
        raw = base64.urlsafe_b64decode(attachment["data"] + "==")
        reader = PdfReader(io.BytesIO(raw))
        pages = [(p.extract_text() or "") for p in reader.pages[:MAX_PDF_PAGES]]
        return re.sub(r"\s+", " ", " ".join(pages)).strip()[:MAX_PDF_CHARS]
    except Exception as error:
        print("Could not read PDF text:", error)
        return ""


def recipient_count(header_map: dict) -> int:
    text = " ".join(header_map.get(h, "") for h in ("to", "cc"))
    return len(re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", text))


def sender_address(header_map: dict) -> str:
    match = re.search(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", header_map.get("from", ""))
    return match.group(0).lower() if match else ""


def analyze_attachments(payload: dict, decoded_body: str, body_analyzer) -> list[dict]:
    """
    Findings about attachments. Kept separate from the body findings.
    `body_analyzer` is the BodyAnalyzer from main.py (used to score text found inside PDFs).
    """
    findings = []
    attachments = list_attachments(payload)
    body_is_empty = len(clean_body(decoded_body or "")) < MIN_BODY_CHARS

    # The message only exists in an attachment (a common way to dodge text filters).
    if attachments and body_is_empty:
        names = ", ".join(f'"{a["filename"][:60]}"' for a in attachments[:3])
        findings.append({
            "type": "Message Only in Attachment",
            "description": f"The email has no message of its own, only an attachment ({names}). Scammers do this so email filters have no text to scan. Don't open it unless you were expecting it.",
            "severity": "Medium",
        })

    # Read the text inside PDFs and run the same wording and phrase checks on it.
    for attachment in attachments:
        text = pdf_text(attachment)
        if attachment["filename"].lower().endswith(".pdf") or attachment["mime"] == "application/pdf":
            if PdfReader is None:
                print("PDF check skipped: run 'uv add pypdf' to read PDF text.")
            else:
                print(f'PDF text read from "{attachment["filename"][:40]}": {len(text)} characters')
        if len(clean_body(text)) < MIN_BODY_CHARS:
            continue
        for finding in body_analyzer.analyze(text):
            if finding["type"] == "No Readable Text":
                continue
            finding = dict(finding)
            finding.pop("evidence", None)  # these phrases are in the PDF, not in the Gmail message
            finding["type"] = "Attachment Text: " + finding["type"]
            finding["description"] = f'Inside "{attachment["filename"][:40]}": ' + finding["description"]
            findings.append(finding)

    return findings


def analyze_sender_and_recipients(header_map: dict) -> list[dict]:
    """Findings from the From / To / Cc headers. Kept separate from the body findings."""
    findings = []

    count = recipient_count(header_map)
    if count >= MANY_RECIPIENTS:
        findings.append({
            "type": "Many Recipients",
            "description": f"This was sent to {count} visible addresses at once. Mass mailings like this are common for scams.",
            "severity": "Low",
        })

    address = sender_address(header_map)
    domain = address.split("@")[-1] if address else ""
    local = address.split("@")[0] if address else ""
    if domain in FREE_MAIL and any(w in local for w in BUSINESS_WORDS):
        findings.append({
            "type": "Business Name on Free Email",
            "description": f'The sender looks like a business ("{address}") but uses a free {domain} account. Real organizations usually send from their own domain.',
            "severity": "Low",
        })

    return findings