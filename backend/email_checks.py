import base64
import html
import io
import re
import zipfile

from body_classifier import clean_body

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

FREE_MAIL = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com",
    "icloud.com", "proton.me", "protonmail.com", "mail.com", "gmx.com",
}


BUSINESS_WORDS = [
    "service", "services", "company", "support", "helpdesk", "official", "admin",
    "security", "billing", "payroll", "recruit", "hiring", "lawyer", "attorney",
    "bank", "invoice", "accounts",
]

MIN_BODY_CHARS = 20      
MANY_RECIPIENTS = 10
MAX_PDF_PAGES = 5
MAX_PDF_CHARS = 5000
MAX_DOCX_XML_BYTES = 5_000_000 
WORD_EXTENSIONS = (".docx", ".docm", ".dotm", ".doc")


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
                "data": part.get("body", {}).get("data"),
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


def _raw_bytes(attachment: dict) -> bytes:
    try:
        return base64.urlsafe_b64decode(attachment["data"] + "==")
    except Exception:
        return b""


def is_word(attachment: dict) -> bool:
    name = attachment["filename"].lower()
    return name.endswith(WORD_EXTENSIONS) or "wordprocessingml" in attachment["mime"] or attachment["mime"] == "application/msword"


def docx_text(attachment: dict) -> str:
    """Plain text from a .docx/.docm, or "" (old binary .doc files can't be read this way)."""
    if not is_word(attachment) or not attachment.get("data"):
        return ""
    raw = _raw_bytes(attachment)
    if not zipfile.is_zipfile(io.BytesIO(raw)):
        return ""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            info = archive.getinfo("word/document.xml")
            if info.file_size > MAX_DOCX_XML_BYTES:
                return ""
            xml = archive.read("word/document.xml").decode("utf-8", errors="replace")
        xml = re.sub(r"</w:p>|<w:br\s*/?>|<w:tab\s*/?>", " ", xml)
        text = html.unescape(re.sub(r"<[^>]+>", "", xml))
        return re.sub(r"\s+", " ", text).strip()[:MAX_PDF_CHARS]
    except Exception as error:
        print("Could not read Word text:", error)
        return ""


def has_macros(attachment: dict) -> bool:
    """True when a Word file carries macros"""
    if not is_word(attachment):
        return False
    name = attachment["filename"].lower()
    if name.endswith((".docm", ".dotm")):
        return True
    raw = _raw_bytes(attachment)
    if zipfile.is_zipfile(io.BytesIO(raw)):          # .docx: macros live in word/vbaProject.bin
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                return any(n.lower().endswith("vbaproject.bin") for n in archive.namelist())
        except Exception:
            return False
    return b"_VBA_PROJECT" in raw or b"VBA" in raw[:200000]   # old .doc files


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

    # A Word file with macros can run a hidden program when opened.
    for attachment in attachments:
        if has_macros(attachment):
            findings.append({
                "type": "Macro-Enabled Document",
                "description": f'"{attachment["filename"][:40]}" is a Word file that contains macros (small programs that can run when it is opened). Scam emails use these to install malware. Don\'t open it unless you were expecting it.',
                "severity": "Medium",
            })

    # Read the text inside PDFs and Word files and run the same wording and phrase checks on it.
    for attachment in attachments:
        text = pdf_text(attachment) or docx_text(attachment)
        if is_word(attachment):
            print(f'Word text read from "{attachment["filename"][:40]}": {len(text)} characters')
        if attachment["filename"].lower().endswith(".pdf") or attachment["mime"] == "application/pdf":
            if PdfReader is None:
                print("PDF check skipped: run 'uv add pypdf' to read PDF text.")
            else:
                print(f'PDF text read from "{attachment["filename"][:40]}": {len(text)} characters')
        if text:   # show exactly what was read, in the backend terminal only
            print(f'--- TEXT INSIDE "{attachment["filename"][:40]}" ---')
            print(text)
            print("--- END OF ATTACHMENT TEXT ---")
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