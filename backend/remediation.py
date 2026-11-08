import hashlib
import json
import re
 
import httpx
 
from config import GEMINI_API_KEY
 
# ===== AREA: SETTINGS =====
AI_ENABLED = True           # False = playbook only, no API calls
INCLUDE_PHRASES = False     # True would also include short trigger phrases (redacted)
MAX_ACTIONS = 4
MAX_WHY_CHARS = 300
CALL_AI_ONLY_FOR = {"medium", "high"}
AI_MODEL = "gemini-3.5-flash-lite"
AI_TEMPERATURE = 0.2
AI_MAX_TOKENS = 600         # headroom in case the model spends some on thinking
AI_TIMEOUT = 15
 
# ===== AREA: FINDING CODES =====
# finding "type" -> (category, short code)
FINDING_CODES = {
    "Message Wording": ("body", "wording"),
    "Urgency Language": ("body", "urgency"),
    "Generic Greeting": ("body", "greeting"),
    "Sensitive Info Request": ("body", "sensitive"),
    "Message Only in Attachment": ("attachment", "attach_only"),
    "Many Recipients": ("sender", "many_recipients"),
    "Business Name on Free Email": ("sender", "freemail_business"),
}
IGNORED_TYPES = {"No Readable Text"}
SEVERITY_CODE = {"High": "H", "Medium": "M", "Low": "L"}
# Link and file reputation results are coded in summarize_intel() below.
 
# ===== AREA: PLAYBOOK =====
# Framework-based steps, in priority order. TODO: verify each source section.
SOURCES = {
    "nist800-61": "NIST SP 800-61 (Computer Security Incident Handling Guide)",
    "nist-csf": "NIST Cybersecurity Framework 2.0 (Respond / Recover)",
    "cisa": "CISA phishing guidance",
}
 
PLAYBOOK = {
    "report": {
        "triggers": {"*"},   # "*" = always included
        "text": "{avoid} Report the email to your IT contact or security team, then delete it.",
        "source": "cisa",
    },
    "file_bad": {
        "triggers": {"file_bad"},
        "text": "A file in this email is flagged as dangerous. Don't open it. If you already did, disconnect from the network, run a security scan, and tell IT immediately.",
        "source": "nist800-61",
    },
    "link_bad": {
        "triggers": {"link_bad"},
        "text": "A link in this email is flagged as dangerous. Don't open it. If you already did, don't enter anything on that page, and tell IT.",
        "source": "cisa",
    },
    "credentials": {
        "triggers": {"sensitive", "urgency"},
        "text": "Never enter a password or personal details because an email asks. Go to the real website by typing the address yourself.",
        "source": "cisa",
    },
    "attachment": {
        "triggers": {"attach_only"},
        "text": "Don't open an attachment you weren't expecting, especially when the email has no message. Confirm with the sender using a phone number or address you already know.",
        "source": "cisa",
    },
    "if_acted": {
        "triggers": {"sensitive", "urgency", "attach_only", "auth_fail", "link_bad", "file_bad"},
        "text": "If you already {acted}: change any affected password now, turn on multi-factor authentication, and tell IT right away.",
        "source": "nist800-61",
    },
    "sender": {
        "triggers": {"freemail_business", "many_recipients", "auth_fail", "reply_to_mismatch"},
        "text": "Check the sender's address closely. Real organizations send from their own domain, not a free email account.",
        "source": "cisa",
    },
    "verify_out_of_band": {
        "triggers": {"urgency", "sensitive", "attach_only", "freemail_business"},
        "text": "If it claims to be from someone you know or a company you use, contact them through a separate, trusted channel to confirm.",
        "source": "nist-csf",
    },
}
 
# ===== AREA: REDACTION =====
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URL = re.compile(r"https?://([^\s/<>\"')]+)[^\s<>\"')]*", re.IGNORECASE)
_PHONE = re.compile(r"(?<!\d)(?:\+?\d{1,2}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\d)")
 
 
def redact(text: str) -> str:
    """Remove emails, phone numbers, and link paths (keeps only the link's domain)."""
    text = _EMAIL.sub("[EMAIL]", text or "")
    text = _URL.sub(lambda m: "[LINK:" + m.group(1).lower() + "]", text)
    text = _PHONE.sub("[PHONE]", text)
    return text[:80]
# AREA: REDACTION (reserved) - names, and keyed hashes (HMAC) if senders must be told apart
 
 
# ===== AREA: PAYLOAD (the only thing the AI will see) =====
def parse_auth(auth_results: list[str]) -> dict:
    """SPF / DKIM / DMARC status across all Authentication-Results headers (any pass wins)."""
    status = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for header in auth_results or []:
        for mech, result in re.findall(r"\b(spf|dkim|dmarc)=(\w+)", header, re.IGNORECASE):
            mech, result = mech.lower(), result.lower()
            if result == "pass":
                status[mech] = "pass"
            elif status[mech] != "pass" and result in {"fail", "softfail", "permerror"}:
                status[mech] = "fail"
    return status
 
 
def sender_domain(from_header: str) -> str:
    match = _EMAIL.search(from_header or "")
    return match.group(0).split("@")[-1].lower() if match else ""
 
 
_LEVEL = {0: None, 2: "M", 3: "H"}
 
 
def _num(value) -> float:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else 0
 
 
def summarize_intel(results) -> dict:
    """
    Turns VirusTotal / IPQS / URLhaus / MalwareBazaar results into severities.
    Returns {"link": 0|2|3, "file": 0|2|3, "link_ok": bool, "file_ok": bool}.
    Only severities leave this function, never the URLs or hashes.
    """
    out = {"link": 0, "file": 0, "link_ok": False, "file_ok": False}
    results = results or {}
 
    for r in results.get("url_results", []):                      # VirusTotal (links)
        if r.get("status") in ("Report found", "No report found"):
            out["link_ok"] = True
        if r.get("status") == "Report found":
            bad, odd = _num(r.get("malicious")), _num(r.get("suspicious"))
            out["link"] = max(out["link"], 3 if bad >= 3 else 2 if (bad >= 1 or odd >= 2) else 0)
 
    for r in results.get("ipqs_results", []):                     # IPQualityScore (links)
        if r.get("status") == "Report found":
            out["link_ok"] = True
            if r.get("phishing") is True or r.get("malware") is True:
                out["link"] = 3
            elif r.get("suspicious") is True or _num(r.get("risk_score")) >= 75:
                out["link"] = max(out["link"], 2)
 
    for r in results.get("urlhaus_results", []):                  # URLhaus (links)
        status = r.get("url_status")
        if status == "Not found":
            out["link_ok"] = True
        elif status not in (None, "Error"):                       # listed = known bad URL
            out["link_ok"] = True
            out["link"] = max(out["link"], 3 if status == "online" else 2)
 
    for r in results.get("file_hash_results", []):                # VirusTotal (files)
        if r.get("status") in ("Report found", "No report found"):
            out["file_ok"] = True
        if r.get("status") == "Report found":
            bad = _num(r.get("malicious"))
            out["file"] = max(out["file"], 3 if bad >= 3 else 2 if bad >= 1 else 0)
 
    for r in results.get("malwarebazaar_results", []):            # MalwareBazaar (files)
        if r.get("status") == "Report found":
            out["file_ok"], out["file"] = True, 3
        elif r.get("status") == "Not found":
            out["file_ok"] = True
    return out
 
 
def build_payload(body_findings, attachment_findings, sender_findings,
                  auth_results=None, from_header="", url_count=0, attachment_kinds=None,
                  reply_to="", intel=None) -> dict:
    """Compact summary: codes and severities only. No subject, body, names, or addresses."""
    findings = []
    for finding in list(body_findings or []) + list(attachment_findings or []) + list(sender_findings or []):
        ftype = finding.get("type", "")
        severity = SEVERITY_CODE.get(finding.get("severity"), "L")
        if ftype in IGNORED_TYPES:
            continue
        if ftype.startswith("Attachment Text: "):      # scam wording found inside a PDF
            inner = FINDING_CODES.get(ftype[len("Attachment Text: "):])
            if inner:
                findings.append(["attachment", "pdf_" + inner[1], severity])
            continue
        code = FINDING_CODES.get(ftype)
        if not code:
            continue
        entry = [code[0], code[1], severity]
        if INCLUDE_PHRASES and finding.get("evidence"):
            entry.append([redact(e.get("phrase", "")) for e in finding["evidence"][:3]])
        findings.append(entry)
 
    auth = parse_auth(auth_results)
    payload = {
        "auth": auth,
        "domain": sender_domain(from_header),
        "f": findings,
        "urls": url_count,
        "attach": sorted(set(attachment_kinds or [])),
    }
 
    # Reputation lookups: coded severities, plus whether the lookups actually ran.
    summary = summarize_intel(intel)
    for category, key in (("links", "link"), ("files", "file")):
        if _LEVEL[summary[key]]:
            payload["f"].append([category, key + "_bad", _LEVEL[summary[key]]])
    payload["intel"] = {
        "links": ("checked" if summary["link_ok"] else "unavailable") if url_count else "none",
        "files": ("checked" if summary["file_ok"] else "unavailable") if attachment_kinds else "none",
    }
 
    # Replies going to a different domain than the sender is a weak header warning sign.
    from_domain, reply_domain = sender_domain(from_header), sender_domain(reply_to)
    if from_domain and reply_domain and reply_domain != from_domain \
            and not reply_domain.endswith("." + from_domain) and not from_domain.endswith("." + reply_domain):
        payload["f"].append(["headers", "reply_to_mismatch", "L"])
    # DKIM alone is weak (mailing lists and forwarding break it), so it stays Low.
    if auth["dmarc"] == "fail" and auth["spf"] == "fail":
        payload["f"].append(["headers", "auth_fail", "H"])
    elif auth["dmarc"] == "fail" or auth["spf"] == "fail":
        payload["f"].append(["headers", "auth_fail", "M"])
    elif auth["dkim"] == "fail":
        payload["f"].append(["headers", "auth_fail", "L"])
 
    return payload
 
 
def payload_key(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
 
 
# ===== AREA: RISK LEVEL (rule-based) =====
def rule_level(payload: dict) -> str:
    findings = payload["f"]
    if not findings:
        return "none"
    if any(f[0] in {"links", "files"} and f[2] == "H" for f in findings):
        return "high"                                         # known-bad link or file
    strong = [f for f in findings if f[2] in {"H", "M"}]     # a lone wording score is weak
    has_high = any(f[2] == "H" for f in strong)
    if len(strong) >= 3 or (has_high and len(strong) >= 2):
        return "high"
    if strong:
        return "medium"
    return "low"
 
 
def _join(items: list[str]) -> str:
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + (", or " if len(items) > 2 else " or ") + items[-1]
 
 
def _wording(payload: dict) -> dict:
    """Only mention links or attachments when the email actually has them."""
    has_links, has_files = payload["urls"] > 0, bool(payload["attach"])
    if has_links and has_files:
        avoid = "Don't click links or open attachments."
    elif has_links:
        avoid = "Don't click any links in it."
    elif has_files:
        avoid = "Don't open the attachment."
    else:
        avoid = "Don't reply or share any information."
    acted = (["clicked a link"] if has_links else []) + (["opened the attachment"] if has_files else [])
    acted.append("typed in a password or personal details")
    return {"avoid": avoid, "acted": _join(acted)}
 
 
def select_playbook(payload: dict) -> list[dict]:
    codes = {f[1].replace("pdf_", "") for f in payload["f"]}
    words = _wording(payload)
    return [
        {"id": key, "text": entry["text"].format(**words), "source": SOURCES[entry["source"]]}
        for key, entry in PLAYBOOK.items()
        if "*" in entry["triggers"] or entry["triggers"] & codes
    ]
 
 
# ===== AREA: AI API (Gemini) =====
# Sends ONLY the coded payload + matched steps. Expects JSON back:
#   {"verdict": "likely_phishing|suspicious|likely_safe", "why": "...", "actions": ["..."]}
SYSTEM_PROMPT = (
    "You help non-technical staff respond to a suspicious email. "
    "You only get a coded summary of automated checks, never the email itself. "
    "Finding format: [category, code, severity H/M/L]. Categories: body = wording, attachment, sender, "
    "headers = authentication/reply-to, links = link reputation, files = file reputation. "
    "'level' is the rule-based risk level; do not rate it lower. "
    "'intel' says whether link/file reputation lookups ran; 'unavailable' means they could not run, so never call links or files safe. "
    "Weigh all categories together; a flagged link or file matters most. "
    "Use ONLY the provided steps; reword them simply. Mention links or attachments only if urls > 0 or attach is non-empty. Reply with JSON only: "
    '{"verdict":"likely_phishing|suspicious|likely_safe","why":"max 2 sentences naming the strongest signals in plain words","actions":["max 3 short steps"]}'
)
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
 
 
def build_user_prompt(payload: dict, steps: list[dict], level: str) -> str:
    return json.dumps({"level": level, "summary": payload, "steps": [s["text"] for s in steps]},
                      separators=(",", ":"))
 
 
def ask_ai(payload: dict, steps: list[dict], level: str):
    """Return the AI's parsed JSON. Raises on any problem (the caller falls back to the playbook)."""
    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set")
 
    body = {
        "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
        "contents": [{"role": "user", "parts": [{"text": build_user_prompt(payload, steps, level)}]}],
        "generationConfig": {
            "temperature": AI_TEMPERATURE,
            "maxOutputTokens": AI_MAX_TOKENS,
            "responseMimeType": "application/json",
        },
    }
    response = httpx.post(
        GEMINI_URL.format(model=AI_MODEL),
        headers={"x-goog-api-key": GEMINI_API_KEY},
        json=body,
        timeout=AI_TIMEOUT,
    )
    response.raise_for_status()
 
    parts = response.json()["candidates"][0]["content"]["parts"]
    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
    return json.loads(text)
 
 
# ===== AREA: VALIDATION =====
ALLOWED_VERDICTS = {"likely_phishing", "suspicious", "likely_safe"}
 
 
def validate_ai_output(data):
    if not isinstance(data, dict) or data.get("verdict") not in ALLOWED_VERDICTS:
        return None
    why, actions = data.get("why"), data.get("actions")
    if not isinstance(why, str) or not isinstance(actions, list):
        return None
    actions = [a.strip() for a in actions if isinstance(a, str) and a.strip()][:MAX_ACTIONS]
    if not actions:
        return None
    return {"verdict": data["verdict"], "why": why.strip()[:MAX_WHY_CHARS], "actions": actions}
 
 
# ===== AREA: CACHE =====
_cache: dict[str, dict] = {}     # same findings -> same advice, no repeat API calls
# AREA: CACHE (reserved) - save to disk so it survives restarts
 
LEVEL_TO_VERDICT = {"none": "likely_safe", "low": "likely_safe", "medium": "suspicious", "high": "likely_phishing"}
 
 
# ===== AREA: MAIN ENTRY POINT (main.py calls this) =====
def get_remediation(payload: dict) -> dict:
    """
    Returns {"risk_level", "verdict", "source", "why", "actions", "references"}.
    risk_level is always rule-based. The advice comes from the AI when it is on and valid,
    otherwise from the playbook.
    """
    level = rule_level(payload)
    note = " Link or file reputation checks could not run." if "unavailable" in payload.get("intel", {}).values() else ""
 
    if level == "none":
        return {"risk_level": level, "verdict": "likely_safe", "source": "rules",
                "why": "No warning signs were found." + note, "actions": [], "references": []}
    if level == "low":
        return {"risk_level": level, "verdict": "likely_safe", "source": "rules",
                "why": "Only minor warning signs were found." + note,
                "actions": ["Check the sender and links before clicking anything."], "references": []}
 
    key = payload_key(payload)
    if key in _cache:
        return _cache[key]
 
    steps = select_playbook(payload)
    references = sorted({s["source"] for s in steps})
 
    ai_result = None
    if AI_ENABLED and level in CALL_AI_ONLY_FOR:
        try:
            ai_result = validate_ai_output(ask_ai(payload, steps, level))
        except Exception as error:               # any API problem -> use the playbook
            print("AI remediation unavailable:", type(error).__name__, str(error)[:120])
        if ai_result and level == "high" and ai_result["verdict"] == "likely_safe":
            ai_result = None                     # never let the AI downgrade a high rule-based risk
 
    if ai_result:
        result = {"risk_level": level, "source": "ai", "references": references, **ai_result}
    else:
        result = {
            "risk_level": level,
            "verdict": LEVEL_TO_VERDICT[level],
            "source": "playbook",
            "why": f"{len(payload['f'])} warning sign(s) were found, risk level {level}.",
            "actions": [s["text"] for s in steps][:MAX_ACTIONS],
            "references": references,
        }
    _cache[key] = result
    return result
 
 
if __name__ == "__main__":
    samples = {
        "PayPal-style phish": build_payload(
            [{"type": "Message Wording", "severity": "High"}, {"type": "Urgency Language", "severity": "Medium"},
             {"type": "Generic Greeting", "severity": "Low"}, {"type": "Sensitive Info Request", "severity": "High"}],
            [], [], ["dkim=pass; spf=pass; dmarc=pass"], "PayPal <help@paypa1-support.com>", 1),
        "Attachment-only scam": build_payload(
            [{"type": "No Readable Text", "severity": "Low"}],
            [{"type": "Message Only in Attachment", "severity": "Medium"}],
            [{"type": "Many Recipients", "severity": "Low"}, {"type": "Business Name on Free Email", "severity": "Low"}],
            ["dkim=pass; spf=pass; dmarc=pass"], "Micheal clark <lawyerservicescompany123@gmail.com>", 0, ["application/pdf"]),
        "Campus mailing list (dkim fail only)": build_payload(
            [], [], [], ["dkim=fail; spf=pass; dmarc=pass"], "Linh Le <lle1@pacific.edu>", 2),
        "Automated newsletter": build_payload(
            [{"type": "Message Wording", "severity": "Low"}], [], [], ["dkim=pass; spf=pass; dmarc=pass"],
            "Canva <marketing@engage.canva.com>", 18),
        "Clean email": build_payload([], [], [], ["dkim=pass; spf=pass; dmarc=pass"], "Husna <a@pacific.edu>", 0),
    }
    for name, payload in samples.items():
        result = get_remediation(payload)
        print(f"\n== {name}")
        print("payload:", json.dumps(payload, separators=(",", ":")))
        print(f"risk: {result['risk_level']} | verdict: {result['verdict']} | source: {result['source']}")
        for action in result["actions"]:
            print("  -", action)
 