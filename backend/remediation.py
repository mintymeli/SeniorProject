import hashlib
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
 
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
NEW_DOMAIN_DAYS = 30        # a site younger than this is a warning sign
 
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
        "text": "{avoid} {report} If coworkers may have gotten it too, warn them.",
        "source": "cisa",
    },
    "file_bad": {
        "triggers": {"file_bad"},
        "text": "Our security checks say a file in this email is dangerous. Don't open it. If you already did, turn off the computer's Wi-Fi or unplug its internet cable, run your virus protection program, and change your important passwords from a different phone or computer.",
        "source": "nist800-61",
    },
    "link_bad": {
        "triggers": {"link_bad"},
        "text": "Our security checks say a link in this email is dangerous. Don't open it. If you already did, close the page, and if you typed anything in, change that password right away.",
        "source": "cisa",
    },
    "link_risky": {
        "triggers": {"link_risky"},
        "text": "One of the links in this email looks risky to our security checks. Don't open it unless you know and trust the sender.",
        "source": "cisa",
    },
    "file_risky": {
        "triggers": {"file_risky"},
        "text": "A file in this email looks risky to our security checks. Don't open it unless you were expecting it from someone you trust.",
        "source": "cisa",
    },
    "link_new": {
        "triggers": {"link_new"},
        "text": "A link in this email goes to a website that was only created recently, which is common in scams. Don't open it unless you know and trust the sender.",
        "source": "cisa",
    },
    "credentials": {
        "triggers": {"sensitive", "urgency"},
        "text": "Never type a password or personal details because an email asks you to. Go to the real website by typing its address yourself.",
        "source": "cisa",
    },
    "attachment": {
        "triggers": {"attach_only"},
        "text": "Don't open an attachment you weren't expecting, especially when the email has no message. Confirm with the sender using a phone number or address you already know.",
        "source": "cisa",
    },
    "if_acted": {
        "triggers": {"sensitive", "urgency", "attach_only", "auth_fail", "link_bad", "link_risky", "link_new", "file_bad", "file_risky"},
        "text": "If you already {acted}: change the password for any account affected right now, turn on 2-Step Verification (a code sent to your phone when you sign in), and look for sign-ins you don't recognize. If you shared payment details, call your bank or card company.",
        "source": "nist800-61",
    },
    "sender": {
        "triggers": {"freemail_business", "many_recipients", "auth_fail", "reply_to_mismatch"},
        "text": "Check the sender's email address closely. Real companies send from their own address (like name@company.com), not a free Gmail or Yahoo address.",
        "source": "cisa",
    },
    "verify_out_of_band": {
        "triggers": {"urgency", "sensitive", "attach_only", "freemail_business"},
        "text": "If it says it's from someone you know or a company you use, call or message them using contact details you already have, not ones from the email, to check.",
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
 
 
_SECOND_LEVEL = {"co", "com", "org", "net", "edu", "gov", "ac"}


def registered_domain(host: str) -> str:
    """my.pacific.edu -> pacific.edu (handles names like example.co.uk)."""
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


_UNIT_DAYS = {"year": 365, "month": 30, "week": 7, "day": 1, "hour": 0, "minute": 0}


def _age_from_text(text):
    """'18 years ago' -> 6570 days. None when it can't be read."""
    match = re.search(r"(\d+)\s*(year|month|week|day|hour|minute)", str(text or ""), re.IGNORECASE)
    return int(match.group(1)) * _UNIT_DAYS[match.group(2).lower()] if match else None


def _age_from_date(text):
    """'2025-09-01' -> days since then. None when there is no date."""
    match = re.search(r"(\d{4})-(\d{2})-(\d{2})", str(text or ""))
    if not match:
        return None
    try:
        created = datetime(*map(int, match.groups()))
    except ValueError:
        return None
    return (datetime.now(timezone.utc).replace(tzinfo=None) - created).days


def _is_own_site(domain, own: str) -> bool:
    """True when a link goes to the sender's own organization (instructure.com mail linking to pacific.instructure.com)."""
    return bool(own) and isinstance(domain, str) and registered_domain(domain) == own


def summarize_intel(results, sender: str = "") -> dict:
    """
    Turns VirusTotal / IPQS / URLscan / URLhaus / MalwareBazaar results into severities and a few facts.
    Returns {"link": 0|2|3, "file": 0|2|3, "link_ok": bool, "file_ok": bool,
             "link_clean": bool, "link_new": bool, "same_org": True|False|None}.
    Only these codes leave this function, never the URLs or hashes.
    """
    out = {"link": 0, "file": 0, "link_ok": False, "file_ok": False,
           "link_clean": False, "link_new": False, "same_org": None}
    results = results or {}
    ages, hosts = [], set()
    ipqs_total = ipqs_clean = 0
    own = registered_domain(sender)

    for r in results.get("url_results", []):                      # VirusTotal (links)
        if r.get("status") in ("Report found", "No report found"):
            out["link_ok"] = True
        if r.get("status") == "Report found":
            bad, odd = _num(r.get("malicious")), _num(r.get("suspicious"))
            out["link"] = max(out["link"], 3 if bad >= 3 else 2 if (bad >= 1 or odd >= 2) else 0)

    for r in results.get("ipqs_results", []):                     # IPQualityScore (links)
        ipqs_total += 1
        if r.get("status") == "Report found":
            out["link_ok"] = True
            if r.get("phishing") is True or r.get("malware") is True:
                out["link"] = 3
            elif (r.get("suspicious") is True or _num(r.get("risk_score")) >= 75) \
                    and not _is_own_site(r.get("domain"), own):
                out["link"] = max(out["link"], 2)
            age = _age_from_text(r.get("domain_age"))
            if age is not None:
                ages.append(age)
            domain = r.get("domain")
            if isinstance(domain, str) and domain not in ("", "Not found"):
                hosts.add(domain.lower())
            risk = r.get("risk_score")
            if (r.get("safe") is True and r.get("suspicious") is not True and r.get("malware") is not True
                    and r.get("phishing") is not True and isinstance(risk, (int, float)) and risk <= 25):
                ipqs_clean += 1

    for r in results.get("urlscan_results", []):                  # URLscan (where the link really goes)
        if r.get("status") == "Report found":
            host = urlparse(r.get("final_url") or "").hostname
            if host:
                hosts.add(host.lower())
            age = _age_from_date(r.get("domain_created"))
            if age is not None:
                ages.append(age)

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

    out["link_new"] = any(age < NEW_DOMAIN_DAYS for age in ages)
    # "clean" needs a positive all-clear for every link, not just a lack of reports
    out["link_clean"] = ipqs_total > 0 and ipqs_clean == ipqs_total and out["link"] == 0 and not out["link_new"]
    if own and hosts:
        out["same_org"] = all(registered_domain(h) == own for h in hosts)
    return out


def flagged_links(results, from_header: str = "") -> list[dict]:
    """
    Which links the reputation checks flagged, and why, so the extension can highlight them in the email.
    Returns [{"url", "severity": "high" | "medium", "reasons": [...]}]. Links that look fine are left out.
    """
    found: dict[str, dict] = {}
    own = registered_domain(sender_domain(from_header))

    def add(url, severity, reason):
        if not isinstance(url, str) or not url:
            return
        entry = found.setdefault(url, {"url": url, "severity": "medium", "reasons": []})
        if severity == "high":
            entry["severity"] = "high"
        if reason not in entry["reasons"]:
            entry["reasons"].append(reason)

    results = results or {}
    for r in results.get("url_results", []):                      # VirusTotal
        if r.get("status") == "Report found":
            bad, odd = _num(r.get("malicious")), _num(r.get("suspicious"))
            if bad >= 3:
                add(r.get("url"), "high", f"VirusTotal: {int(bad)} security engines flagged this link")
            elif bad >= 1 or odd >= 2:
                add(r.get("url"), "medium", f"VirusTotal: {int(bad + odd)} security engines flagged this link as risky")

    for r in results.get("ipqs_results", []):                     # IPQualityScore
        if r.get("status") != "Report found":
            continue
        if r.get("phishing") is True or r.get("malware") is True:
            add(r.get("url"), "high", "IPQualityScore flagged it as phishing or malware")
        elif (r.get("suspicious") is True or _num(r.get("risk_score")) >= 75) \
                and not _is_own_site(r.get("domain"), own):
            add(r.get("url"), "medium", "IPQualityScore rated it risky")
        age = _age_from_text(r.get("domain_age"))
        if age is not None and age < NEW_DOMAIN_DAYS:
            add(r.get("url"), "medium", "The website was created very recently")

    for r in results.get("urlhaus_results", []):                  # URLhaus
        status = r.get("url_status")
        if status not in (None, "Error", "Not found"):
            add(r.get("url"), "high" if status == "online" else "medium", "Listed in the URLhaus malware database")

    for r in results.get("urlscan_results", []):                  # URLscan
        if r.get("status") == "Report found":
            age = _age_from_date(r.get("domain_created"))
            if age is not None and age < NEW_DOMAIN_DAYS:
                add(r.get("url"), "medium", "The website was created very recently")

    return list(found.values())


def build_payload(body_findings, attachment_findings, sender_findings,
                  auth_results=None, from_header="", url_count=0, attachment_kinds=None,
                  reply_to="", intel=None, in_spam=False) -> dict:
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
 
    if in_spam:                                              # Gmail already filed it as spam
        findings.append(["gmail", "in_spam", "M"])
    auth = parse_auth(auth_results)
    payload = {
        "auth": auth,
        "domain": sender_domain(from_header),
        "f": findings,
        "urls": url_count,
        "attach": sorted(set(attachment_kinds or [])),
    }
 
    # Reputation lookups: coded severities, plus whether the lookups actually ran.
    summary = summarize_intel(intel, sender_domain(from_header))
    for category, key in (("links", "link"), ("files", "file")):
        if _LEVEL[summary[key]]:
            code = key + ("_bad" if summary[key] == 3 else "_risky")
            payload["f"].append([category, code, _LEVEL[summary[key]]])
    if summary["link_new"] and not summary["link"]:
        payload["f"].append(["links", "link_new", "M"])           # site created very recently
    if url_count and summary["same_org"] is not None:
        payload["dest"] = "same_org" if summary["same_org"] else "other"
    payload["intel"] = {
        "links": ("clean" if summary["link_clean"] else "checked" if summary["link_ok"] else "unavailable") if url_count else "none",
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
def _is_spam(payload: dict) -> bool:
    return any(f[1] == "in_spam" for f in payload["f"])


def reassured(payload: dict) -> bool:
    """Wording is the only strong warning sign, and every link checked clean and leads to the sender's own organization."""
    strong = [f for f in payload["f"] if f[2] in {"H", "M"} and f[1] != "in_spam"]
    return (bool(strong) and all(f[0] == "body" for f in strong)
            and payload.get("intel", {}).get("links") == "clean"
            and payload.get("dest") == "same_org"
            and payload["auth"]["dmarc"] == "pass")


def rule_level(payload: dict) -> str:
    level = _content_level(payload)
    # Gmail already put it in spam: never lower than medium, but it doesn't stack with other signals.
    if _is_spam(payload) and level in {"none", "low"}:
        return "medium"
    return level


def _content_level(payload: dict) -> str:
    findings = [f for f in payload["f"] if f[1] != "in_spam"]
    if not findings:
        return "none"
    if any(f[0] in {"links", "files"} and f[2] == "H" for f in findings):
        return "high"                                         # known-bad link or file
    strong = [f for f in findings if f[2] in {"H", "M"}]     # a lone wording score is weak
    if not strong:
        return "low"
    has_high = any(f[2] == "H" for f in strong)
    level = "high" if len(strong) >= 3 or (has_high and len(strong) >= 2) else "medium"
    # Wording alone is the weakest evidence. If the links checked clean, lower the risk.
    if all(f[0] == "body" for f in strong) and payload.get("intel", {}).get("links") == "clean":
        if reassured(payload):
            return "low"
        return "medium" if level == "high" else level
    return level


def _join(items: list[str]) -> str:
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + (", or " if len(items) > 2 else " or ") + items[-1]
 
 
def _wording(payload: dict) -> dict:
    """Only mention links or attachments when the email actually has them."""
    has_links, has_files = payload["urls"] > 0, bool(payload["attach"])
    if has_links and has_files:
        avoid = "Don't click links or open attachments."
    elif has_links and payload.get("intel", {}).get("links") == "clean":
        avoid = "Our security check didn't find anything wrong with the links, but Gmail still sent this to spam. Only open them if you were expecting this email from this sender."
    elif has_links:
        avoid = "Don't click any links in it."
    elif has_files:
        avoid = "Don't open the attachment."
    else:
        avoid = "Don't reply or share any information."
    acted = (["clicked a link"] if has_links else []) + (["opened the attachment"] if has_files else [])
    acted.append("typed in a password or personal details")
    if any(f[1] == "in_spam" for f in payload["f"]):
        report = "Gmail already moved it to your spam folder, so leave it there or choose Delete forever."
    else:
        report = "In Gmail, click the Report spam button (the circle with an exclamation mark) above the email. This flags it as a scam and removes it from your inbox."
    return {"avoid": avoid, "acted": _join(acted), "report": report}
 
 
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
    "The reader is one person at a small business with no IT team or security staff, so they handle this themselves. "
    "Never tell them to contact IT, a security team, an administrator, or a help desk; give steps they can do on their own. "
    "Write in plain everyday words for someone with no technical background. Avoid jargon, or explain it in a few words in parentheses. "
    "Finding format: [category, code, severity H/M/L]. Categories: body = wording, attachment, sender, "
    "headers = authentication/reply-to, links = link reputation, files = file reputation, gmail = Gmail already filed it in spam. "
    "'level' is the rule-based risk level; do not rate it lower. "
    "'intel' says whether link/file reputation lookups ran; 'unavailable' means they could not run, so never call links or files safe. "
    "'intel' links = clean means the link reputation checks found nothing wrong; 'dest' = same_org means the links lead to the sender's own organization. Weigh that against wording-only warnings. "
    "If 'intel' links = clean, never tell them not to click the links at all; say our security check found nothing wrong with the links, but because Gmail put it in spam they should open them only if they were expecting this email from this sender. Do not use the word 'clean'. "
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
_NEEDS_IT_TEAM = re.compile(r"\bIT\b|(?i:security team|security department|administrator|help ?desk)")


def _mentions_it_team(text: str) -> bool:
    """Small businesses may have no IT staff, so advice that points to one is rejected."""
    return bool(_NEEDS_IT_TEAM.search(text))
 
 
def validate_ai_output(data):
    if not isinstance(data, dict) or data.get("verdict") not in ALLOWED_VERDICTS:
        return None
    why, actions = data.get("why"), data.get("actions")
    if not isinstance(why, str) or not isinstance(actions, list):
        return None
    actions = [a.strip() for a in actions if isinstance(a, str) and a.strip()][:MAX_ACTIONS]
    if not actions:
        return None
    if any(_mentions_it_team(t) for t in [why] + actions):
        return None                              # fall back to the playbook
    return {"verdict": data["verdict"], "why": why.strip()[:MAX_WHY_CHARS], "actions": actions}
 
 
# ===== AREA: CACHE =====
_cache: dict[str, dict] = {}     # same findings -> same advice, no repeat API calls
# AREA: CACHE (reserved) - save to disk so it survives restarts
 
SIGN_TEXT = {                       # finding code -> plain words
    "wording": "the wording resembles scam emails",
    "urgency": "it pressures you to act quickly",
    "greeting": "it uses a generic greeting",
    "sensitive": "it mentions sensitive information",
    "attach_only": "the message is only in an attachment",
    "many_recipients": "it was sent to many people at once",
    "freemail_business": "a business name is used on a free email account",
    "in_spam": "Gmail already filed it as spam",
    "reply_to_mismatch": "replies go to a different address than the sender",
    "auth_fail": "the sender didn't pass email security checks",
    "link_bad": "a link was flagged as dangerous",
    "link_risky": "a link looks risky",
    "link_new": "a link goes to a very new website",
    "file_bad": "a file was flagged as dangerous",
    "file_risky": "a file looks risky",
}


def describe_signs(payload: dict) -> str:
    """'Gmail already filed it as spam, and the wording resembles scam emails.' (strongest signs first)"""
    order = {"H": 0, "M": 1, "L": 2}
    phrases = []
    for _, code, severity in sorted(payload["f"], key=lambda f: order.get(f[2], 3)):
        text = SIGN_TEXT.get(code) or ("text inside an attachment looks like a scam" if code.startswith("pdf_") else "")
        if text and text not in phrases:
            phrases.append(text)
    if not phrases:
        return "Some warning signs were found."
    top = phrases[:3]
    text = top[0] if len(top) == 1 else ", ".join(top[:-1]) + (", and " if len(top) > 2 else " and ") + top[-1]
    return text[0].upper() + text[1:] + "."


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
    if level == "low" and reassured(payload):
        return {"risk_level": level, "verdict": "likely_safe", "source": "rules",
                "why": "The wording looks like a scam email, but the sender passed security checks and every link goes to the sender's own organization and checked out clean.",
                "actions": ["If you weren't expecting this email, check with the sender before clicking anything."],
                "references": []}
    if level == "low":
        return {"risk_level": level, "verdict": "likely_safe", "source": "rules",
                "why": "Only minor warning signs were found." + note,
                "actions": ["Check the sender's address and hover over any link to see where it goes before clicking."], "references": []}
 
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
        if ai_result and ai_result["verdict"] == "likely_safe":
            ai_result = None                     # never let the AI call a medium or high rule-based risk safe
 
    if ai_result:
        result = {"risk_level": level, "source": "ai", "references": references, **ai_result}
    else:
        result = {
            "risk_level": level,
            "verdict": LEVEL_TO_VERDICT[level],
            "source": "playbook",
            "why": describe_signs(payload),
            "actions": [s["text"] for s in steps][:MAX_ACTIONS],
            "references": references,
        }
    _cache[key] = result
    return result
 
 
if __name__ == "__main__":
    def _ipqs(domain, age="18 years ago", risk=0):
        return {"status": "Report found", "safe": True, "suspicious": False, "domain": domain,
                "malware": False, "phishing": False, "risk_score": risk, "domain_age": age}
    campus_intel = {                                            # shaped like the real UOP email results
        "url_results": [{"status": "No report found"}] * 4,
        "ipqs_results": [_ipqs("my.pacific.edu"), _ipqs("technology.pacific.edu"), _ipqs("my.pacific.edu"), _ipqs("my.pacific.edu")],
        "urlscan_results": [{"status": "Report found", "final_url": "https://sso.pacific.edu/app/x", "domain_created": "Not found."}],
        "urlhaus_results": [{"url_status": "Not found"}] * 4,
    }
    awareness_words = [{"type": "Message Wording", "severity": "High"}, {"type": "Urgency Language", "severity": "Medium"},
                       {"type": "Sensitive Info Request", "severity": "High"}]
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
        "Canva email from the spam folder": build_payload(
            [{"type": "Message Wording", "severity": "Low"}], [], [], ["dkim=pass; spf=pass; dmarc=pass"],
            "Canva <marketing@engage.canva.com>", 18, in_spam=True),
        "Awareness email in the spam folder": build_payload(
            awareness_words, [], [], ["dkim=pass; spf=pass; dmarc=pass"], "MyPacific <mypacific@pacific.edu>", 4,
            intel=campus_intel, in_spam=True),
        "Clean email": build_payload([], [], [], ["dkim=pass; spf=pass; dmarc=pass"], "Husna <a@pacific.edu>", 0),
        "Awareness email (clean links, same org)": build_payload(
            awareness_words, [], [], ["dkim=pass; spf=pass; dmarc=pass"], "MyPacific <mypacific@pacific.edu>", 4, intel=campus_intel),
        "Same wording, clean links to another site": build_payload(
            awareness_words, [], [], ["dkim=pass; spf=pass; dmarc=pass"], "Support <help@example.com>", 4, intel=campus_intel),
        "Same wording, brand-new link site": build_payload(
            awareness_words, [], [], ["dkim=pass; spf=pass; dmarc=pass"], "Support <help@example.com>", 1,
            intel={"ipqs_results": [_ipqs("example-login.com", age="3 days ago", risk=40)]}),
    }
    print("\nflagged links demo:", flagged_links({
        "url_results": [{"url": "http://bad.example/a", "status": "Report found", "malicious": 5, "suspicious": 0},
                        {"url": "http://ok.example/b", "status": "Report found", "malicious": 0, "suspicious": 0}],
        "ipqs_results": [{"url": "http://bad.example/a", "status": "Report found", "phishing": True, "risk_score": 90},
                         {"url": "http://new.example/c", "status": "Report found", "phishing": False, "risk_score": 10, "domain_age": "2 days ago"}],
        "urlhaus_results": [{"url": "http://ok.example/b", "url_status": "Not found"}]}))
    for name, payload in samples.items():
        result = get_remediation(payload)
        print(f"\n== {name}")
        print("payload:", json.dumps(payload, separators=(",", ":")))
        print(f"risk: {result['risk_level']} | verdict: {result['verdict']} | source: {result['source']}")
        for action in result["actions"]:
            print("  -", action)