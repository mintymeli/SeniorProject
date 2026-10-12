import html
import re

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_NAME = "cybersectony/phishing-email-detection-distilbert_v2.4.1"

# Per the model card the 4 outputs are:
# 0 legitimate_email, 1 phishing_url, 2 legitimate_url, 3 phishing_url_alt
PHISHING_INDICES = [1, 3]

# Urgency is matched as phrases in context, not single words. "immediately" alone
# also appears in normal mail ("book signing immediately following the keynote"),
# so we look for pressure to act: "verify immediately", "within 24 hours", etc.
URGENCY_PATTERNS = [
    r"\bact now\b",
    r"\b(respond|reply|act|verify|confirm|update|click|call|pay|send)\b[^.!?\n]{0,30}\b(immediately|right away|asap|now)\b",
    r"\bas soon as you (see|get|read) this\b",
    r"\burgent(ly)?\b",
    r"\bimmediate (action|attention|response)\b",
    r"\baccount (will be |has been |is )?(permanently )?(suspended|closed|locked|limited|disabled|terminated)\b",
    r"\bverify your (account|identity|password|email|information|details)\b",
    r"\bwithin (12|24|48|72) hours\b",
    r"\bfinal (notice|warning)\b",
    r"\b(failure to|if you do not|unless you) (act|respond|verify|confirm|comply)\b",
]


def find_urgency(text: str) -> list[str]:
    """Returns the urgency phrases found in already-lowercased text."""
    hits = []
    for pattern in URGENCY_PATTERNS:
        match = re.search(pattern, text)
        if match:
            hits.append(match.group(0))
    return hits


GENERIC_GREETING = re.compile(
    r"\b(dear (customer|user|member|client|valued customer|account holder)|valued customer|hello (customer|user))\b",
    re.IGNORECASE,
)

SENSITIVE_PHRASES = [
    "your password", "enter your password", "social security", "credit card",
    "card number", "bank account", "verify your identity", "confirm your identity",
    "login credentials", "account number",
]

URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def extract_links(body: str) -> list[str]:
    """Pull URLs from the raw body (before HTML is stripped, so href links are kept)."""
    seen = []
    for url in URL_PATTERN.findall(body):
        url = url.rstrip(".,;")
        if url not in seen:
            seen.append(url)
    return seen


def clean_body(text: str) -> str:
    """Strip HTML tags so the model reads the message, not markup."""
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text)
    return re.sub(r"\s+", " ", text).strip()


class BodyAnalyzer:
    """Loads the model once, then scores email bodies."""

    def __init__(self, threshold: float = 0.7):
        self.threshold = threshold
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
        self.model.eval()

    def class_probabilities(self, body: str) -> list[float]:
        # Tokens here just means chunks of text; the model reads at most 512 of them.
        inputs = self.tokenizer(
            clean_body(body), return_tensors="pt", truncation=True, max_length=512
        )
        with torch.no_grad():
            return torch.softmax(self.model(**inputs).logits, dim=-1)[0].tolist()

    def phishing_probability(self, body: str) -> float:
        probs = self.class_probabilities(body)
        return sum(probs[i] for i in PHISHING_INDICES)

    def analyze(self, body: str) -> list[dict]:
        """Returns findings shaped like PhishingIndicator (type, description, severity)."""
        findings = []

        # Don't score empty or near-empty text: the model leans "phishing" on it,
        # which gives a meaningless result (e.g. 100% on a blank body).
        if len(clean_body(body)) < 20:
            return [{
                "type": "No Readable Text",
                "description": "This email has little or no readable text, so the message wording could not be checked.",
                "severity": "Low",
            }]

        score = self.phishing_probability(body)
        lowered = clean_body(body).lower()
        urgency_hits = find_urgency(lowered)
        has_rule_hit = (
            bool(urgency_hits)
            or any(p in lowered for p in SENSITIVE_PHRASES)
            or bool(GENERIC_GREETING.search(lowered))
        )

        # The model alone over-flags automated email (receipts, job alerts, codes),
        # so a high score only becomes Medium/High when a rule-based check agrees.
        if score >= self.threshold:
            if has_rule_hit:
                findings.append({
                    "type": "Message Wording",
                    "description": f"The wording of this message resembles known phishing emails ({score:.0%} match), and it also contains warning signs listed below.",
                    "severity": "High" if score >= 0.9 else "Medium",
                })
            else:
                findings.append({
                    "type": "Message Wording",
                    "description": f"The wording resembles phishing emails ({score:.0%} match), but no other warning signs were found. Automated emails like receipts or alerts can look like this, so check the sender and links.",
                    "severity": "Low",
                })

        hits = urgency_hits
        if hits:
            findings.append({
                "type": "Urgency Language",
                "description": "Pressures you to act quickly: " + ", ".join(hits),
                "severity": "Medium",
            })

        greeting = GENERIC_GREETING.search(lowered)
        if greeting:
            findings.append({
                "type": "Generic Greeting",
                "description": f'Uses a generic greeting ("{greeting.group(0)}") instead of your name.',
                "severity": "Low",
            })

        asked = [p for p in SENSITIVE_PHRASES if p in lowered]
        if asked:
            findings.append({
                "type": "Sensitive Info Request",
                "description": "Mentions sensitive information: " + ", ".join(asked),
                "severity": "High",
            })

        return findings


if __name__ == "__main__":
    analyzer = BodyAnalyzer()
    print("Model labels:", analyzer.model.config.id2label)

    samples = {
        "legit (friendly)": "Hey everyone, we are hosting a board game night this Friday at the First-Gen Hub. Food and drinks will be provided. Hope to see you all there! All the best, Iman",
        "legit (receipt)": "Thanks for your order! Your order #48213 has shipped and should arrive on Tuesday. You can track your package any time from your account page.",
        "legit (job alert)": "New job match. A new role at BizLink Technology matches your preferences. View job. Update your preferences.",
        "fake phishing": "Dear Customer, your PayPal account has been limited. Verify your identity within 24 hours or your account will be permanently suspended. Click here: http://paypa1-support.com/verify",
    }
    for name, text in samples.items():
        probs = analyzer.class_probabilities(text)
        print(f"\n{name}: phishing probability = {sum(probs[i] for i in PHISHING_INDICES):.2%}")
        print("  all 4 classes [0,1,2,3]:", [f"{p:.1%}" for p in probs])
        for f in analyzer.analyze(text):
            print("  -", f)
        print("  links:", extract_links(text))