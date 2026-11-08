"""
eval_body.py - offline check of the body analyzer. Nothing is emailed or sent anywhere.

Usage (from backend):   uv run eval_body.py emails.csv
CSV needs two columns: text,label     (label: phishing / legit, or 1 / 0)
"""
import csv
import sys

csv.field_size_limit(10_000_000)

FLAG_SEVERITIES = {"Medium", "High"}      # what the popup treats as a real warning
SHOW_WRONG = 10


def is_phishing(label) -> bool:
    return str(label).strip().lower() in {"1", "phishing", "phish"}


def evaluate(rows, analyzer):
    """Returns two result dicts: full analyzer (model + rules) and model score alone."""
    results = {"analyzer": [], "model": []}
    for text, label in rows:
        truth = is_phishing(label)
        flagged = any(f["severity"] in FLAG_SEVERITIES for f in analyzer.analyze(text))
        model_flag = analyzer.phishing_probability(text) >= analyzer.threshold
        results["analyzer"].append((truth, flagged, text))
        results["model"].append((truth, model_flag, text))
    return results


def summarize(items):
    tp = sum(1 for t, p, _ in items if t and p)
    fp = sum(1 for t, p, _ in items if not t and p)
    fn = sum(1 for t, p, _ in items if t and not p)
    tn = sum(1 for t, p, _ in items if not t and not p)
    ratio = lambda a, b: a / b if b else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "false_positive_rate": ratio(fp, fp + tn),
    }


def show(name, items):
    s = summarize(items)
    print(f"\n== {name}  ({len(items)} emails)")
    print(f"   caught phishing {s['tp']}  | missed phishing {s['fn']}  | wrongly flagged legit {s['fp']}  | correct legit {s['tn']}")
    print(f"   precision {s['precision']:.0%}   recall {s['recall']:.0%}   false-positive rate {s['false_positive_rate']:.0%}")
    for title, test in (("Wrongly flagged (legit)", lambda t, p: p and not t), ("Missed (phishing)", lambda t, p: t and not p)):
        wrong = [text for t, p, text in items if test(t, p)][:SHOW_WRONG]
        if wrong:
            print(f"   {title}:")
            for text in wrong:
                print("     -", " ".join(text.split())[:90])


def load(path):
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        return [(row["text"], row["label"]) for row in csv.DictReader(f) if row.get("text")]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: uv run eval_body.py emails.csv")
    from body_classifier import BodyAnalyzer       # loaded here so evaluate() can be tested without the model
    rows = load(sys.argv[1])
    results = evaluate(rows, BodyAnalyzer())
    show("Model + rules (what the popup uses)", results["analyzer"])
    show("Model score alone", results["model"])