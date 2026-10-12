import glob
import os

import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

# display name -> (model id, class indices that mean "phishing")
# cybersectony: class 1 = phishing (confirmed on our samples), 3 is the second phishing class
# ElSlay / jagan-raj: binary models, 1 = phishing, 0 = legitimate (per their model cards)
MODELS = {
    "cybersectony": ("cybersectony/phishing-email-detection-distilbert_v2.4.1", [1, 3]),
    "ElSlay": ("ElSlay/BERT-Phishing-Email-Model", [1]),
    "jagan-raj": ("jagan-raj/PhishMail", [1]),
}

THRESHOLD = 0.5  # a model "flags" an email when its phishing score is at least this

# Just for testing, will need to test with real emails(expected label, short name, email text)
SAMPLES = [
    ("legit", "friendly invite",
     "Hey everyone, we are hosting a board game night this Friday at the First-Gen Hub. Food and drinks will be provided. Hope to see you all there! All the best, Iman"),
    ("legit", "order receipt",
     "Thanks for your order! Your order #48213 has shipped and should arrive on Tuesday. You can track your package any time from your account page."),
    ("legit", "job alert",
     "New job match. A new role at BizLink Technology matches your preferences. View job. Update your preferences."),
    ("legit", "handshake collections",
     "New items added to CO-OP Employers. New jobs added to collections you follow. G3 Enterprises, Inc. Intern-Marketing $22.5/hr • Internship • Modesto, CA (Onsite) G3 Enterprises, Inc. Intern-IT $24/hr • Internship • Modesto, CA (Onsite) G3 Enterprises, Inc. Intern-Finance $22.5/hr • Internship • Modesto, CA (Onsite) Added to CO-OP Employers. Want more curated content? Check out all the collections your school has curated for you."),
    ("legit", "verification code",
     "Your verification code is 482913. It expires in 10 minutes. If you didn't request this code, you can safely ignore this email."),
    ("legit", "library newsletter",
     "This week at the library: extended study hours during midterms, a new exhibit on the first floor, and a book sale on Friday. You can unsubscribe at any time from your account settings."),
    ("legit", "meeting reminder",
     "Reminder: our team meeting is tomorrow at 2 PM in Room 204. Please bring your project updates. See you there!"),
    ("phish", "fake paypal",
     "Dear Customer, your PayPal account has been limited. Verify your identity within 24 hours or your account will be permanently suspended. Click here: http://paypa1-support.com/verify"),
    ("phish", "fake m365 password",
     "Your Microsoft 365 password expires today. To keep using your email, confirm your password now: http://example.com/m365-login. Failure to act will lock your mailbox."),
    ("phish", "gift card scam",
     "Hi, are you available? I'm in a meeting and need you to buy 5 Apple gift cards for a client. Reply as soon as you see this and I'll send the details. Keep this between us. Thanks."),
]


def load_folder_samples(folder="test_emails"):
    """Reads legit_*.txt and phish_*.txt files from the folder, if it exists."""
    found = []
    for path in sorted(glob.glob(os.path.join(folder, "*.txt"))):
        fname = os.path.basename(path)
        if fname.startswith("legit_"):
            label = "legit"
        elif fname.startswith("phish_"):
            label = "phish"
        else:
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            found.append((label, fname[:-4], f.read()))
    return found


def load_models():
    loaded = {}
    for name, (model_id, phish_idx) in MODELS.items():
        try:
            print(f"Loading {name} ({model_id})...")
            tokenizer = AutoTokenizer.from_pretrained(model_id)
            model = AutoModelForSequenceClassification.from_pretrained(model_id)
            model.eval()
            loaded[name] = (tokenizer, model, phish_idx)
        except Exception as error:
            print(f"  Could not load {name}: {error}")
    return loaded


def phishing_score(tokenizer, model, phish_idx, text):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        probs = torch.softmax(model(**inputs).logits, dim=-1)[0].tolist()
    return sum(probs[i] for i in phish_idx if i < len(probs))


def main():
    samples = SAMPLES + load_folder_samples()
    models = load_models()
    if not models:
        print("No models loaded.")
        return

    names = list(models)
    stats = {n: {"correct": 0, "false_pos": 0, "false_neg": 0} for n in names}

    print("\nPhishing score per model (X = wrong at threshold {:.0%})\n".format(THRESHOLD))
    header = f"{'email':<24}{'expected':<10}" + "".join(f"{n:<16}" for n in names)
    print(header)
    print("-" * len(header))

    for expected, name, text in samples:
        row = f"{name[:23]:<24}{expected:<10}"
        for n in names:
            tokenizer, model, phish_idx = models[n]
            score = phishing_score(tokenizer, model, phish_idx, text)
            flagged = score >= THRESHOLD
            wrong = (flagged and expected == "legit") or (not flagged and expected == "phish")
            if wrong:
                stats[n]["false_pos" if expected == "legit" else "false_neg"] += 1
            else:
                stats[n]["correct"] += 1
            row += f"{score:>6.0%} {'X' if wrong else ' ':<9}"
        print(row)

    total = len(samples)
    print("\nSummary (out of {} emails)".format(total))
    for n in names:
        s = stats[n]
        print(f"  {n:<14} correct: {s['correct']:<3} "
              f"false positives (legit flagged): {s['false_pos']:<3} "
              f"false negatives (phishing missed): {s['false_neg']}")


if __name__ == "__main__":
    main()