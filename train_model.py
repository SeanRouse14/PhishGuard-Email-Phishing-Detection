"""Optional ML training on your OWN labeled CSV. Does NOT use the tiny demo set by default.

Required CSV columns: sender, subject, body, expected (Phishing or Legitimate).
Example: python train_model.py training_emails.csv
"""
import csv
import sys
from collections import Counter
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

ROOT = Path(__file__).resolve().parent


def main(path):
    with open(path, newline='', encoding='utf-8') as handle:
        rows = list(csv.DictReader(handle))
    required = {'sender', 'subject', 'body', 'expected'}
    if not rows or not required.issubset(rows[0]):
        raise ValueError('CSV needs sender, subject, body, expected columns')
    if len(rows) < 40:
        raise ValueError('Need at least 40 labeled examples. Do not train on the 10 artificial samples.')
    labels = [r['expected'].strip() for r in rows]
    counts = Counter(labels)
    if set(counts) != {'Phishing', 'Legitimate'} or min(counts.values()) < 15:
        raise ValueError('Need at least 15 examples of each label, Phishing and Legitimate.')
    text = [' '.join((r['sender'], r['subject'], r['body'])) for r in rows]
    x_train, x_test, y_train, y_test = train_test_split(text, labels, test_size=0.25, random_state=42, stratify=labels)
    model = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), max_features=8000), LogisticRegression(max_iter=1000))
    model.fit(x_train, y_train)
    print('Held-out evaluation (small datasets are not suitable for production):')
    print(classification_report(y_test, model.predict(x_test), zero_division=0))
    joblib.dump(model, ROOT / 'phishing_model.joblib')
    print('Saved phishing_model.joblib. Do not commit private emails or untrusted model files.')


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python train_model.py path/to/labeled_training.csv')
    main(sys.argv[1])
