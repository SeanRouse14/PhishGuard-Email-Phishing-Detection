"""PhishGuard local demonstration web application. Run with python app.py."""
import json
import os
import re
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from flask import Flask, flash, redirect, render_template, request, url_for
from prototype import classify, init_db

BASE = Path(__file__).resolve().parent
app = Flask(__name__)
app.secret_key = os.environ.get('PHISHGUARD_SECRET', 'local-demo-only-change-before-deploy')
MAX_FIELD = 20000
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly'}


def inspect_links(body):
    """Local URL heuristics; does not visit any URL or claim definitive safety."""
    findings = []
    for raw in URL_RE.findall(body):
        url = raw.rstrip('.,;!?)]}')
        parsed = urlsplit(url)
        host = (parsed.hostname or '').lower()
        concerns = []
        if parsed.scheme == 'http':
            concerns.append('Uses unencrypted HTTP')
        if host in SHORTENERS:
            concerns.append('Uses a URL shortener')
        if host.startswith('xn--') or '.xn--' in host:
            concerns.append('Contains an internationalized domain name')
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host):
            concerns.append('Uses an IP address instead of a domain name')
        if '@' in parsed.netloc:
            concerns.append('Contains @ in the link address')
        if len(host) > 55:
            concerns.append('Unusually long hostname')
        findings.append({'url': url, 'concerns': concerns or ['No simple URL warnings detected']})
        if len(findings) >= 15:
            break
    return findings


def ml_result(sender, subject, body):
    """Optional trained model. Training script writes model only when data requirements pass."""
    model_path = BASE / 'phishing_model.joblib'
    if not model_path.exists():
        return None
    try:
        import joblib
        pipeline = joblib.load(model_path)  # load ONLY locally trained, trusted files
        text = f'{sender} {subject} {body}'
        classes = list(pipeline.classes_)
        phishing_pos = classes.index('Phishing')
        probability = float(pipeline.predict_proba([text])[0][phishing_pos])
        return round(probability * 100, 1)
    except (ImportError, ValueError, OSError, AttributeError, IndexError):
        return None


@app.get('/')
def home():
    return render_template('index.html', result=None, history=None)


@app.post('/scan')
def scan():
    sender = request.form.get('sender', '').strip()[:MAX_FIELD]
    subject = request.form.get('subject', '').strip()[:MAX_FIELD]
    body = request.form.get('body', '').strip()[:MAX_FIELD]
    if not sender or not subject or not body:
        flash('Please enter sender, subject, and email body.')
        return redirect(url_for('home'))
    label, score, explanation = classify(sender, subject, body)
    links = inspect_links(body)
    # Preserve original classifier behavior and store its score honestly as heuristic points.
    with init_db() as conn:
        cur = conn.execute('INSERT INTO email_samples(sender,subject,body) VALUES (?,?,?)', (sender, subject, body))
        pred = conn.execute('INSERT INTO predictions(email_id,label,score,explanation) VALUES (?,?,?,?)',
                            (cur.lastrowid, label, score, explanation))
        prediction_id = pred.lastrowid
    result = {'id': prediction_id, 'label': label, 'score': score,
              'explanation': explanation, 'links': links,
              'ml_probability': ml_result(sender, subject, body)}
    return render_template('index.html', result=result, history=None,
                           sender=sender, subject=subject, body=body)


@app.get('/history')
def history():
    with init_db() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute('''SELECT p.id, s.sender, s.subject, p.label, p.score,
                        p.explanation, p.created_at,
                        (SELECT c.corrected_label FROM corrections c WHERE c.prediction_id=p.id
                        ORDER BY c.id DESC LIMIT 1) AS feedback
                        FROM predictions p JOIN email_samples s ON s.id=p.email_id
                        ORDER BY p.id DESC LIMIT 30''').fetchall()
    return render_template('index.html', result=None, history=[dict(r) for r in rows])


@app.post('/feedback/<int:prediction_id>')
def feedback(prediction_id):
    label = request.form.get('label')
    if label not in ('Phishing', 'Legitimate'):
        flash('Invalid feedback label.')
        return redirect(url_for('history'))
    with init_db() as conn:
        exists = conn.execute('SELECT 1 FROM predictions WHERE id=?', (prediction_id,)).fetchone()
        if not exists:
            flash('Scan not found.')
            return redirect(url_for('history'))
        conn.execute('INSERT INTO corrections(prediction_id,corrected_label) VALUES (?,?)',
                     (prediction_id, label))
    flash('Feedback saved for review. This does not automatically retrain the model.')
    return redirect(url_for('history'))


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
