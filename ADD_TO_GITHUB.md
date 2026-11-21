# PhishGuard Five New Features

This folder is an **addition** to the existing [PhishGuard repository](https://github.com/SeanRouse14/PhishGuard-Email-Phishing-Detection). Keep the existing `prototype.py`, `sample_emails.csv`, diagrams, and README. Upload the **new** files/folders to the root of the same GitHub repository. Do not replace `prototype.py`.

## Features

1. **Web scanner:** `app.py` + `templates/index.html` + `static/style.css` allow users to scan sender, subject, and body in a browser.
2. **ML probability (optional):** `train_model.py` trains a TF-IDF/logistic-regression model with enough labeled examples. The website only shows an experimental ML percentage if a locally trained model exists. This is **not** a calibrated, validated phishing probability.
3. **Suspicious link detection:** `app.py` checks URLs without visiting them. Checks HTTP, shorteners, IP-address hosts, IDNs, long hosts, and `@` in URL authority.
4. **Phishing explanation:** uses reasons from existing `prototype.classify`, plus URL warnings.
5. **History + feedback:** saves scans to existing SQLite tables; users can review the 30 newest scans and record corrections. Feedback does **not** auto-retrain.

## Install / run (Python 3.9+)

```bash
python -m pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** on your own computer. The app starts only on localhost.

## Optional ML feature

Create a labeled CSV you are authorized to use, with `sender,subject,body,expected` columns. Use at least 40 examples, with at least 15 each of `Phishing` and `Legitimate` (more is much better). Do NOT train on the 10 synthetic demo rows and claim the result is accurate.

```bash
python train_model.py training_emails.csv
python app.py
```

The example script reports held-out metrics. The displayed probability is a model output, **not calibrated or externally validated**. Do not upload sensitive email messages or datasets to a public repository.

## Privacy and limitations

- Local-only classroom demonstration; not a real email security product.
- No Gmail/Outlook connections, inbox scraping, or automatic clicking of links.
- Rule-based classifications remain those of the existing `prototype.py`.
- Never paste passwords or real personal/sensitive email data.
- The app has no user login or CSRF protection; do not expose it to the public internet.
- For a deployed product, authentication, access controls, model validation, data protection, and stronger URL analysis would be needed.
