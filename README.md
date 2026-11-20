# Email Phishing Detection — Milestone 3 Simulation

This is a **working rule-based proof of concept/testbed**, not a trained machine-learning model. It has no external API calls and does not access a live email account. It analyzes supplied sender/subject/body text; labels it Phishing, Review, or Legitimate; explains triggered rules; and stores inputs, predictions, and corrections in a local SQLite database.

## Run (Python 3.9+; no dependencies)

1. Download or clone this folder and open a terminal inside it.
2. Run `python prototype.py --evaluate` to run the 10 illustrative labeled sample messages and print accuracy, precision, recall, F1, and the confusion counts (Review counts as flagged).
3. Test a new message with `python prototype.py --sender security@example-notices.com --subject "Urgent verify your account" --body "Click here to confirm your identity"`.
4. Log a human correction using a prediction ID from step 3: `python prototype.py --correct 11 --label Legitimate` (substitute the actual printed ID).
5. Inspect `predictions.db` using any SQLite viewer, or run `python -m sqlite3 predictions.db` if your Python version includes the optional SQLite command line module.

## Limitations

The examples are artificial and deliberately simple. Reported testbed metrics **do not validate real-world effectiveness** and must not be misrepresented as trained-ML results or Milestone 2 evaluation targets. The risk score is NOT a calibrated probability. The Figma prototype is a separate interface artifact; it is not connected to this CLI testbed. A later implementation could train a classifier on a cited, labeled dataset, evaluate on held-out examples, host the model, and integrate the Figma screens.

## Files

- `prototype.py`: runnable CLI testbed
- `sample_emails.csv`: labeled illustrative test data
- `predictions.db`: automatically created on first run
