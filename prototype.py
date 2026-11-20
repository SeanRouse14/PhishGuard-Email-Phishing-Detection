"""CIS321 phishing detection simulation/testbed. Standard library only.
Rule-based illustrative baseline, NOT a trained machine learning model.
"""
import argparse, csv, json, sqlite3, re
from pathlib import Path

ROOT=Path(__file__).resolve().parent
DB=ROOT/'predictions.db'

def init_db():
    conn=sqlite3.connect(DB)
    conn.executescript('''CREATE TABLE IF NOT EXISTS email_samples(id INTEGER PRIMARY KEY, sender TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS predictions(id INTEGER PRIMARY KEY, email_id INTEGER NOT NULL, label TEXT NOT NULL, score REAL NOT NULL, explanation TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(email_id) REFERENCES email_samples(id));
CREATE TABLE IF NOT EXISTS corrections(id INTEGER PRIMARY KEY, prediction_id INTEGER NOT NULL, corrected_label TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(prediction_id) REFERENCES predictions(id));''')
    return conn

def classify(sender,subject,body):
    text=(subject+' '+body).lower()
    triggers={'verify your account':2,'password':1,'urgent':1,'click here':2,'gift card':2,'wire transfer':2,'suspended':2,'confirm your identity':2,'login immediately':2,'bank details':2,'security alert':1,'act now':2,'prize':1}
    reasons=[f'phrase: {phrase}' for phrase,points in triggers.items() if phrase in text]
    score=sum(points for phrase,points in triggers.items() if phrase in text)
    if re.search(r'https?://',text):score+=1;reasons.append('contains a link')
    if sender.count('@')!=1 or not sender.split('@')[-1].count('.'):
        score+=2;reasons.append('unusual sender address')
    if score>=3: label='Phishing'
    elif score>=1:label='Review'
    else:label='Legitimate'
    # score is a heuristic indicator, NOT calibrated probability
    return label,score,', '.join(reasons) if reasons else 'No defined warning signs matched'

def run_samples():
    conn=init_db(); counts={'Phishing':0,'Review':0,'Legitimate':0}; rows=[]
    with (ROOT/'sample_emails.csv').open(newline='',encoding='utf-8') as f:
        for row in csv.DictReader(f):
            cur=conn.execute('INSERT INTO email_samples(sender,subject,body) VALUES (?,?,?)',(row['sender'],row['subject'],row['body']))
            label,score,why=classify(row['sender'],row['subject'],row['body'])
            conn.execute('INSERT INTO predictions(email_id,label,score,explanation) VALUES (?,?,?,?)',(cur.lastrowid,label,score,why))
            counts[label]+=1
            rows.append((row['expected'],label))
    conn.commit();conn.close()
    print('Simulation results (not a trained ML model):')
    for row in rows:print(f'Expected: {row[0]:10} Predicted: {row[1]}')
    print('Prediction counts:',counts)
    # Review treated as flagged for manual review; phishing benchmark is a two-class simplification.
    tp=sum(actual=='Phishing' and pred in ('Phishing','Review') for actual,pred in rows)
    fn=sum(actual=='Phishing' and pred=='Legitimate' for actual,pred in rows)
    fp=sum(actual=='Legitimate' and pred in ('Phishing','Review') for actual,pred in rows)
    tn=sum(actual=='Legitimate' and pred=='Legitimate' for actual,pred in rows)
    precision=tp/(tp+fp) if tp+fp else 0
    recall=tp/(tp+fn) if tp+fn else 0
    f1=2*precision*recall/(precision+recall) if precision+recall else 0
    accuracy=(tp+tn)/len(rows)
    print(json.dumps({'samples':len(rows),'TP':tp,'FP':fp,'TN':tn,'FN':fn,'accuracy':round(accuracy,3),'precision':round(precision,3),'recall':round(recall,3),'f1':round(f1,3)},indent=2))

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--evaluate',action='store_true');ap.add_argument('--sender');ap.add_argument('--subject');ap.add_argument('--body');ap.add_argument('--correct',type=int);ap.add_argument('--label',choices=['Phishing','Legitimate']);args=ap.parse_args()
    if args.evaluate:run_samples();return
    conn=init_db()
    if args.correct is not None:
        if not args.label:ap.error('--correct requires --label')
        conn.execute('INSERT INTO corrections(prediction_id,corrected_label) VALUES (?,?)',(args.correct,args.label));conn.commit();print('Correction logged');return
    if None in (args.sender,args.subject,args.body):ap.error('Provide --evaluate, or --sender --subject --body, or --correct ID --label LABEL')
    cur=conn.execute('INSERT INTO email_samples(sender,subject,body) VALUES (?,?,?)',(args.sender,args.subject,args.body))
    label,score,reasons=classify(args.sender,args.subject,args.body)
    p=conn.execute('INSERT INTO predictions(email_id,label,score,explanation) VALUES (?,?,?,?)',(cur.lastrowid,label,score,reasons));conn.commit()
    print(json.dumps({'prediction_id':p.lastrowid,'classification':label,'risk_score_not_probability':score,'reasons':reasons},indent=2))
if __name__=='__main__':main()
