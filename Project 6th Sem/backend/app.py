from flask import Flask, render_template, jsonify
import sqlite3
from scanner import run_scan
import joblib
import pandas as pd

app = Flask(__name__)

# Load pre-trained model (e.g., Random Forest for risk scoring)
model = joblib.load('model.pkl')

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/start_scan')
def start_scan():
    results = run_scan()  # Run Nmap/OpenVAS scan
    return jsonify(results)

@app.route('/get_vulnerabilities')
def get_vulnerabilities():
    conn = sqlite3.connect('backend/database.db')
    df = pd.read_sql_query("SELECT * FROM vulnerabilities", conn)
    conn.close()
    return df.to_json(orient='records')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)  # Add host='0.0.0.0'