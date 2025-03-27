import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Load preprocessed data
df = pd.read_csv('nvd_data.csv')

# Map severity to numerical values (include "UNKNOWN")
severity_map = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3, 'UNKNOWN': 4}
df['severity'] = df['severity'].map(severity_map)

# Drop rows with NaN in severity
df = df.dropna(subset=['severity'])

# Features and target
X = df[['severity', 'cvss_score']]
y = df['severity']

# Train the model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

# Save the model
joblib.dump(model, 'model.pkl')