import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib

df = pd.read_csv("dataset/urls.csv")
df.columns = df.columns.str.strip()

# Only the features we can realistically compute live from a raw URL
USABLE_FEATURES = [
    'having_IPhaving_IP_Address',
    'URLURL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'HTTPS_token',
    'age_of_domain',
    'DNSRecord',
]

X = df[USABLE_FEATURES]
y = df['Result']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"Model Accuracy (usable features only): {accuracy * 100:.2f}%")

joblib.dump(model, "model/phishing_model.pkl")
joblib.dump(USABLE_FEATURES, "model/feature_columns.pkl")
print("Model retrained and saved successfully!")