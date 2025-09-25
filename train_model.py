# train_model.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Step 1: Load dataset
df = pd.read_csv("dataset.csv")

# Step 2: Drop index column
df = df.drop(columns=["index"])

# Step 3: Features (X) and Target (y)
X = df.drop(columns=["Result"])
y = df["Result"]

# Step 4: Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# Step 5: Train model (Random Forest works well)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Step 6: Evaluate
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Step 7: Save model
joblib.dump(model, "phishing_model.pk9")
print("✅ Model saved as phishing_model.pk9")
