import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# 1. Load Dataset
data = pd.read_csv("phishing.csv")

# Drop columns that are not features
X = data.drop(["id", "Result"], axis=1)   # all 30 features
y = data["Result"]                        # labels (-1 = safe, 1 = phishing)


# 2. Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# 3. Train Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 4. Evaluate
y_pred = model.predict(X_test)
print("✅ Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# 5. Save Model
joblib.dump(model, "phishing_model.pkl")
print("✅ Model trained and saved as phishing_model.pkl")
