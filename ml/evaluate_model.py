import os
import joblib
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay, roc_curve, auc

# -----------------------------
# Load data
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "phishing.csv")
data = pd.read_csv(DATASET_PATH)

numeric_data = data.select_dtypes(include=["number"])
y = numeric_data["label"]
if set(y.unique()) == {-1, 1}:
    y = y.map({-1: 0, 1: 1})
X = numeric_data.drop(columns=["label"])

# -----------------------------
# Load model & RFE
# -----------------------------
MODEL_DIR = os.path.join(BASE_DIR, "..", "backend", "model")
model = joblib.load(os.path.join(MODEL_DIR, "phishing_model.pkl"))
rfe = joblib.load(os.path.join(MODEL_DIR, "feature_selector.pkl"))

X_selected = rfe.transform(X)
y_pred = model.predict(X_selected)

# -----------------------------
# Confusion Matrix
# -----------------------------
cm = confusion_matrix(y, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["Safe", "Phishing"])
disp.plot(cmap=plt.cm.Blues)
plt.title("Confusion Matrix")
plt.savefig("confusion_matrix.png")
plt.show()

# -----------------------------
# ROC Curve
# -----------------------------
y_prob = model.predict_proba(X_selected)[:, 1]
fpr, tpr, thresholds = roc_curve(y, y_prob)
roc_auc = auc(fpr, tpr)

plt.figure()
plt.plot(fpr, tpr, color="darkorange", lw=2, label=f"ROC curve (AUC = {roc_auc:.2f})")
plt.plot([0,1], [0,1], color="navy", lw=2, linestyle="--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curve")
plt.legend(loc="lower right")
plt.savefig("roc_curve.png")
plt.show()
