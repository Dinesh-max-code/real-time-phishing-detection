# ============================================================
# Phishing URL Detection - Multi-Dataset Stable Version
# (With Confusion Matrix Visualization Added)
# ============================================================

import os
import glob
import time
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    average_precision_score
)
from sklearn.feature_selection import RFE
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

import lightgbm as lgb


# ------------------------------------------------------------
# DATASET LOADING
# ------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")

print("Loading all datasets...")

csv_files = glob.glob(os.path.join(DATASET_DIR, "*.csv"))
dataframes = []

for file in csv_files:
    print(f"\nReading: {os.path.basename(file)}")

    df = None
    for enc in ["utf-8", "latin1", "cp1252"]:
        try:
            df = pd.read_csv(
                file,
                engine="python",
                encoding=enc,
                sep=None,
                on_bad_lines="skip"
            )
            break
        except Exception:
            continue

    if df is None:
        print("  ❌ Could not read file — skipping")
        continue

    print("  → Raw shape:", df.shape)

    possible_labels = ["label", "class", "result", "status"]
    label_col = None

    for col in df.columns:
        if col.lower() in possible_labels:
            label_col = col
            break

    if label_col is None:
        print("  ⚠ No label column — skipping")
        continue

    df.rename(columns={label_col: "label"}, inplace=True)

    if set(df["label"].unique()) == {-1, 1}:
        df["label"] = df["label"].map({-1: 0, 1: 1})

    df = df[df["label"].isin([0, 1])]
    numeric_df = df.select_dtypes(include=["number"])

    if "label" not in numeric_df.columns:
        print("  ⚠ No numeric features — skipping")
        continue

    print("  → Usable shape:", numeric_df.shape)
    dataframes.append(numeric_df)

if len(dataframes) == 0:
    raise ValueError("❌ No compatible datasets found.")

data = pd.concat(dataframes, ignore_index=True)

print("\nTotal merged rows:", len(data))
print("Datasets used:", len(dataframes))


# ------------------------------------------------------------
# CLEANING
# ------------------------------------------------------------

X = data.drop(columns=["label"])
y = data["label"]

X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

constant_cols = [col for col in X.columns if X[col].nunique() <= 1]
X = X.drop(columns=constant_cols)

drop_features = [
    "URLSimilarityIndex", "TLDLegitimateProb", "URLCharProb",
    "DomainTitleMatchScore", "LineOfCode", "LargestLineLength",
    "HasDescription", "HasSocialNet", "HasCopyrightInfo",
    "NoOfImage", "NoOfCSS", "NoOfJS", "NoOfSelfRef", "NoOfExternalRef"
]

X = X.drop(columns=[f for f in drop_features if f in X.columns])

X["temp_label"] = y
X = X.drop_duplicates()
y = X["temp_label"]
X = X.drop(columns=["temp_label"])

print("Final dataset shape:", X.shape)


# ------------------------------------------------------------
# TRAIN TEST SPLIT
# ------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)


# ------------------------------------------------------------
# RFE
# ------------------------------------------------------------

base_model = lgb.LGBMClassifier(
    n_estimators=120,
    learning_rate=0.1,
    max_depth=5,
    random_state=42,
    verbose=-1
)

n_features = min(15, X_train.shape[1])

rfe = RFE(base_model, n_features_to_select=n_features, step=3)
rfe.fit(X_train, y_train)

X_train_sel = rfe.transform(X_train)
X_test_sel = rfe.transform(X_test)

selected_features = X.columns[rfe.support_]

print("Selected features:", list(selected_features))


# ------------------------------------------------------------
# TRAIN FINAL MODEL
# ------------------------------------------------------------

start_time = time.time()

final_model = lgb.LGBMClassifier(
    n_estimators=150,
    learning_rate=0.1,
    max_depth=5,
    random_state=42,
    verbose=-1
)

final_model.fit(X_train_sel, y_train)

training_time = time.time() - start_time


# ------------------------------------------------------------
# EVALUATION
# ------------------------------------------------------------

y_pred = final_model.predict(X_test_sel)
y_prob = final_model.predict_proba(X_test_sel)[:, 1]

accuracy = accuracy_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, y_prob)
ap_score = average_precision_score(y_test, y_prob)

print("\n================ EVALUATION ================")
print("Test Accuracy:", round(accuracy, 4))
print("ROC-AUC:", round(roc_auc, 4))
print("Average Precision (PR-AUC):", round(ap_score, 4))
print("\n", classification_report(y_test, y_pred))

cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

print("Sensitivity:", round(tp / (tp + fn), 4))
print("Specificity:", round(tn / (tn + fp), 4))
print("Training Time:", round(training_time, 4), "sec")


# ------------------------------------------------------------
# CONFUSION MATRIX VISUALIZATION (NEW FEATURE ADDED)
# ------------------------------------------------------------

plt.figure(figsize=(6,5))

sns.heatmap(
    cm,
    annot=True,
    fmt="d",
    cmap="Blues",
    xticklabels=["Legitimate (0)", "Phishing (1)"],
    yticklabels=["Legitimate (0)", "Phishing (1)"]
)

plt.xlabel("Predicted Label")
plt.ylabel("True Label")
plt.title("Confusion Matrix - Phishing Detection")

plt.tight_layout()
plt.savefig("confusion_matrix.png", dpi=300)
plt.show()

print("Confusion matrix saved as confusion_matrix.png")


# ------------------------------------------------------------
# SAVE MODEL
# ------------------------------------------------------------

MODEL_DIR = os.path.join(BASE_DIR, "..", "backend", "model")
os.makedirs(MODEL_DIR, exist_ok=True)

joblib.dump(final_model, os.path.join(MODEL_DIR, "phishing_model.pkl"))
joblib.dump(rfe, os.path.join(MODEL_DIR, "feature_selector.pkl"))
joblib.dump(selected_features.tolist(),
            os.path.join(MODEL_DIR, "selected_features.pkl"))

print("\n✅ Model saved successfully")