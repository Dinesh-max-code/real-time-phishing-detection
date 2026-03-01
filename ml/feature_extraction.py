# ============================================================
# Feature Extraction & Selection Utilities
# ============================================================

import numpy as np
from sklearn.feature_selection import SelectKBest, chi2


def apply_feature_selection(X, y, k=15):
    """
    Select top-k important features using Chi-Square test

    Parameters:
    X : pandas DataFrame (features)
    y : pandas Series (labels)
    k : int (number of features to select)

    Returns:
    X_selected : numpy array
    selector   : fitted SelectKBest object
    features   : list of selected feature names
    """

    selector = SelectKBest(score_func=chi2, k=k)
    X_selected = selector.fit_transform(X, y)

    selected_features = X.columns[selector.get_support()]

    return X_selected, selector, selected_features
