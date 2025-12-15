"""
Train a Random Forest classifier to identify cryptographic algorithms from ciphertext.
SIH-1681 Compliant: Outputs Precision, Recall, Confusion Matrix, and Feature Importance.
"""

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import numpy as np

def train_cipher_classifier(data_file='training_data.csv', model_file='cipher_model.pkl'):
    """Train and save the cipher identification model."""
    print(f"Loading training data from {data_file}...")
    try:
        df = pd.read_csv(data_file)
    except FileNotFoundError:
        print("Data file not found! Run generate_training_data.py first.")
        return None, 0

    # Separate features and labels
    X = df.drop('label', axis=1).values
    y = df['label'].values
    feature_names = df.columns[:-1]
    
    print(f"Dataset: {len(df)} samples, {X.shape[1]} features")
    print(f"Classes: {set(y)}")
    
    # Split into train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    # Train Random Forest (Baseline Model per SIH Req 5.1)
    print("\nTraining Random Forest classifier...")
    clf = RandomForestClassifier(
        n_estimators=300,        # Increased trees
        max_depth=None,          # Allow full depth
        min_samples_split=2,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'  # Handle potential imbalance
    )
    
    clf.fit(X_train, y_train)
    
    # Evaluate (SIH Req 6: Evaluation Methodology)
    print("\n" + "="*30)
    print("   MODEL EVALUATION REPORT   ")
    print("="*30)
    
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"Overall Accuracy: {accuracy * 100:.2f}%")
    print("\nClassification Report (Precision / Recall):")
    print(classification_report(y_test, y_pred))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Feature importance (SIH Req 7: Explainability)
    print("\n" + "="*30)
    print("   EXPLAINABILITY (Feature Importance)   ")
    print("="*30)
    
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]

    print("Top Influential Features:")
    for f in range(X.shape[1]):
        print(f"{f+1}. {feature_names[indices[f]]}: {importances[indices[f]]:.4f}")

    # Save model
    print(f"\nSaving model to {model_file}...")
    joblib.dump(clf, model_file)
    print("Model saved successfully!")
    
    return clf, accuracy

if __name__ == "__main__":
    train_cipher_classifier(
        data_file='d:/CryptX-main/training_data.csv',
        model_file='d:/CryptX-main/cipher_model.pkl'
    )
