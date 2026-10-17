# train a simple Random Forest on our synthetic event CSV
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib

HERE = Path(__file__).resolve().parent
CSV = HERE / "events_train.csv"
OUT = HERE / "threat_model.pkl"

def main():
    df = pd.read_csv(CSV)
    X = df[["cpu_pct", "mem_mb", "etype_encoded", "hour_of_day", "is_sys_dir", "proc_count"]]
    y = df["risk_lvl"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    preds = model.predict(X_test)
    print(classification_report(y_test, preds))
    print("confusion matrix:")
    print(confusion_matrix(y_test, preds))

    joblib.dump(model, OUT)
    print(f"saved model -> {OUT}")

if __name__ == "__main__":
    main()
