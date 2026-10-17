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
FEATURES = [
    "cpu_pct",
    "mem_mb",
    "etype_encoded",
    "hour_of_day",
    "is_sys_dir",
    "proc_count",
]

def main():
    df = pd.read_csv(CSV)
    missing = set(FEATURES + ["risk_lvl"]) - set(df.columns)
    if missing:
        raise ValueError(f"Training CSV is missing columns: {', '.join(sorted(missing))}")
    if df.empty:
        raise ValueError(f"Training CSV contains no rows: {CSV}")

    X = df[FEATURES]
    y = df["risk_lvl"]
    if y.nunique() < 2:
        raise ValueError("Training requires at least two distinct risk labels")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train.to_numpy(), y_train)

    preds = model.predict(X_test.to_numpy())
    print("Evaluation is on a synthetic classroom dataset; it does not estimate real-world detection performance.")
    print(classification_report(y_test, preds, zero_division=0))
    print("confusion matrix:")
    print(confusion_matrix(y_test, preds))

    joblib.dump(model, OUT)
    print(f"saved model -> {OUT}")

if __name__ == "__main__":
    main()
