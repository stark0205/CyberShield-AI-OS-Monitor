"""Train and evaluate a process-risk model from a prepared OpTC subset."""

import argparse
import csv
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.metrics import classification_report
from sklearn.model_selection import GroupShuffleSplit


HERE = Path(__file__).resolve().parent
DEFAULT_DATASET = HERE / "optc_labeled.csv"
DEFAULT_OUTPUT = HERE / "threat_model_optc.pkl"
REQUIRED_FIELDS = {"host", "event_type", "process_name", "has_parent", "risk_lvl"}
RISK_LEVELS = {"Normal", "Suspicious", "High Risk"}


def load_dataset(path: Path) -> list[dict[str, str | int]]:
    with path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        if not reader.fieldnames or not REQUIRED_FIELDS.issubset(reader.fieldnames):
            missing = sorted(REQUIRED_FIELDS - set(reader.fieldnames or []))
            raise ValueError(f"Training CSV is missing required columns: {', '.join(missing)}")

        rows: list[dict[str, str | int]] = []
        for row_number, row in enumerate(reader, start=2):
            host = (row.get("host") or "").strip()
            event_type = (row.get("event_type") or "").strip().lower()
            process_name = (row.get("process_name") or "").strip().lower()
            risk_level = (row.get("risk_lvl") or "").strip()
            if not host or not event_type or not process_name:
                raise ValueError(
                    f"Training CSV row {row_number} must include host, "
                    "event_type, and process_name"
                )
            if risk_level not in RISK_LEVELS:
                raise ValueError(
                    f"Training CSV row {row_number} has invalid risk_lvl "
                    f"{risk_level!r}; use {', '.join(sorted(RISK_LEVELS))}"
                )
            try:
                has_parent = int(row.get("has_parent") or "")
            except ValueError as error:
                raise ValueError(
                    f"Training CSV row {row_number} has invalid has_parent"
                ) from error
            if has_parent not in (0, 1):
                raise ValueError(
                    f"Training CSV row {row_number} has_parent must be 0 or 1"
                )
            rows.append(
                {
                    "host": host,
                    "event_type": event_type,
                    "process_name": process_name,
                    "has_parent": has_parent,
                    "risk_lvl": risk_level,
                }
            )

    if not rows:
        raise ValueError(f"No training events found in {path}")
    return rows


def build_features(row: dict[str, str | int]) -> dict[str, str | int]:
    """Use only features also available to the running application."""
    return {
        "event_type": str(row["event_type"]),
        "process_name": str(row["process_name"]),
        "has_parent": int(row["has_parent"]),
    }


def find_host_holdout(rows: list[dict[str, str | int]], labels: list[str]):
    groups = [str(row["host"]) for row in rows]
    classes = set(labels)
    hosts_per_class = {
        label: {
            str(row["host"])
            for row in rows
            if row["risk_lvl"] == label
        }
        for label in classes
    }
    unsupported = [label for label, hosts in hosts_per_class.items() if len(hosts) < 2]
    if unsupported:
        raise ValueError(
            "Host-held-out evaluation requires every risk label on at least "
            "two hosts; not enough hosts for: " + ", ".join(sorted(unsupported))
        )

    splitter = GroupShuffleSplit(n_splits=100, test_size=0.2, random_state=42)
    for train_indices, test_indices in splitter.split(rows, labels, groups):
        train_labels = {labels[index] for index in train_indices}
        test_labels = {labels[index] for index in test_indices}
        if train_labels == classes and test_labels == classes:
            return train_indices, test_indices

    raise ValueError(
        "Could not create a host-held-out split containing every class in "
        "both sets; provide more labeled hosts per class"
    )


def train_model(dataset: Path, output: Path) -> dict[str, object]:
    rows = load_dataset(dataset)
    labels = [str(row["risk_lvl"]) for row in rows]
    classes = sorted(set(labels))
    if len(classes) < 2:
        raise ValueError("Training needs at least two distinct risk labels")

    train_indices, test_indices = find_host_holdout(rows, labels)
    vectorizer = DictVectorizer()
    train_features = vectorizer.fit_transform(
        [build_features(rows[index]) for index in train_indices]
    )
    test_features = vectorizer.transform(
        [build_features(rows[index]) for index in test_indices]
    )
    train_labels = [labels[index] for index in train_indices]
    test_labels = [labels[index] for index in test_indices]

    classifier = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced_subsample",
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    classifier.fit(train_features, train_labels)
    predictions = classifier.predict(test_features)
    print(
        classification_report(
            test_labels,
            predictions,
            labels=classes,
            target_names=classes,
            zero_division=0,
        )
    )
    print(
        f"Host-held-out evaluation: {len(test_indices)} test events, "
        f"{len(set(str(rows[index]['host']) for index in test_indices))} test hosts"
    )

    artifact = {
        "schema_version": 1,
        "source": "DARPA OpTC eCAR labeled subset",
        "features": ["event_type", "process_name", "has_parent"],
        "vectorizer": vectorizer,
        "classifier": classifier,
        "classes": classes,
        "training_rows": len(train_indices),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, output)
    print(f"Saved OpTC model: {output}")
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    train_model(args.dataset, args.output)


if __name__ == "__main__":
    main()
