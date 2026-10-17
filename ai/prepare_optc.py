"""Prepare a manually labeled, bounded OpTC eCAR JSONL subset for training."""

import argparse
import csv
import gzip
import json
import tempfile
from collections import Counter
from pathlib import Path


RISK_LEVELS = {"Normal", "Suspicious", "High Risk"}
OUTPUT_FIELDS = (
    "event_id",
    "host",
    "event_type",
    "process_name",
    "has_parent",
    "risk_lvl",
)
PROCESS_START_ACTIONS = {"CREATE", "START"}
FILE_ACTIONS = {"CREATE", "DELETE", "MODIFY", "UPDATE", "WRITE"}


def load_labels(path: Path) -> dict[str, str]:
    """Load explicit event-id labels; never infer labels from event heuristics."""
    labels: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        if not reader.fieldnames or not {"id", "risk_lvl"}.issubset(reader.fieldnames):
            raise ValueError("Labels CSV must contain id and risk_lvl columns")

        for row_number, row in enumerate(reader, start=2):
            event_id = (row.get("id") or "").strip()
            risk_level = (row.get("risk_lvl") or "").strip()
            if not event_id:
                raise ValueError(f"Labels CSV row {row_number} has no event id")
            if risk_level not in RISK_LEVELS:
                raise ValueError(
                    f"Labels CSV row {row_number} has unsupported risk_lvl "
                    f"{risk_level!r}; use {', '.join(sorted(RISK_LEVELS))}"
                )
            previous = labels.get(event_id)
            if previous is not None and previous != risk_level:
                raise ValueError(f"Conflicting labels for event id {event_id!r}")
            labels[event_id] = risk_level

    if not labels:
        raise ValueError(f"No event labels found in {path}")
    return labels


def iter_jsonl(path: Path):
    opener = gzip.open if path.suffix.lower() == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"{path}:{line_number} is not JSON Lines; export one eCAR "
                    "object per line before preparing the subset"
                ) from error
            if not isinstance(record, dict):
                raise ValueError(f"{path}:{line_number} must contain a JSON object")
            yield record


def _basename(path_value: object) -> str:
    path = str(path_value or "").strip().replace("\\", "/").rstrip("/")
    return path.rsplit("/", 1)[-1]


def _has_parent(record: dict) -> int:
    try:
        return int(int(record.get("ppid", -1)) > 0)
    except (TypeError, ValueError):
        return 0


def prepare_record(record: dict, risk_level: str) -> dict[str, str | int] | None:
    """Convert supported eCAR process/file events to runtime-compatible features."""
    event_id = str(record.get("id") or "").strip()
    properties = record.get("properties")
    if not isinstance(properties, dict):
        properties = {}

    object_type = str(record.get("object") or "").upper()
    action = str(record.get("action") or "").upper()
    if object_type == "PROCESS" and action in PROCESS_START_ACTIONS:
        event_type = "new_proc"
        process_name = _basename(properties.get("image_path"))
    elif object_type == "FILE" and action in FILE_ACTIONS:
        event_type = "file_mod"
        process_name = _basename(
            properties.get("file_path")
            or properties.get("path")
            or properties.get("file_name")
        )
    else:
        return None

    if not event_id or not process_name:
        return None

    return {
        "event_id": event_id,
        "host": str(record.get("hostname") or "").strip(),
        "event_type": event_type,
        "process_name": process_name.lower(),
        "has_parent": _has_parent(record),
        "risk_lvl": risk_level,
    }


def prepare_dataset(events_path: Path, labels_path: Path, output_path: Path) -> Counter:
    labels = load_labels(labels_path)
    counts: Counter = Counter()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as output_file:
            temporary_path = Path(output_file.name)
            writer = csv.DictWriter(output_file, fieldnames=OUTPUT_FIELDS)
            writer.writeheader()

            for record in iter_jsonl(events_path):
                event_id = str(record.get("id") or "").strip()
                risk_level = labels.get(event_id)
                if risk_level is None:
                    counts["unlabeled"] += 1
                    continue

                prepared = prepare_record(record, risk_level)
                if prepared is None:
                    counts["unsupported_or_incomplete"] += 1
                    continue

                writer.writerow(prepared)
                counts[risk_level] += 1

        if not sum(counts[level] for level in RISK_LEVELS):
            raise ValueError(
                "No labeled PROCESS CREATE/START or FILE CREATE/DELETE/MODIFY/"
                "UPDATE/WRITE records were found"
            )
        temporary_path.replace(output_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True, type=Path, help="eCAR JSONL or .jsonl.gz")
    parser.add_argument("--labels", required=True, type=Path, help="CSV with id,risk_lvl columns")
    parser.add_argument("--output", default=Path(__file__).with_name("optc_labeled.csv"), type=Path)
    args = parser.parse_args()

    counts = prepare_dataset(args.events, args.labels, args.output)
    print(f"Prepared {sum(counts[level] for level in RISK_LEVELS)} labeled events: {args.output}")
    for level in sorted(RISK_LEVELS):
        print(f"  {level}: {counts[level]}")
    print(
        "Skipped: "
        f"{counts['unlabeled']} unlabeled; "
        f"{counts['unsupported_or_incomplete']} unsupported or incomplete"
    )


if __name__ == "__main__":
    main()
